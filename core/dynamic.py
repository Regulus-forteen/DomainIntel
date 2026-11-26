# -*- coding: utf-8 -*-
"""
动态解析模块（Playwright）
用真实浏览器加载页面、点击下载按钮、拦截网络请求，拿到 JS 生成的载荷地址。

设计原则：
- 可选依赖：未安装 playwright 时不影响主流程
- 延迟安装：首次使用才提示
- 超时保护：单站点最多 30 秒
"""
from urllib.parse import urljoin, urlparse

BINARY_EXT = ("exe", "zip", "rar", "7z", "msi", "apk", "dmg", "pkg", "tar",
              "gz", "cab")

# 点了这些选择器当作"下载按钮"
CLICK_SELECTORS = [
    "a.dl-btn",
    "a[data-dl]",
    "button[data-dl]",
    "a[download]",
    "a[href*='download']",
    "a[href*='.exe']",
    ".download-btn",
    ".btn-download",
    ".dl-btn",
    "a:has-text('下载')",
    "button:has-text('下载')",
    "a:has-text('立即下载')",
    "a:has-text('免费下载')",
    "button:has-text('立即下载')",
]

# 拦截这些类型的响应视为载荷
PAYLOAD_TYPES = ("application/octet-stream", "application/zip",
                 "application/x-msdownload", "application/x-msi",
                 "application/vnd.android.package-archive",
                 "application/x-7z-compressed", "application/x-rar")


def is_available():
    """检查 playwright 是否可用"""
    try:
        import playwright  # noqa
        return True, None
    except ImportError:
        return False, "未安装 playwright"


def _looks_payload(url):
    low = (url or "").lower()
    path = urlparse(low).path
    if any(path.endswith("." + e) for e in BINARY_EXT):
        return True
    if any(k in low for k in ("/download/", "/dl/", "xiazai", "/file/")):
        return True
    return False


def resolve(url, timeout=30000, max_clicks=6, headless=True, progress_cb=None):
    """
    用 Playwright 打开页面，点击下载按钮，抓真实载荷地址。
    返回 {
      ok: bool, error: str,
      payloads: [url...],          # 判定的载荷地址
      requests: [url...],          # 所有可疑请求（供排查）
      downloads: [url...],         # 浏览器实际触发的下载
      navigations: [url...],       # 页面跳转链
    }
    """
    ok, err = is_available()
    if not ok:
        return {"ok": False, "error": err + "，请运行：pip install playwright && playwright install chromium",
                "payloads": [], "requests": [], "downloads": [], "navigations": []}

    from playwright.sync_api import sync_playwright

    payloads = set()
    suspect_reqs = set()
    downloads = set()
    navs = set()

    def _cb(stage, detail=""):
        if progress_cb:
            progress_cb(stage, detail)

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=headless,
                                         args=["--no-sandbox",
                                               "--disable-dev-shm-usage"])
            ctx = browser.new_context(
                user_agent=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 (KHTML, like Gecko) "
                            "Chrome/120.0.0.0 Safari/537.36"),
                accept_downloads=True,
                ignore_https_errors=True,
            )
            page = ctx.new_page()

            # 拦截请求
            def on_request(req):
                u = req.url
                if _looks_payload(u):
                    payloads.add(u)
                # 记录可疑的接口请求
                if any(k in u.lower() for k in
                       ("download", "/dl", "file", "setup", "install", "pkg")):
                    suspect_reqs.add(u)

            def on_response(resp):
                try:
                    ct = (resp.headers or {}).get("content-type", "").lower()
                    if any(t in ct for t in PAYLOAD_TYPES):
                        payloads.add(resp.url)
                except Exception:
                    pass

            def on_download(dl):
                try:
                    downloads.add(dl.url)
                    payloads.add(dl.url)
                except Exception:
                    pass

            def on_nav(frame):
                if frame == page.main_frame:
                    navs.add(frame.url)

            page.on("request", on_request)
            page.on("response", on_response)
            page.on("download", on_download)
            page.on("framenavigated", on_nav)

            _cb("goto", url)
            page.goto(url, timeout=timeout, wait_until="domcontentloaded")
            page.wait_for_timeout(1500)

            # 先看看静态里有没有
            try:
                html = page.content()
                import re
                for m in re.finditer(
                        r"[\w./:\-]{6,200}?\.(?:%s)" % "|".join(BINARY_EXT),
                        html, re.I):
                    u = m.group(0)
                    if u.startswith("//"):
                        u = "https:" + u
                    elif u.startswith("/"):
                        u = urljoin(url, u)
                    payloads.add(u)
            except Exception:
                pass

            # 逐个尝试点击
            clicked = 0
            for sel in CLICK_SELECTORS:
                if clicked >= max_clicks:
                    break
                try:
                    loc = page.locator(sel)
                    n = min(loc.count(), 3)
                    for i in range(n):
                        if clicked >= max_clicks:
                            break
                        try:
                            el = loc.nth(i)
                            if not el.is_visible():
                                continue
                            _cb("click", "%s [%d]" % (sel, i))
                            el.click(timeout=6000, no_wait_after=True)
                            clicked += 1
                            page.wait_for_timeout(1200)
                        except Exception:
                            continue
                except Exception:
                    continue

            # 等新页面/下载完成
            page.wait_for_timeout(1500)

            # 检查所有打开的标签页
            try:
                for pg in ctx.pages:
                    u = pg.url
                    if _looks_payload(u):
                        payloads.add(u)
            except Exception:
                pass

            browser.close()

    except Exception as e:
        return {"ok": False, "error": "%s: %s" % (type(e).__name__, str(e)[:120]),
                "payloads": sorted(payloads), "requests": sorted(suspect_reqs),
                "downloads": sorted(downloads), "navigations": sorted(navs)}

    # 从可疑请求里再筛一遍
    for u in suspect_reqs:
        if _looks_payload(u):
            payloads.add(u)

    return {
        "ok": True,
        "error": None,
        "payloads": sorted(payloads)[:20],
        "requests": sorted(suspect_reqs)[:30],
        "downloads": sorted(downloads)[:10],
        "navigations": sorted(navs)[:10],
        "clicked": clicked,
    }


def install_hint():
    return ("需要安装 Playwright + Chromium：\n\n"
            "  pip install playwright\n"
            "  playwright install chromium\n\n"
            "安装后重启本工具即可使用动态解析。")