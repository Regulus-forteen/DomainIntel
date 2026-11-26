# -*- coding: utf-8 -*-
"""
HTTP / TLS / 页面指纹 采集模块
包含 FOFA / Quake / ZoomEye 可用的指纹：
- favicon hash（mmh3，FOFA 的 icon_hash 语法）
- 页面 body MD5
- 标题、Server、特征词、下载链接、对象存储桶
- TLS 证书明细与 SHA256
"""
import re
import ssl
import socket
import hashlib
import base64
from urllib.parse import urljoin

import requests
import urllib3

urllib3.disable_warnings()

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

UA_POOL = [
    UA,
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) "
     "Gecko/20100101 Firefox/121.0"),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
     "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"),
]

# 可执行 / 压缩包扩展名（不含 html、php 等页面）
BINARY_EXT = r"(?:exe|zip|rar|7z|msi|apk|dmg|pkg|tar|gz|cab)"

# Serverless / 免费托管平台（黑产常用来做载荷分发，域名随时可换）
SERVERLESS_HOSTS = (
    "workers.dev", "pages.dev", "vercel.app", "netlify.app", "herokuapp.com",
    "glitch.me", "repl.co", "deno.dev", "fly.dev", "onrender.com",
    "web.app", "firebaseapp.com", "r2.dev", "azurewebsites.net",
    "cloudfront.net", "github.io", "gitlab.io", "surge.sh", "now.sh",
)


# 高风险 TLD（注册便宜、滥用率高）
RISKY_TLDS = ("cyou", "top", "xyz", "icu", "buzz", "click", "shop", "vip",
              "work", "loan", "men", "gq", "tk", "ml", "cf", "ga", "rest",
              "monster", "sbs", "cfd", "buzz")


def _looks_random(label):
    """
    判断域名主体是否像随机串。
    思路：真实品牌/单词通常能被拆成常见音节或本身就是词典词；
    随机串往往长度长、缺乏常见双字母组合、字母分布发散。
    """
    s = label.lower()
    if len(s) < 8:
        return False

    # 明显的品牌词/常见词直接排除
    COMMON = ("todesk", "deepseek", "typora", "nexus", "mod", "google", "apple",
              "microsoft", "windows", "android", "office", "adobe", "chrome",
              "browser", "player", "music", "video", "photo", "cloud", "drive",
              "store", "market", "update", "install", "setup", "download",
              "client", "server", "console", "manager", "helper", "tool")
    for w in COMMON:
        if w in s:
            return False

    vowels = sum(1 for ch in s if ch in "aeiou")
    vr = vowels / max(1, len(s))

    # 常见英文双字母组合出现次数
    bigrams = ("th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
               "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
               "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
               "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea",
               "ra", "ce", "li", "ch", "ll", "be", "ma", "si", "om", "ur")
    bg = sum(1 for i in range(len(s) - 1) if s[i:i+2] in bigrams)

    # 连续辅音
    max_cons = cur = 0
    for ch in s:
        if ch.isalpha() and ch not in "aeiou":
            cur += 1
            max_cons = max(max_cons, cur)
        else:
            cur = 0

    # 判定：长串 + 常见组合极少 + 辅音堆积
    if len(s) >= 12 and bg <= 2:
        return True
    if max_cons >= 4 and bg <= 3:
        return True
    if len(s) >= 14 and vr < 0.25:
        return True
    return False


def _official_variant(host, brand_officials):
    """
    判断 host 是否是某品牌官方域名的变体（加前后缀）。
    例：oray.com → cdn-oray.com / oray-cdn.com
        deepseek.com → cdns-deepseek.com / deepseek-cdn.com
    返回命中的品牌名，未命中返回 None
    """
    h = (host or "").lower().split(":")[0]
    labels = h.split(".")
    if len(labels) < 2:
        return None
    main = labels[-2]           # 主标签，如 cdn-oray
    for brand, officials in brand_officials.items():
        for off in officials:
            off_label = off.lower().split(".")[0]
            if len(off_label) < 3:
                continue
            # 完全相同不算变体（那是官方本身）
            if main == off_label:
                continue
            # 主标签包含官方标签 + 有额外前后缀
            if off_label in main and len(main) > len(off_label):
                return brand
    return None


def _is_object_host(host):
    h = (host or "").lower()
    return any(k in h for k in CDN_OBJECT_HOSTS)


def _risky_domain(host):
    """判断是否高风险域名：高风险 TLD + 随机串主体"""
    h = (host or "").lower().split(":")[0]
    parts = h.split(".")
    if len(parts) < 2:
        return False
    tld = parts[-1]
    if tld not in RISKY_TLDS:
        return False
    label = parts[-2] if len(parts) >= 2 else ""
    return _looks_random(label)


# 主流网盘（黑产常用来托管恶意样本，绕过域名封禁）
NETDISK_PATTERNS = [
    (r"pan\.baidu\.com/s/", "百度网盘"),
    (r"drive\.uc\.cn/s/", "UC网盘"),
    (r"pan\.quark\.cn/s/", "夸克网盘"),
    (r"pan\.xunlei\.com/s/", "迅雷网盘"),
    (r"aliyundrive\.com/s/", "阿里云盘"),
    (r"www\.aliyundrive\.com/s/", "阿里云盘"),
    (r"cloud\.189\.cn/t/", "天翼云盘"),
    (r"caiyun\.139\.com/", "移动云盘"),
    (r"115\.com/s/", "115网盘"),
    (r"lanzou[a-z]?\.com/", "蓝奏云"),
    (r"123pan\.com/s/", "123云盘"),
    (r"pan\.jianguoyun\.com", "坚果云"),
]

# 跳转网关特征（域名里带这些 + go.php / jump / tj）
# 对象存储 / CDN 分发平台（载荷常托管在这类免费或低门槛服务上）
CDN_OBJECT_HOSTS = (
    "r2.dev", "r2.cloudflarestorage.com",
    "oss-cn-", "oss-accelerate", "oss-ap-",
    "tos-cn-", "cos.ap-", "cos.na-", "myqcloud.com",
    "kodo", "qiniucdn", "bkt.clouddn.com",
    "blob.core.windows.net", "s3.amazonaws.com",
    "storage.googleapis.com", "digitaloceanspaces.com",
    "backblazeb2.com", "b2cdn.com",
)

PUBLIC_PLATFORM_HOSTS = {
    "github.com", "www.github.com", "gitlab.com", "gitee.com",
    "opensource.org", "www.opensource.org",
    "w3.org", "www.w3.org", "schema.org",
    "google.com", "www.google.com", "fonts.googleapis.com",
    "fonts.gstatic.com", "cdnjs.cloudflare.com",
    "cloudflare.com", "beian.miit.gov.cn", "beian.mps.gov.cn",
    "miit.gov.cn", "tsm.miit.gov.cn",
}

GATEWAY_HINTS = ["hhxiazai", "tj.", "jump", "go.php", "down.php", "dl.php",
                 "xiazai", "soft", "down1", "down2"]

FEATURE_WORDS = [
    "deepseek", "深度求索", "官网", "下载", "客户端", "免费", "破解", "客服",
    "vpn", "梯子", "翻墙", "加速器", "科学上网",
    "apk", "android", "windows", "mac", "ios", "dmg", "exe",
    "二维码", "扫码", "邀请", "充值", "会员", "vip",
    "登录", "注册", "官方", "正版", "备案",
]


def _favicon_hash(content):
    """FOFA icon_hash 算法：内容 base64 后取 mmh3"""
    try:
        import mmh3
        return mmh3.hash(base64.encodebytes(content))
    except Exception:
        return None


def _extract_favicon(txt, url, timeout=6):
    """从 HTML 里找 favicon 并计算 hash"""
    m = re.search(r'<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]*href=["\']([^"\']+)', txt, re.I)
    if not m:
        m = re.search(r'<link[^>]+href=["\']([^"\']+)["\'][^>]*rel=["\'](?:shortcut )?icon["\']',
                      txt, re.I)
    if not m:
        return {}
    fav = m.group(1).strip()
    if fav.startswith("//"):
        fav = "https:" + fav
    elif not fav.startswith("http"):
        fav = urljoin(url, fav)
    try:
        fr = requests.get(fav, headers={"User-Agent": UA}, timeout=timeout, verify=False)
        if fr.status_code == 200 and fr.content:
            return {"favicon_url": fav,
                    "favicon_hash": _favicon_hash(fr.content),
                    "favicon_md5": hashlib.md5(fr.content).hexdigest()}
    except Exception:
        pass
    return {}


def http_probe(url, timeout=12, maxbytes=1200000, ua=None, referer=None):
    """探测单个 URL。maxbytes 给足——克隆站常把 <title> 埋在内联脚本之后。"""
    info = {"url": url}
    try:
        hdrs = {"User-Agent": ua or UA,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"}
        if referer:
            hdrs["Referer"] = referer
        r = requests.get(url, headers=hdrs, timeout=timeout,
                         allow_redirects=True, verify=False, stream=True)
        info["status"] = r.status_code
        info["final_url"] = r.url
        info["redirects"] = [h.headers.get("Location") for h in r.history
                             if h.headers.get("Location")]
        h = {k.lower(): v for k, v in r.headers.items()}
        info["server"] = h.get("server", "")
        info["powered_by"] = h.get("x-powered-by", "")
        info["content_type"] = h.get("content-type", "")
        info["headers"] = {k: v for k, v in list(h.items())[:25]}
        clen = h.get("content-length")
        info["len_header"] = int(clen) if clen and clen.isdigit() else None

        raw = b""
        title_seen_at = None
        for chunk in r.iter_content(8192):
            if not chunk:
                continue
            raw += chunk
            # 记录首次出现 </title> 的位置；之后继续多读至少 300KB，
            # 因为下载按钮/表单/脚本常出现在标题之后很远
            if title_seen_at is None and b"</title>" in raw.lower():
                title_seen_at = len(raw)
            if title_seen_at is not None and len(raw) - title_seen_at > 300000:
                break
            if len(raw) >= maxbytes:
                break
        try:
            r.close()
        except Exception:
            pass

        txt = raw.decode("utf-8", "ignore")
        info["len"] = len(raw)
        info["body_md5"] = hashlib.md5(raw).hexdigest()

        m = re.search(r"<title[^>]*>(.*?)</title>", txt, re.I | re.S)
        info["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:200] if m else ""

        low = txt.lower()
        info["features"] = [w for w in FEATURE_WORDS if w in low]

        links = re.findall(r'https?://[^\s"\'<>()\\]+', txt)

        # ================= 链接分析（升级版）=================
        from urllib.parse import urlparse as _up, unquote as _unq
        import base64 as _b64

        def _root_of(host):
            h = (host or "").lower().split(":")[0]
            parts = h.split(".")
            for suf in (".com.cn", ".net.cn", ".org.cn", ".gov.cn", ".edu.cn"):
                if h.endswith(suf):
                    return ".".join(parts[-3:])
            return ".".join(parts[-2:]) if len(parts) >= 2 else h

        def _abs(h):
            if not h or h.startswith("#") or h.lower().startswith("javascript:"):
                return None
            if h.startswith("//"):
                return "https:" + h
            if h.startswith("/"):
                return urljoin(url, h)
            if not h.startswith("http"):
                return urljoin(url, h)
            return h

        def _is_binary(h):
            path = _up(h).path.lower()
            return bool(re.search(r"\." + BINARY_EXT + r"$", path, re.I))

        def _netdisk(u):
            for pat, name in NETDISK_PATTERNS:
                if re.search(pat, u, re.I):
                    return name
            return None

        def _try_b64(s):
            """尝试把 base64 参数还原成 URL"""
            s = _unq(s)
            for pad in ("", "=", "=="):
                try:
                    raw = _b64.b64decode(s + pad, validate=False)
                    txt = raw.decode("utf-8", "ignore")
                    if txt.startswith("http"):
                        return txt
                except Exception:
                    continue
            return None

        def _decode_gateway(u):
            """解析跳转网关里的目标地址"""
            try:
                q = _up(u).query
                for k in ("u", "url", "target", "to", "link", "redirect"):
                    m = re.search(r"(?:^|&)" + k + r"=([^&]+)", q)
                    if m:
                        dec = _try_b64(m.group(1))
                        if dec:
                            return dec
            except Exception:
                pass
            return None

        cur_root = _root_of(_up(url).netloc.lower())

        anchors = [m.group(1).strip() for m in re.finditer(
            r'<a\b[^>]*?href\s*=\s*["\']([^"\']+)["\'][^>]*>', txt, re.I)]

        payload_strong = []    # 外站可执行
        payload_weak = []      # 本站可执行
        gateways = []          # 跳转网关（含解码目标）
        netdisks = []          # 网盘链接
        download_pages = []    # 下载页
        external_links = []    # 一般外链

        def _handle(u):
            try:
                ph = _up(u).netloc.lower()
                pr = _root_of(ph)
            except Exception:
                return
            external = (pr != cur_root)

            # 网盘
            nd = _netdisk(u)
            if nd:
                netdisks.append({"url": u, "netdisk": nd})
                return

            # 跳转网关：域名命中特征 或 带可解码参数
            low = u.lower()
            if any(h in low for h in GATEWAY_HINTS) or re.search(r"[?&](u|url|target)=", low):
                tgt = _decode_gateway(u)
                gateways.append({"url": u, "target": tgt})
                if tgt:
                    nd2 = _netdisk(tgt)
                    if nd2 and not any(x["url"] == tgt for x in netdisks):
                        netdisks.append({"url": tgt, "netdisk": nd2,
                                         "via": u})
                return

            binary = _is_binary(u)
            if binary and external:
                payload_strong.append(u)
            elif binary:
                payload_weak.append(u)
            elif external:
                external_links.append(u)
            else:
                if re.search(r"download|/dl/|xiazai|setup|install|下载", low):
                    download_pages.append(u)

        for h in anchors:
            u = _abs(h)
            if u:
                _handle(u)

        # 兜底：扫描整页文本里的绝对 URL
        for m in re.finditer(r'https?://[^\s"\'<>()\\]+', txt):
            _handle(m.group(0))

        info["payload_strong"] = sorted(set(payload_strong))[:15]
        info["payload_weak"] = sorted(set(payload_weak))[:15]
        info["download_pages"] = sorted(set(download_pages))[:10]
        info["external_links"] = sorted(set(external_links))[:20]

        # 网关与网盘去重
        seen = set()
        g2 = []
        for g in gateways:
            if g["url"] not in seen:
                seen.add(g["url"])
                g2.append(g)
        info["gateways"] = g2[:10]

        seen = set()
        n2 = []
        for n in netdisks:
            if n["url"] not in seen:
                seen.add(n["url"])
                n2.append(n)
        info["netdisks"] = n2[:15]

        # ---------- 从 JS / onclick 里提取下载路径 ----------
        js_dl = set()
        # triggerDownload(this, '/path/file.exe') / download('...') / location.href='...'
        for m in re.finditer(
                r"""(?:triggerDownload|downloadFile|download|startDownload|dl|goDownload)"""
                r"""\s*\(\s*(?:this\s*,\s*)?["']([^"']{3,300}?)["']""",
                txt, re.I):
            js_dl.add(m.group(1))
        # onclick / onmousedown 属性里的任意字符串路径
        for m in re.finditer(
                r"""on(?:click|mousedown|mouseup)\s*=\s*["']([^"']{3,400}?)["']""",
                txt, re.I):
            body = m.group(1)
            for mm in re.finditer(
                    r"""["']([^"']*\.(?:""" + BINARY_EXT + r"""))["']""",
                    body, re.I):
                js_dl.add(mm.group(1))
        # window.location / location.href 赋值
        for m in re.finditer(
                r"""(?:window\.)?location(?:\.href)?\s*=\s*["']([^"']{3,300}?)["']""",
                txt, re.I):
            js_dl.add(m.group(1))

        for u in js_dl:
            if not u:
                continue
            u = u.strip()
            if u.startswith("//"):
                u = "https:" + u
            elif u.startswith("/"):
                u = urljoin(url, u)
            elif not u.startswith("http"):
                u = urljoin(url, u)
            low = u.lower()
            # 只有带可执行扩展名的才算载荷
            if not re.search(r"\.(?:%s)(\?|#|$)" % BINARY_EXT, low, re.I):
                continue
            try:
                ph = _up(u).netloc.lower()
                pr = _root_of(ph)
                ext = (pr != cur_root)
            except Exception:
                ext = False
            if ext:
                info["payload_strong"].append(u)
            else:
                info["payload_weak"].append(u)

        info["payload_strong"] = sorted(set(info["payload_strong"]))[:15]
        info["payload_weak"] = sorted(set(info["payload_weak"]))[:15]
        info["js_downloads"] = sorted(js_dl)[:20]

        # ---------- ① 结构化数据里的 downloadUrl ----------
        ld_downloads = []
        for m in re.finditer(
                r'<script[^>]+type\s*=\s*["\']application/ld\+json["\'][^>]*>(.*?)</script>',
                txt, re.I | re.S):
            body = m.group(1)
            # 直接正则抓 downloadUrl（不依赖 json 解析，容忍脏数据）
            for dm in re.finditer(r'"downloadUrl"\s*:\s*"([^"]+)"', body, re.I):
                ld_downloads.append(dm.group(1))
            # 也抓 contentUrl / url 里带扩展名的
            for dm in re.finditer(
                    r'"(?:contentUrl|fileUrl|installUrl)"\s*:\s*"([^"]+)"', body, re.I):
                ld_downloads.append(dm.group(1))

        # ---------- ② data-* 线索 ----------
        data_hints = []
        for m in re.finditer(
                r'data-(?:dl|file|url|href|src|link|download|pkg|app)\s*=\s*["\']([^"\']{1,120})["\']',
                txt, re.I):
            v = m.group(1).strip()
            if v and v not in data_hints:
                data_hints.append(v)
        # 从 onclick 里抓 data-* 引用
        for m in re.finditer(r"dataset\.(?:dl|file|url|href|link)", txt, re.I):
            pass  # 仅作存在性标记，下面用 data_hints 是否为空判断

        # ---------- ③ JS 映射表：{"sunlogim": "https://...exe"} ----------
        js_map = {}
        for m in re.finditer(
                r'["\']([a-z0-9_\-]{3,40})["\']\s*:\s*["\'](https?://[^"\']{6,300}?)["\']',
                txt, re.I):
            key, val = m.group(1), m.group(2)
            if re.search(r"\.(?:%s)" % BINARY_EXT, val, re.I) or \
                    any(h in val.lower() for h in SERVERLESS_HOSTS):
                js_map[key] = val

        # 用 data-dl 的值去映射表里查
        for hint in data_hints:
            if hint in js_map:
                ld_downloads.append(js_map[hint])

        # ---------- ④ JS 拼接：'prefix' + xxx.data-dl + '.exe' ----------
        js_concat = []
        for m in re.finditer(
                r"""["']((?:https?://|/)[^"']{0,120}?)["']\s*\+\s*[\w$.]*(?:dataset\.)?(?:dl|file|url|href)\b\s*\+\s*["']([^"']{0,40})["']""",
                txt, re.I):
            prefix, suffix = m.group(1), m.group(2)
            if any(h in prefix for h in data_hints[:3]):
                continue
            for hint in data_hints[:3]:
                js_concat.append(prefix + hint + suffix)

        # ---------- ⑤ 汇总到载荷列表 ----------
        for u in ld_downloads + js_concat:
            if not u:
                continue
            if not u.startswith("http"):
                u = urljoin(url, u)
            try:
                low = u.lower()
                host = _up(u).netloc.lower()
                is_serveless = any(h in host for h in SERVERLESS_HOSTS)
                is_bin = bool(re.search(r"\.(?:%s)" % BINARY_EXT, low, re.I))
                # 结构化数据的 downloadUrl 即便无扩展名也算载荷线索
                if is_bin or is_serveless:
                    if is_serveless:
                        info.setdefault("serverless_payload", []).append(u)
                    if _root_of(host) != cur_root:
                        info["payload_strong"].append(u)
                    else:
                        info["payload_weak"].append(u)
            except Exception:
                continue

        info["ld_downloads"] = sorted(set(ld_downloads))[:10]
        info["data_hints"] = data_hints[:15]
        info["js_map_hits"] = sorted(set(js_map.values()))[:10]
        info["serverless_payload"] = sorted(set(info.get("serverless_payload") or []))[:10]

        # ---------- 可疑外链域名（高风险 TLD + 随机串）----------
        suspicious_hosts = []
        try:
            for hh in set(re.findall(r"https?://([a-z0-9\.\-]+)", txt, re.I)):
                hh = hh.lower().split(":")[0]
                if _root_of(hh) == cur_root:
                    continue
                if _risky_domain(hh):
                    suspicious_hosts.append(hh)
        except Exception:
            pass
        info["suspicious_hosts"] = sorted(set(suspicious_hosts))[:10]

        info["download_links"] = sorted(
            set(info["payload_strong"]) | set(info["payload_weak"]))[:20]

        # 诱导文案
        LURE_WORDS = ["立即下载", "马上安装", "点击下载", "免费下载", "高速下载",
                      "电脑版下载", "客户端下载", "下载安装", "一键下载", "本地下载",
                      "download now", "install now", "free download"]
        info["lure_words"] = [w for w in LURE_WORDS if w in txt]

        # ---------- 网盘 / 网关：全文正则（不依赖 a 标签）----------
        def _collect_netdisk_gateway(body_text):
            nd, gw = [], []
            low = body_text
            # 网盘
            for pat, name in NETDISK_PATTERNS:
                # 有协议头
                for m in re.finditer(r'https?://[^\s"\'<>()\\]*?' + pat + r'[^\s"\'<>()\\]*',
                                     low, re.I):
                    nd.append({"url": m.group(0), "netdisk": name})
                # 无协议头
                for m in re.finditer(r'(?<![\w/])' + pat + r'[^\s"\'<>()\\]*',
                                     low, re.I):
                    u = "https://" + m.group(0)
                    nd.append({"url": u, "netdisk": name})
            # 网关（含 base64 目标）
            for m in re.finditer(r'https?://[^\s"\'<>()\\]*(?:go|down|dl|jump)\.php[^\s"\'<>()\\]*',
                                 low, re.I):
                u = m.group(0)
                tg = _decode_gateway(u)
                gw.append({"url": u, "target": tg})
                if tg:
                    for pat, name in NETDISK_PATTERNS:
                        if re.search(pat, tg, re.I):
                            nd.append({"url": tg, "netdisk": name, "via": u})
                            break
            # 域名里带 hhxiazai / tj. 之类
            for m in re.finditer(r'https?://[^\s"\'<>()\\]*(?:hhxiazai|xiazai)[^\s"\'<>()\\]*',
                                 low, re.I):
                u = m.group(0)
                if not any(g["url"] == u for g in gw):
                    gw.append({"url": u, "target": _decode_gateway(u)})
            return nd, gw

        nd2, gw2 = _collect_netdisk_gateway(txt)
        for x in nd2:
            if not any(y["url"] == x["url"] for y in netdisks):
                netdisks.append(x)
        for x in gw2:
            if not any(y["url"] == x["url"] for y in gateways):
                gateways.append(x)

        # 重新去重
        seen = set()
        n3 = []
        for n in netdisks:
            if n["url"] not in seen:
                seen.add(n["url"])
                n3.append(n)
        info["netdisks"] = n3[:15]

        seen = set()
        g3 = []
        for g in gateways:
            if g["url"] not in seen:
                seen.add(g["url"])
                g3.append(g)
        info["gateways"] = g3[:10]

        # ---------- 是否引用了品牌真官网（严格判定）----------
        info["refs_official"] = []
        try:
            import json as _json
            from pathlib import Path as _P
            bf = _P(__file__).resolve().parent / "brands.json"
            bdata = _json.loads(bf.read_text(encoding="utf-8"))

            hosts = set(h.lower() for h in
                        re.findall(r'(?<![\w.\-])([a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)+)',
                                   txt, re.I))
            hosts = {h for h in hosts if "." in h}

            for b in bdata.get("brands", []):
                for o in b.get("official", []):
                    oh = o.lower().split("/")[0].strip()
                    if not oh or oh in ("github.com", "sourceforge.net"):
                        continue
                    if oh in PUBLIC_PLATFORM_HOSTS:
                        continue
                    if oh == cur_root:
                        continue
                    # 必须是完整匹配某 host
                    if oh in hosts:
                        info["refs_official"].append(
                            {"brand": b.get("name"), "host": oh})
                        break
        except Exception:
            pass

        # ---------- 二层：抓下载页，复用完整分析逻辑 ----------
        def _merge_dict(src_dict):
            for k in ("payload_strong", "payload_weak", "ld_downloads",
                      "js_map_hits", "serverless_payload", "suspicious_hosts",
                      "download_pages"):
                for x in (src_dict.get(k) or []):
                    if x not in info.get(k, []):
                        info.setdefault(k, []).append(x)
            for x in (src_dict.get("netdisks") or []):
                if not any(y["url"] == x["url"] for y in info.get("netdisks", [])):
                    info.setdefault("netdisks", []).append(x)
            for x in (src_dict.get("gateways") or []):
                if not any(y["url"] == x["url"] for y in info.get("gateways", [])):
                    info.setdefault("gateways", []).append(x)
            for w in (src_dict.get("lure_words") or []):
                if w not in info.get("lure_words", []):
                    info.setdefault("lure_words", []).append(w)

        depth1_pages = list(dict.fromkeys(
            (info.get("download_pages") or [])[:3]))
        depth2_pages = []

        if depth1_pages:
            for dp in depth1_pages:
                try:
                    r2 = requests.get(dp, headers={"User-Agent": UA, "Referer": url},
                                      timeout=12, verify=False)
                    if r2.status_code >= 400:
                        continue
                    t2 = r2.text
                    sub = analyze_links(t2, dp)
                    _merge_dict(sub)
                    # 收集下一层候选
                    for p2 in (sub.get("download_pages") or [])[:2]:
                        if p2 not in depth1_pages and p2 not in depth2_pages:
                            depth2_pages.append(p2)
                except Exception:
                    pass

        # 递归一层：如果还是没拿到载荷，再抓一层
        if not info.get("payload_strong") and depth2_pages:
            for dp in depth2_pages[:2]:
                try:
                    r3 = requests.get(dp, headers={"User-Agent": UA, "Referer": url},
                                      timeout=12, verify=False)
                    if r3.status_code >= 400:
                        continue
                    _merge_dict(analyze_links(r3.text, dp))
                except Exception:
                    pass

        # 去重收尾
        for k in ("payload_strong", "payload_weak", "ld_downloads", "js_map_hits",
                  "serverless_payload", "suspicious_hosts"):
            info[k] = sorted(set(info.get(k) or []))[:20]
        info["download_pages"] = sorted(set(info.get("download_pages") or []))[:10]
        info["download_links"] = sorted(
            set(info.get("payload_strong") or []) | set(info.get("payload_weak") or []))[:20]
        info["payload_deep"] = info["payload_strong"][:15]

        info["buckets"] = sorted({
            re.sub(r"^https?://", "", l).split("/")[0]
            for l in links
            if re.search(r"(oss|tos|cos|kodo)[a-z0-9\-]*\.(aliyuncs|volces|myqcloud|clouddn)\.com",
                         l, re.I)
        })[:10]

        info["out_domains"] = sorted({
            re.sub(r"^https?://", "", l).split("/")[0].lower()
            for l in links
        })[:40]

        info["body_head"] = re.sub(r"\s+", " ", txt)[:600]
        info.update(_extract_favicon(txt, url))

        # 统一分析（对象存储/官方变体/外部JS）
        try:
            sub = analyze_links(txt, url)
            for k in ("object_storage", "official_variants", "external_js_domains"):
                if sub.get(k):
                    info[k] = sub[k]
            for u in (sub.get("object_storage") or []):
                if u not in (info.get("payload_strong") or []):
                    info.setdefault("payload_strong", []).append(u)
            for d in (sub.get("external_js_domains") or []):
                if d not in (info.get("external_js") or []):
                    info.setdefault("external_js", []).append(d)
        except Exception:
            pass
        info["html"] = txt[:maxbytes]

    except requests.exceptions.SSLError as e:
        info["error"] = "SSL: " + str(e)[:100]
    except requests.exceptions.ConnectTimeout:
        info["error"] = "连接超时"
    except requests.exceptions.ReadTimeout:
        info["error"] = "读取超时"
    except requests.exceptions.ConnectionError as e:
        info["error"] = "连接失败: " + str(e)[:80]
    except Exception as e:
        info["error"] = "%s: %s" % (type(e).__name__, str(e)[:80])
    return info


def cert_probe(domain, timeout=8):
    """TLS 证书明细"""
    info = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=timeout) as sk:
            with ctx.wrap_socket(sk, server_hostname=domain) as ss:
                der = ss.getpeercert(binary_form=True)
                if not der:
                    return {"error": "空证书"}
                info["sha256"] = hashlib.sha256(der).hexdigest()
                info["tls_version"] = ss.version()
                try:
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend
                    c = x509.load_der_x509_certificate(der, default_backend())
                    info["subject"] = c.subject.rfc4514_string()
                    info["issuer"] = c.issuer.rfc4514_string()
                    info["not_before"] = str(c.not_valid_before_utc)[:19]
                    info["not_after"] = str(c.not_valid_after_utc)[:19]
                    info["serial"] = str(c.serial_number)
                    try:
                        oid = x509.oid.NameOID.ORGANIZATION_NAME
                        info["issuer_org"] = c.issuer.get_attributes_for_oid(oid)[0].value
                    except Exception:
                        info["issuer_org"] = ""
                    try:
                        san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                        info["san"] = san.value.get_values_for_type(x509.DNSName)[:30]
                    except Exception:
                        info["san"] = []
                except Exception as e:
                    info["decode_error"] = str(e)[:80]
    except Exception as e:
        info["error"] = "%s: %s" % (type(e).__name__, str(e)[:80])
    return info


def collect_http(domain):
    """
    http + https 都试，但以 https 为优先。
    三级重试：
      1) https + 标准 UA
      2) https + 换 UA + Referer
      3) http  + 标准 UA
    任一级拿到 200 就停止。
    """
    import random
    import time

    out = {}

    def _try(scheme, ua=None, referer=None):
        url = "%s://%s/" % (scheme, domain)
        res = http_probe(url, ua=ua, referer=referer)
        out.setdefault(scheme, res)
        if res.get("status") and res.get("status") < 400:
            out[scheme] = res
            return res
        # 保留第一次的记录，避免被后续失败覆盖掉有用信息
        if not out[scheme].get("status"):
            out[scheme] = res
        return None

    # 1) https + 标准 UA
    got = _try("https")
    if got:
        return out, got

    # 2) https + 换 UA + Referer
    time.sleep(random.uniform(0.8, 1.6))
    got = _try("https", ua=UA_POOL[1], referer="https://www.google.com/")
    if got:
        return out, got

    # 3) http + 标准 UA（最后降级）
    time.sleep(random.uniform(0.5, 1.2))
    got = _try("http")
    if got:
        return out, got

    # 4) 全失败，也给一次 http + 换 UA 的机会
    time.sleep(random.uniform(0.5, 1.0))
    got = _try("http", ua=UA_POOL[2], referer="https://www.bing.com/")
    if got:
        return out, got

    # 全失败：返回已有记录里信息最多的那个
    best = None
    for v in out.values():
        if v.get("status") or v.get("title") or v.get("len"):
            best = v
            break
    return out, best

def analyze_links(html, base_url):
    """
    独立分析一段 HTML 里的载荷线索。
    供主页面与二层抓取共用，返回 dict：
      {payload_strong, payload_weak, netdisks, gateways, download_pages,
       ld_downloads, data_hints, js_map_hits, serverless_payload,
       suspicious_hosts, lure_words}
    """
    from urllib.parse import urlparse as _up, unquote as _unq
    import base64 as _b64

    out = {
        "payload_strong": [], "payload_weak": [], "netdisks": [],
        "gateways": [], "download_pages": [], "ld_downloads": [],
        "data_hints": [], "js_map_hits": [], "serverless_payload": [],
        "suspicious_hosts": [], "lure_words": [],
        "object_storage": [],       # r2.dev / OSS / TOS 等对象存储直链
        "official_variants": [],    # cdn-oray.com 这类官方域变体
        "external_js_domains": [],  # 页面引用的外部 JS 所在域名
    }
    txt = html or ""
    if not txt:
        return out

    def _root_of(host):
        h = (host or "").lower().split(":")[0]
        parts = h.split(".")
        for suf in (".com.cn", ".net.cn", ".org.cn", ".gov.cn", ".edu.cn"):
            if h.endswith(suf):
                return ".".join(parts[-3:])
        return ".".join(parts[-2:]) if len(parts) >= 2 else h

    def _abs(h):
        if not h or h.startswith("#") or h.lower().startswith("javascript:"):
            return None
        if h.startswith("//"):
            return "https:" + h
        if not h.startswith("http"):
            return urljoin(base_url, h)
        return h

    def _is_bin(u):
        try:
            path = _up(u).path.lower()
        except Exception:
            return False
        return bool(re.search(r"\." + BINARY_EXT + r"$", path, re.I))

    def _netdisk(u):
        for pat, name in NETDISK_PATTERNS:
            if re.search(pat, u, re.I):
                return name
        return None

    def _try_b64(s):
        s = _unq(s)
        for pad in ("", "=", "=="):
            try:
                raw = _b64.b64decode(s + pad, validate=False)
                t = raw.decode("utf-8", "ignore")
                if t.startswith("http"):
                    return t
            except Exception:
                continue
        return None

    def _decode_gateway(u):
        try:
            q = _up(u).query
            for k in ("u", "url", "target", "to", "link", "redirect"):
                m = re.search(r"(?:^|&)" + k + r"=([^&]+)", q)
                if m:
                    d = _try_b64(m.group(1))
                    if d:
                        return d
        except Exception:
            pass
        return None

    cur_root = _root_of(_up(base_url).netloc.lower())

    def _push(u):
        if not u:
            return
        u = u.strip()
        try:
            host = _up(u).netloc.lower()
        except Exception:
            return
        ext = (_root_of(host) != cur_root)

        nd = _netdisk(u)
        if nd:
            out["netdisks"].append({"url": u, "netdisk": nd})
            return

        low = u.lower()
        if any(h in low for h in GATEWAY_HINTS) or re.search(r"[?&](u|url|target)=", low):
            tg = _decode_gateway(u)
            out["gateways"].append({"url": u, "target": tg})
            if tg:
                nd2 = _netdisk(tg)
                if nd2:
                    out["netdisks"].append({"url": tg, "netdisk": nd2, "via": u})
            return

        if _is_bin(u):
            (out["payload_strong"] if ext else out["payload_weak"]).append(u)
            return

        if ext:
            return
        if re.search(r"download|/dl/|xiazai|setup|install|下载", low):
            out["download_pages"].append(u)

    # a 标签
    for m in re.finditer(r'<a\b[^>]*?href\s*=\s*["\']([^"\']+)["\'][^>]*>',
                         txt, re.I):
        u = _abs(m.group(1))
        if u:
            _push(u)

    # 全文绝对 URL（兜底）
    for m in re.finditer(r'https?://[^\s"\'<>()\\]+', txt):
        _push(m.group(0))

    # Schema.org
    for m in re.finditer(
            r'<script[^>]+type\s*=\s*["\']application/ld\+json["\'][^>]*>(.*?)</script>',
            txt, re.I | re.S):
        body = m.group(1)
        for dm in re.finditer(r'"(?:downloadUrl|contentUrl|fileUrl|installUrl)"\s*:\s*"([^"]+)"',
                              body, re.I):
            u = dm.group(1).replace("\\/", "/")
            out["ld_downloads"].append(u)
            u2 = _abs(u)
            if u2:
                try:
                    host = _up(u2).netloc.lower()
                    if any(h in host for h in SERVERLESS_HOSTS):
                        out["serverless_payload"].append(u2)
                    if _root_of(host) != cur_root:
                        out["payload_strong"].append(u2)
                    else:
                        out["payload_weak"].append(u2)
                except Exception:
                    pass

    # data-*
    for m in re.finditer(
            r'data-(?:dl|file|url|href|src|link|download|pkg|app)\s*=\s*["\']([^"\']{1,120})["\']',
            txt, re.I):
        v = m.group(1).strip()
        if v and v not in out["data_hints"]:
            out["data_hints"].append(v)

    # JS 映射表
    for m in re.finditer(
            r'["\']([a-z0-9_\-]{3,40})["\']\s*:\s*["\'](https?://[^"\']{6,300}?)["\']',
            txt, re.I):
        val = m.group(2).replace("\\/", "/")
        if re.search(r"\.(?:%s)" % BINARY_EXT, val, re.I) or \
                any(h in val.lower() for h in SERVERLESS_HOSTS):
            out["js_map_hits"].append(val)
    for hint in out["data_hints"]:
        for m in re.finditer(
                r'["\']%s["\']\s*:\s*["\'](https?://[^"\']{6,300}?)["\']'
                % re.escape(hint), txt, re.I):
            u = m.group(1).replace("\\/", "/")
            out["js_map_hits"].append(u)
            u2 = _abs(u)
            if u2:
                out["payload_strong"].append(u2)

    # onclick / triggerDownload
    for m in re.finditer(
            r"""on(?:click|mousedown)\s*=\s*["']([^"']{3,400}?)["']""", txt, re.I):
        for mm in re.finditer(
                r"""["']([^"']*\.(?:""" + BINARY_EXT + r"""))["']""", m.group(1), re.I):
            u = _abs(mm.group(1))
            if u:
                out["payload_weak"].append(u)
    for m in re.finditer(
            r"""(?:triggerDownload|downloadFile|startDownload)\(\s*(?:this\s*,\s*)?["']([^"']{3,300}?)["']""",
            txt, re.I):
        u = _abs(m.group(1))
        if u and re.search(r"\.(?:%s)" % BINARY_EXT, u, re.I):
            out["payload_weak"].append(u)

    # 诱导文案
    LURE = ["立即下载", "马上安装", "点击下载", "免费下载", "高速下载",
            "电脑版下载", "客户端下载", "下载安装", "一键下载", "本地下载",
            "download now", "install now", "free download"]
    out["lure_words"] = [w for w in LURE if w in txt]

    # 可疑域名
    try:
        for hh in set(re.findall(r"https?://([a-z0-9\.\-]+)", txt, re.I)):
            hh = hh.lower().split(":")[0]
            if _root_of(hh) == cur_root:
                continue
            if _risky_domain(hh):
                out["suspicious_hosts"].append(hh)
    except Exception:
        pass

    # ---------- 对象存储 / CDN 直链 ----------
    all_urls = set(re.findall(r"https?://[^\s\"'<>()\\]+", txt))
    for u in all_urls:
        try:
            hh = _up(u).netloc.lower()
        except Exception:
            continue
        if _is_object_host(hh):
            if re.search(r"\.(?:exe|zip|rar|7z|msi|apk|dmg|pkg)", u, re.I):
                out["object_storage"].append(u)
                out["payload_strong"].append(u)

    # ---------- 官方域名变体 ----------
    try:
        import json as _json
        _bf = Path(__file__).resolve().parent / "brands.json"
        _bd = _json.loads(_bf.read_text(encoding="utf-8"))
        officials = {}
        for b in _bd.get("brands", []):
            offs = [o.split("/")[0] for o in b.get("official", [])]
            if offs:
                officials[b.get("name", "")] = offs
        for hh in set(re.findall(r"https?://([a-z0-9\.\-]+)", txt, re.I)):
            hh = hh.lower().split(":")[0]
            brand = _official_variant(hh, officials)
            if brand:
                out["official_variants"].append({"host": hh, "brand": brand})
    except Exception:
        pass

    # ---------- 外部 JS 域名（head.js 型分发）----------
    for m in re.finditer(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', txt, re.I):
        u = _abs(m.group(1))
        if not u:
            continue
        try:
            hh = _up(u).netloc.lower()
        except Exception:
            continue
        if _root_of(hh) != cur_root:
            out["external_js_domains"].append(hh)
            # 外部 JS 本身也作为候选下载站记录
            out["download_pages"].append(u)

    out["object_storage"] = sorted(set(out["object_storage"]))[:10]
    out["external_js_domains"] = sorted(set(out["external_js_domains"]))[:10]
    _seen_ov = set()
    _ov = []
    for x in out["official_variants"]:
        if x["host"] not in _seen_ov:
            _seen_ov.add(x["host"])
            _ov.append(x)
    out["official_variants"] = _ov[:10]

    for k in ("payload_strong", "payload_weak", "download_pages", "ld_downloads",
              "js_map_hits", "serverless_payload", "suspicious_hosts", "data_hints"):
        out[k] = sorted(set(out[k]))[:20]
    out["data_hints"] = out["data_hints"][:15]
    seen = set()
    out["netdisks"] = [x for x in out["netdisks"]
                       if not (x["url"] in seen or seen.add(x["url"]))][:15]
    seen = set()
    out["gateways"] = [x for x in out["gateways"]
                       if not (x["url"] in seen or seen.add(x["url"]))][:10]
    return out
