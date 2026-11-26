# -*- coding: utf-8 -*-
"""
单域名全量探测编排 + 风险判定
"""
import datetime
import time

from . import dnsx, whoisx, httpx, ipx
from . import scoring

# 已知恶意特征（可扩展）
SUSPICIOUS_TLDS = {"top", "xyz", "cyou", "icu", "buzz", "click", "shop", "vip",
                   "work", "loan", "men", "gq", "tk", "ml", "cf", "ga"}
BRAND_KEYWORDS = ["deepseek", "深度求索", "yuanbao", "元宝", "doubao", "豆包",
                  "qianwen", "千问", "quark", "夸克", "feishu", "飞书",
                  "dingtalk", "钉钉", "huorong", "火绒", "jianying", "剪映",
                  "capcut", "uu", "surfshark", "proton", "strongvpn", "zoogvpn",
                  "nexusmod", "telegram", "kook", "todesk", "baidu", "360"]


def score(result):
    """兼容旧接口：转调 v2 评分"""
    r = scoring.score_v2(result)
    return {"score": r["score"], "level": r["level"],
            "reasons": [t for t, _ in r.get("strong", [])] or r.get("weak", []),
            "detail": r}


def probe(domain, options=None):
    """
    单域名全量探测
    options: {
      'multi_round': True, 'port_scan': True, 'reverse_ip': True,
      'subdomain': False, 'cert': True, 'auth_check': True,
    }
    """
    opt = {"multi_round": True, "port_scan": True, "reverse_ip": True,
           "subdomain": False, "cert": True, "auth_check": True}
    if options:
        opt.update(options)

    domain = domain.strip().lower().rstrip(".")
    if domain.startswith("http://") or domain.startswith("https://"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    t0 = time.time()
    r = {"domain": domain, "ts": datetime.datetime.now().isoformat(timespec="seconds")}

    # 1. 权威验证（判断是否真实存在，绕缓存）
    if opt["auth_check"]:
        r["auth_check"] = dnsx.authoritative_check(domain)

    # 2. DNS 全类型
    r["dns"] = dnsx.query_records(domain)

    # 3. 多轮采样（检测动态调度）
    if opt["multi_round"]:
        r["dns_multi"] = dnsx.multi_round(domain)

    # 4. WHOIS
    try:
        r["whois"] = whoisx.whois(domain)
    except Exception as e:
        r["whois"] = {"error": str(e)[:100]}

    # 5. HTTP / TLS
    ips = r["dns"].get("A", [])
    if not ips and r.get("dns_multi"):
        ips = list(r["dns_multi"].get("ip_pool", {}).keys())
        ips = [i for i in ips if not i.startswith("<")]

    if ips:
        r["http"], r["http_best"] = httpx.collect_http(domain)
        # 页面没抓到就重试一次（单次失败很常见）
        if not r["http_best"]:
            time.sleep(1.0)
            r["http"], r["http_best"] = httpx.collect_http(domain)
        if opt["cert"]:
            r["cert"] = httpx.cert_probe(domain)

        # 动态解析（可选）：静态没拿到载荷时用浏览器点击
        if opt.get("dynamic") and not (r.get("http_best") or {}).get("download_links"):
            r["dynamic"] = _run_dynamic(domain, r.get("http_best") or {})

        # 6. IP 情报
        r["ip_infos"] = []
        for ip in ips[:3]:
            ii = ipx.ip_info(ip)
            if opt["port_scan"]:
                ii["open_ports"] = ipx.port_scan(ip)
            if opt["reverse_ip"]:
                ii["reverse_ip"] = ipx.reverse_ip(ip)
            r["ip_infos"].append(ii)
    else:
        r["http"] = {}
        r["http_best"] = {}

    # 7. 子域枚举
    if opt["subdomain"]:
        r["subdomains"] = dnsx.subdomain_probe(domain)

    # 7.5 分发节点探测：外部 JS 域名 / 官方域变体 → 探测其子域
    try:
        r["dist_nodes"] = _probe_dist_nodes(domain, r.get("http_best") or {})
    except Exception as e:
        r["dist_nodes"] = {"error": str(e)[:80]}


    # 8. 风险评分（v2）
    r["risk"] = scoring.score_v2(r)
    r["elapsed"] = round(time.time() - t0, 1)
    return r


def probe_batch(domains, options=None, workers=6, progress_cb=None):
    """批量探测，返回 (results, stats)"""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results = []
    done = 0
    total = len(domains)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(probe, d, options): d for d in domains}
        for f in as_completed(futs):
            d = futs[f]
            try:
                results.append(f.result())
            except Exception as e:
                results.append({"domain": d, "error": str(e)[:120],
                                "risk": {"score": 0, "level": "探测失败", "reasons": [str(e)[:80]]}})
            done += 1
            if progress_cb:
                progress_cb(done, total, d)

    # ---- 跨域名同源关联（同模板 / 同邮箱 / 同IP / 同证书）----
    _mark_relations(results)

    order = {d: i for i, d in enumerate(domains)}
    results.sort(key=lambda x: order.get(x["domain"], 9999))

    # 统计
    from collections import Counter
    lv = Counter(r.get("risk", {}).get("level", "未知") for r in results)
    stats = {
        "total": total,
        "by_level": dict(lv),
        "alive": sum(1 for r in results if r.get("dns", {}).get("A")),
        "dynamic": sum(1 for r in results if r.get("dns_multi", {}).get("dynamic")),
        "with_payload": sum(1 for r in results
                            if (r.get("http_best") or {}).get("download_links")),
        "elapsed": round(sum(r.get("elapsed", 0) for r in results), 1),
    }
    return results, stats

def _mark_relations(results):
    """
    批量跑完后统一分析同源关系，写回每个结果的 rel 字段：
      rel = {"md5_group": [...], "email_group": [...], "ip_group": [...], "cert_group": [...]}
    命中任意分组的域名会被加上 strong 证据（同源聚集），分值最高 25。
    """
    from collections import defaultdict

    md5_map = defaultdict(list)
    email_map = defaultdict(list)
    ip_map = defaultdict(list)
    cert_map = defaultdict(list)

    for r in results:
        h = r.get("http_best") or {}
        m = h.get("body_md5")
        if m and h.get("len", 0) > 5000:      # 忽略太小或空的页面
            md5_map[m].append(r["domain"])

        w = r.get("whois") or {}
        em = w.get("email")
        if em and "redacted" not in em.lower() and "@" in em:
            email_map[em].append(r["domain"])

        for ip in (r.get("dns") or {}).get("A", []):
            ip_map[ip].append(r["domain"])

        cert = r.get("cert") or {}
        sn = cert.get("serial")
        if sn:
            cert_map[str(sn)].append(r["domain"])

    for r in results:
        rel = {}
        h = r.get("http_best") or {}
        m = h.get("body_md5")
        if m and len(md5_map.get(m, [])) > 1:
            rel["md5_group"] = [d for d in md5_map[m] if d != r["domain"]]

        em = (r.get("whois") or {}).get("email")
        if em and len(email_map.get(em, [])) > 1:
            rel["email_group"] = [d for d in email_map[em] if d != r["domain"]]

        for ip in (r.get("dns") or {}).get("A", []):
            if len(ip_map.get(ip, [])) > 1:
                rel.setdefault("ip_group", [])
                rel["ip_group"].extend(
                    [d for d in ip_map[ip] if d != r["domain"]])

        sn = str((r.get("cert") or {}).get("serial") or "")
        if sn and len(cert_map.get(sn, [])) > 1:
            rel["cert_group"] = [d for d in cert_map[sn] if d != r["domain"]]

        if rel:
            r["rel"] = rel
            risk = r.setdefault("risk", {"strong": [], "weak": [], "deduct": []})
            strong = risk.setdefault("strong", [])
            add = 0
            if rel.get("md5_group"):
                strong.append(("页面与 %d 个同批域名完全一致（同模板同源）"
                               % len(rel["md5_group"]), 25))
                add += 25
            if rel.get("email_group"):
                strong.append(("与 %d 个同批域名共用注册邮箱（同主体）"
                               % len(rel["email_group"]), 25))
                add += 25
            if rel.get("cert_group"):
                strong.append(("与 %d 个同批域名共用同一张证书"
                               % len(rel["cert_group"]), 15))
                add += 15
            if add:
                risk["score"] = min(100, (risk.get("score") or 0) + add)
                s = risk["score"]
                risk["level"] = ("高危" if s >= 70 else "可疑" if s >= 45
                                 else "低危" if s >= 20 else "正常")

def _run_dynamic(domain, http_best):
    """
    调 Playwright 解析 JS 驱动的下载地址，并把结果合并回 http_best
    """
    try:
        from . import dynamic as dyn
    except Exception as e:
        return {"ok": False, "error": str(e)[:100]}

    ok, err = dyn.is_available()
    if not ok:
        return {"ok": False, "error": err}

    page_url = http_best.get("final_url") or ("https://%s/" % domain)
    res = dyn.resolve(page_url, timeout=30000, max_clicks=6)

    # 合并到 http_best
    if res.get("payloads"):
        cur_strong = set(http_best.get("payload_strong") or [])
        cur_weak = set(http_best.get("payload_weak") or [])
        from urllib.parse import urlparse as _up

        def _root(h):
            h = (h or "").lower().split(":")[0]
            parts = h.split(".")
            for s in (".com.cn", ".net.cn", ".org.cn", ".gov.cn", ".edu.cn"):
                if h.endswith(s):
                    return ".".join(parts[-3:])
            return ".".join(parts[-2:]) if len(parts) >= 2 else h

        cur_root = _root(_up(page_url).netloc)
        for u in res["payloads"]:
            try:
                pr = _root(_up(u).netloc)
            except Exception:
                continue
            if pr != cur_root:
                cur_strong.add(u)
            else:
                cur_weak.add(u)

        http_best["payload_strong"] = sorted(cur_strong)[:20]
        http_best["payload_weak"] = sorted(cur_weak)[:20]
        http_best["download_links"] = sorted(cur_strong | cur_weak)[:20]
        http_best["dynamic_found"] = True

    http_best["dynamic_requests"] = res.get("requests") or []
    http_best["dynamic_downloads"] = res.get("downloads") or []
    return res

# 公共统计 / 公共服务 / 知名 CDN，不当作攻击者的分发节点
NOISE_HOSTS = (
    "51.la", "cnzz.com", "umeng.com", "baidu.com", "google-analytics.com",
    "googletagmanager.com", "gtag", "hm.baidu.com", "clarity.ms",
    "doubleclick.net", "facebook.net", "twitter.com", "jquery.com",
    "bootcdn.net", "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "staticfile.org", "fontawesome.com", "googleapis.com", "gstatic.com",
    "cloudflare.com", "cloudflareinsights.com", "51yes.com", "51tui.com",
    "w3.org", "schema.org", "mozilla.org", "wordpress.org", "wp.com",
    "qq.com", "weixin.qq.com", "gtimg.cn", "bdstatic.com",
)


def _is_noise(host):
    h = (host or "").lower()
    return any(k in h for k in NOISE_HOSTS)


def _probe_dist_nodes(domain, http_best):
    """
    从页面线索里找出候选分发节点，探测常见子域，抓载荷
    返回 {
      candidates: [{host, source}],
      probed: [{host, ips, status, payloads}],
      payloads: [url...]
    }
    """
    import requests
    from . import httpx as _hx

    out = {"candidates": [], "probed": [], "payloads": []}

    # 候选来源1：页面引用的外部 JS 域名
    for h in (http_best.get("external_js") or []):
        out["candidates"].append({"host": h, "source": "外部JS"})
    # 来源2：官方域变体
    for x in (http_best.get("official_variants") or []):
        out["candidates"].append({"host": x.get("host"), "source": "官方域变体"})

    # 去重，排除已处理过的域名
    seen = {domain}
    cands = []
    for c in out["candidates"]:
        h = (c.get("host") or "").lower()
        if not h or h in seen:
            continue
        if _is_noise(h):
            continue
        seen.add(h)
        cands.append(c)
    out["candidates"] = cands[:6]

    if not cands:
        return out

    # 对每个候选域，先解析主域，再试探常见子域
    import dns.resolver
    SUBS = ["1", "2", "1019web", "web", "www", "dl", "down", "app", "cdn", "static"]
    UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

    for c in cands:
        base = c["host"]
        # 去掉公共后缀得到主域
        parts = base.split(".")
        if len(parts) >= 3 and parts[-2] in ("com", "net", "org", "gov", "edu")                 and parts[-1] == "cn":
            root = ".".join(parts[-3:])
        else:
            root = ".".join(parts[-2:]) if len(parts) >= 2 else base

        test_hosts = [root]
        for s in SUBS:
            test_hosts.append("%s.%s" % (s, root))

        for th in test_hosts[:8]:
            if th in seen or _is_noise(th):
                continue
            seen.add(th)
            try:
                ans = dns.resolver.resolve(th, "A", lifetime=4)
                ips = sorted({x.address for x in ans})
            except Exception:
                continue

            item = {"host": th, "ips": ips, "status": None, "payloads": []}
            # 有解析就试着抓页面
            try:
                url = "http://%s/" % th
                r = requests.get(url, headers={"User-Agent": UA}, timeout=10,
                                 verify=False, allow_redirects=True)
                item["status"] = r.status_code
                if r.status_code < 400 and len(r.text) > 200:
                    sub = _hx.analyze_links(r.text, url)
                    pays = (sub.get("payload_strong") or []) + \
                           (sub.get("object_storage") or [])
                    if pays:
                        item["payloads"] = sorted(set(pays))[:5]
                        for x in item["payloads"]:
                            if x not in out["payloads"]:
                                out["payloads"].append(x)
            except Exception:
                pass

            out["probed"].append(item)

    # 把抓到的载荷合并进 http_best
    if out["payloads"]:
        cur = set(http_best.get("payload_strong") or [])
        cur |= set(out["payloads"])
        http_best["payload_strong"] = sorted(cur)[:20]
        http_best["download_links"] = sorted(
            set(http_best.get("download_links") or []) | cur)[:20]

    return out
