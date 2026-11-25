# -*- coding: utf-8 -*-
"""
多节点解析探测 —— 判断是否使用 CDN，并寻找未套 CDN 的漏点

原理：
CDN 的 DNS 按查询来源分配最近边缘节点。从不同地区/运营商查询同一域名：
- 返回多个分散 IP，且都属于已知 CDN 段  → 确认使用 CDN，正常
- 某个节点返回不属于任何 CDN 段的 IP      → 疑似直连源站（漏点）

数据源：check-host.net 公开 API（免费，无需 key）
"""
import time

import requests
import urllib3

urllib3.disable_warnings()

BASE = "https://check-host.net"
HEADERS = {
    "Accept": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36",
}

# 主要 CDN / 云 WAF 的 IP 段（前缀匹配）
CDN_PREFIXES = {
    "Cloudflare": ["104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
                   "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
                   "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.",
                   "172.70.", "172.71.", "188.114.", "162.158.", "162.159.",
                   "173.245.", "197.234.", "198.41.", "190.93.", "131.0.72."],
    "Akamai": ["23.32.", "23.33.", "23.34.", "23.35.", "23.36.", "23.37.", "23.38.",
               "23.39.", "23.40.", "23.41.", "23.42.", "23.43.", "23.44.", "23.45.",
               "23.46.", "23.47.", "23.48.", "23.49.", "23.50.", "23.51.", "23.52.",
               "23.53.", "23.54.", "23.55.", "23.56.", "23.57.", "23.58.", "23.59.",
               "23.60.", "23.61.", "23.62.", "23.63.", "23.64.", "23.65.", "23.66.",
               "23.67.", "23.72.", "23.73.", "23.74.", "23.75.", "23.76.", "23.77.",
               "23.78.", "23.79.", "23.192.", "23.193.", "23.194.", "23.195.",
               "23.196.", "23.197.", "23.198.", "23.199.", "23.200.", "23.201.",
               "23.202.", "23.203.", "23.204.", "23.205.", "23.206.", "23.207.",
               "23.208.", "23.209.", "23.210.", "23.211.", "23.212.", "23.213.",
               "23.214.", "23.215.", "23.216.", "23.217.", "23.218.", "23.219.",
               "23.220.", "23.221.", "23.222.", "23.223."],
    "Fastly": ["151.101.", "199.232.", "185.31.17.", "23.235."],
    "CloudFront": ["13.32.", "13.33.", "13.224.", "13.225.", "13.226.", "13.227.",
                   "13.228.", "13.54.", "13.113.", "13.124.", "13.126.", "13.35.",
                   "52.84.", "52.85.", "54.182.", "54.192.", "54.230.", "54.239.",
                   "99.84.", "99.86.", "18.64.", "18.65.", "18.66.", "18.67.",
                   "18.68.", "18.238.", "18.239.", "18.244."],
    "Azure": ["13.107.", "20.36.", "20.37.", "20.38.", "20.39.", "20.40.", "20.41.",
              "20.42.", "20.43.", "20.44.", "20.45.", "20.46.", "20.47.", "20.48.",
              "20.49.", "20.50.", "20.51.", "20.52.", "20.53.", "20.54.", "20.55.",
              "20.56.", "20.57.", "20.58.", "20.59.", "20.60.", "20.61.", "20.62.",
              "20.63.", "20.64.", "20.65.", "20.66.", "20.67.", "20.68.", "20.69.",
              "20.70.", "20.71.", "20.72.", "20.73.", "20.74.", "20.75.", "20.76.",
              "20.77.", "20.78.", "20.79.", "20.80.", "20.81.", "20.82.", "20.83.",
              "20.84.", "20.85.", "20.86.", "20.87.", "20.88.", "20.89.", "20.90.",
              "20.91.", "20.92.", "20.93.", "20.94.", "20.95.", "20.96.", "20.97.",
              "20.98.", "20.99.", "20.100.", "20.101.", "20.102.", "20.103.",
              "20.104.", "20.105.", "20.106.", "20.107.", "20.108.", "20.109.",
              "20.110.", "20.111.", "20.112.", "20.113.", "20.114.", "20.115.",
              "20.116.", "20.117.", "20.118.", "20.119.", "20.120.", "20.121.",
              "20.122.", "20.123.", "20.124.", "20.125.", "20.126.", "20.127.",
              "20.128.", "20.129.", "20.130.", "20.131.", "20.132.", "20.133.",
              "52.96.", "52.97.", "52.98.", "52.99."],
    "阿里云CDN": ["117.185.", "121.0.16.", "47.246.", "8.209.", "47.91."],
    "腾讯云CDN": ["1.12.", "1.32.", "119.28.", "129.28.", "150.109.", "203.205."],
    "百度云加速": ["103.235.", "45.113."],
    "Incapsula": ["45.64.64.", "103.28.248.", "107.154.", "149.126.", "185.11.",
                  "192.230.", "199.83.", "45.60.0.", "45.60.1."],
    "Sucuri": ["192.124.249.", "185.93.2."],
    "StackPath/MaxCDN": ["151.139."],
    "Gcore": ["92.223."],
    "AWS Global Accelerator": ["75.2."],
}


def _cdn_of(ip):
    """判断 IP 属于哪个 CDN，返回 CDN 名称或 None"""
    for name, prefixes in CDN_PREFIXES.items():
        for p in prefixes:
            if ip.startswith(p):
                return name
    return None


def _fmt_location(meta):
    """['at','Austria','Vienna','1.2.3.4','AS123'] -> '奥地利 维也纳'"""
    if not meta or len(meta) < 3:
        return "未知"
    return "%s %s" % (meta[1], meta[2])


def check_dns(domain, max_nodes=25, timeout_wait=40):
    """
    多节点 DNS 解析
    返回 {'domain','nodes':[{'node','country','city','ips','cdn','error'}],
          'ip_pool','cdn_names','is_cdn','suspects','error'}
    """
    out = {"domain": domain, "nodes": [], "ip_pool": {}, "cdn_names": {},
           "is_cdn": False, "suspects": []}

    try:
        r = requests.get(BASE + "/check-dns",
                         params={"host": domain, "max_nodes": max_nodes},
                         headers=HEADERS, timeout=15, verify=False)
        if r.status_code != 200:
            out["error"] = "提交失败 HTTP %s" % r.status_code
            return out
        j = r.json()
    except Exception as e:
        out["error"] = "%s: %s" % (type(e).__name__, str(e)[:80])
        return out

    req_id = j.get("request_id")
    node_meta = j.get("nodes") or {}
    if not req_id:
        out["error"] = "未获取 request_id"
        return out

    # 轮询
    result, deadline = None, time.time() + max(10, timeout_wait)
    try:
        while time.time() < deadline:
            time.sleep(2.5)
            r2 = requests.get(BASE + "/check-result/" + req_id,
                              headers=HEADERS, timeout=15, verify=False)
            if r2.status_code != 200:
                continue
            data = r2.json()
            if not isinstance(data, dict):
                continue
            result = data
            if data and all(v is not None for v in data.values()):
                break
    except Exception:
        pass

    if not result:
        out["error"] = "等待结果超时"
        return out

    pool = {}
    cdn_names = {}
    for node, res in result.items():
        meta = node_meta.get(node) or []
        ips = []
        err = ""
        if not res:
            err = "无响应"
        elif isinstance(res, list):
            for entry in res:
                if isinstance(entry, dict):
                    # 正常结构：{"A": [...], "AAAA": [...], "TTL": n}
                    a = entry.get("A")
                    if isinstance(a, list):
                        ips.extend([x for x in a if isinstance(x, str)])
                    elif isinstance(a, str):
                        ips.append(a)
                    if entry.get("error"):
                        err = str(entry["error"])[:40]
                elif isinstance(entry, list) and len(entry) >= 2:
                    # ping 风格：['OK', '1.2.3.4', '12ms']
                    if isinstance(entry[1], str) and entry[1].count(".") == 3:
                        ips.append(entry[1])

        ips = sorted(set(ips))
        cdn = ""
        for ip in ips:
            c = _cdn_of(ip)
            if c:
                cdn = c
                cdn_names[c] = cdn_names.get(c, 0) + 1
                break

        for ip in ips:
            pool[ip] = pool.get(ip, 0) + 1

        out["nodes"].append({
            "node": node,
            "location": _fmt_location(meta),
            "asn": meta[4] if len(meta) > 4 else "",
            "ips": ips,
            "cdn": cdn,
            "error": err,
        })

    out["ip_pool"] = dict(sorted(pool.items(), key=lambda x: -x[1]))
    out["cdn_names"] = cdn_names

    ipv4 = [ip for ip in pool if ":" not in ip]
    out["is_cdn"] = len(ipv4) >= 3 or bool(cdn_names)

    # 找漏点：不属于任何已知 CDN 段的 IP
    for ip, c in out["ip_pool"].items():
        if ":" in ip:
            continue
        if _cdn_of(ip):
            continue
        nodes_with = [n["node"] for n in out["nodes"] if ip in n["ips"]]
        out["suspects"].append({
            "ip": ip,
            "count": c,
            "nodes": nodes_with,
            "reason": "不在已知 CDN 段",
        })

    # 节点按地区排序
    out["nodes"].sort(key=lambda x: x["location"])
    return out


def summarize(r):
    """生成给界面用的一行摘要"""
    if r.get("error"):
        return "多节点探测失败: " + r["error"]
    n = len([x for x in r.get("nodes", []) if x.get("ips")])
    total = len(r.get("nodes", []))
    ips = list((r.get("ip_pool") or {}).keys())
    if not ips:
        return "多节点均无解析结果（%d 个节点）" % total
    cdn = ", ".join("%s×%d" % (k, v) for k, v in (r.get("cdn_names") or {}).items())
    s = "已测 %d/%d 节点，返回 %d 个不同 IP" % (n, total, len(ips))
    if cdn:
        s += "，CDN: " + cdn
    if r.get("suspects"):
        s += "，⚠ %d 个疑似源站" % len(r["suspects"])
    return s