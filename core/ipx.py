# -*- coding: utf-8 -*-
"""
IP 情报模块
- 归属 / ASN：优先 Team Cymru DNS（查 BGP 路由表，最权威），ip-api 兜底
- 反向 DNS
- 端口探测（并发）
- 同 IP 反查
"""
import socket
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor

import dns.resolver
import requests
import urllib3

urllib3.disable_warnings()

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 888,
                 993, 995, 1433, 3306, 3389, 5432, 6379, 8080, 8443, 27017]


def _cymru(ip):
    """Team Cymru DNS 接口，直接查 BGP 路由表，比第三方 IP 库准"""
    rev = ".".join(reversed(ip.split(".")))
    out = {}
    try:
        ans = dns.resolver.resolve("%s.origin.asn.cymru.com" % rev, "TXT", lifetime=6)
        for r in ans:
            txt = r.to_text().strip('"')
            parts = [x.strip() for x in txt.split("|")]
            if len(parts) >= 3:
                out["asn"] = parts[0]
                out["prefix"] = parts[1]
                out["country"] = parts[2]
                out["registry"] = parts[3] if len(parts) > 3 else ""
    except Exception:
        pass
    if out.get("asn"):
        asn = out["asn"].split()[0].lstrip("AS")
        try:
            ans = dns.resolver.resolve("AS%s.asn.cymru.com" % asn, "TXT", lifetime=6)
            for r in ans:
                txt = r.to_text().strip('"')
                parts = [x.strip() for x in txt.split("|")]
                if len(parts) >= 5:
                    out["as_name"] = parts[-1]
        except Exception:
            pass
    return out


def _ipapi(ip):
    """ip-api 兜底，带中文归属"""
    try:
        j = requests.get(
            "http://ip-api.com/json/%s?lang=zh-CN&fields=status,country,regionName,city,"
            "isp,org,as,hosting,proxy,mobile" % ip,
            timeout=6).json()
        if j.get("status") == "success":
            return j
    except Exception:
        pass
    return {}


def ip_info(ip):
    """综合 IP 情报"""
    out = {"ip": ip}

    c = _cymru(ip)
    if c.get("asn"):
        out["asn"] = "AS" + c["asn"].split()[0].lstrip("AS")
        out["bgp_prefix"] = c.get("prefix", "")
        out["bgp_country"] = c.get("country", "")
        out["as_name"] = c.get("as_name", "")

    a = _ipapi(ip)
    if a:
        out.update({
            "country": a.get("country", ""),
            "region": a.get("regionName", ""),
            "city": a.get("city", ""),
            "isp": a.get("isp", ""),
            "org": a.get("org", ""),
            "as_string": a.get("as", ""),
            "is_hosting": a.get("hosting"),
            "is_proxy": a.get("proxy"),
        })

    try:
        out["ptr"] = socket.gethostbyaddr(ip)[0]
    except Exception:
        out["ptr"] = ""

    return out


def port_scan(ip, ports=None, timeout=1.5, max_workers=20):
    """常见端口探测，并发执行（串行会极慢）"""
    ports = ports or DEFAULT_PORTS

    def one(p):
        try:
            with socket.create_connection((ip, p), timeout=timeout):
                return p
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        got = [p for p in ex.map(one, ports) if p]
    return sorted(got)


def reverse_ip(ip, timeout=12):
    """同 IP 反查（免费接口，配额有限，失败返回空）"""
    out = []
    try:
        r = requests.get("https://api.hackertarget.com/reverseiplookup/?q=%s" % ip,
                         timeout=timeout)
        t = r.text.strip()
        if t and "error" not in t.lower() and "no records" not in t.lower() \
                and "API count exceeded" not in t:
            out = [x.strip() for x in t.splitlines() if x.strip()][:100]
    except Exception:
        pass
    return out


def traceroute(ip):
    """对 IP 做路由追踪（可选，较慢）"""
    try:
        if "windows" in platform.system().lower():
            cmd = ["tracert", "-h", "12", "-w", "800", ip]
        else:
            cmd = ["traceroute", "-m", "12", "-w", "1", ip]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60, errors="ignore")
        return r.stdout[:3000]
    except Exception as e:
        return "traceroute 失败: " + str(e)[:60]