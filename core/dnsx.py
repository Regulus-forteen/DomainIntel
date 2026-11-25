# -*- coding: utf-8 -*-
"""
DNS 采集模块

关键设计（来自实战教训）：
1. 权威验证：直接向 gTLD 权威服务器查询，绕过所有递归缓存
   —— 系统 DNS 缓存残留会导致「已删除的域名被判为存在」这类误判
2. 多轮采样：同一域名用多个公共 DNS 多次查询，检测动态调度
3. 区分 NXDOMAIN / NODATA / 超时，三种状态含义完全不同
"""
import time
from collections import Counter

import dns.resolver
import dns.message
import dns.query
import dns.rcode

PUBLIC_DNS = ["223.5.5.5", "119.29.29.29", "180.76.76.76",
              "114.114.114.114", "8.8.8.8", "1.1.1.1", "9.9.9.9"]

_TLD_NS_CACHE = {}


def _get_tld_servers(tld):
    """取 gTLD / ccTLD 权威服务器 IP，带缓存"""
    tld = tld.lower()
    if tld in _TLD_NS_CACHE:
        return _TLD_NS_CACHE[tld]
    ips = []
    try:
        for r in dns.resolver.resolve(tld, "NS", lifetime=8):
            ns = r.target.to_text().rstrip(".")
            try:
                for a in dns.resolver.resolve(ns, "A", lifetime=5):
                    ips.append(a.address)
            except Exception:
                pass
    except Exception:
        pass
    _TLD_NS_CACHE[tld] = ips[:6]
    return _TLD_NS_CACHE[tld]


def authoritative_check(domain, timeout=4):
    """
    直接问注册局权威服务器，判断域名在注册局层面是否存在。
    返回 {'status': 'EXISTS'|'NXDOMAIN'|'FAIL', 'via': ip, 'delegated_ns': [...]}
    这是判断域名真实存在性的唯一可靠方式。
    """
    tld = domain.rsplit(".", 1)[-1]
    servers = _get_tld_servers(tld)
    if not servers:
        return {"status": "FAIL", "reason": "no_tld_server"}

    last_err = ""
    for ip in servers:
        try:
            q = dns.message.make_query(domain, "A")
            resp = dns.query.udp(q, ip, timeout=timeout)
            rc = dns.rcode.to_text(resp.rcode())
            if rc == "NXDOMAIN":
                return {"status": "NXDOMAIN", "via": ip}
            if rc == "NOERROR":
                answers = []
                for rrset in resp.answer:
                    for rr in rrset:
                        answers.append(rr.to_text())
                ns_deleg = []
                for rrset in resp.authority:
                    if rrset.rdtype == 2:  # NS
                        for rr in rrset:
                            ns_deleg.append(rr.target.to_text().rstrip("."))
                return {"status": "EXISTS", "via": ip,
                        "answers": answers, "delegated_ns": ns_deleg[:5]}
        except Exception as e:
            last_err = type(e).__name__
    return {"status": "FAIL", "reason": last_err or "all_timeout"}


def query_records(domain, rtypes=("A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA", "CAA"),
                  timeout=4):
    """
    查询各类 DNS 记录。
    必须显式指定公共 DNS，不能用系统默认解析器——
    系统解析器常带本地缓存（甚至被污染），会把已变更的旧记录当成当前值。
    """
    out = {}
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["223.5.5.5", "119.29.29.29"]
    resolver.timeout = timeout
    resolver.lifetime = timeout + 2
    for rt in rtypes:
        try:
            ans = resolver.resolve(domain, rt, raise_on_no_answer=False)
            if ans.rrset:
                out[rt] = [r.to_text().rstrip(".") for r in ans]
        except Exception:
            pass
    return out


def multi_round(domain, rounds=2, nameservers=None):
    """
    多 DNS 多轮采样，检测动态调度。
    返回 {'ip_pool': {ip: count}, 'distinct_ip_count', 'dynamic', 'all_nxdomain', ...}
    """
    nameservers = nameservers or ["223.5.5.5", "119.29.29.29", "8.8.8.8"]
    ips = Counter()
    errors = Counter()
    nx = 0
    total = 0

    for srv in nameservers:
        for _ in range(rounds):
            total += 1
            try:
                r = dns.resolver.Resolver(configure=False)
                r.nameservers = [srv]
                r.timeout = 4
                r.lifetime = 6
                ans = r.resolve(domain, "A", raise_on_no_answer=False)
                if ans.rrset:
                    for x in ans:
                        ips[x.address] += 1
                else:
                    errors["NODATA"] += 1
            except dns.resolver.NXDOMAIN:
                nx += 1
            except Exception as e:
                errors[type(e).__name__] += 1
            time.sleep(0.05)

    distinct = list(ips.keys())
    return {
        "ip_pool": dict(ips.most_common()),
        "distinct_ip_count": len(distinct),
        "dynamic": len(distinct) > 1,
        "all_nxdomain": (nx == total),
        "nxdomain_count": nx,
        "total_queries": total,
        "errors": dict(errors),
    }


def subdomain_probe(domain, prefixes=None, timeout=3, max_workers=20):
    """常见子域枚举"""
    from concurrent.futures import ThreadPoolExecutor

    prefixes = prefixes or [
        "www", "m", "app", "api", "cn", "en", "dl", "download", "pc", "mobile",
        "admin", "mail", "ftp", "vpn", "test", "dev", "static", "cdn", "img",
        "login", "user", "passport", "pay", "shop", "bbs", "blog",
    ]

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["223.5.5.5", "119.29.29.29"]
    resolver.timeout = timeout
    resolver.lifetime = timeout + 1

    def check(p):
        fq = "%s.%s" % (p, domain)
        try:
            ans = resolver.resolve(fq, "A", raise_on_no_answer=False)
            if ans.rrset:
                return {"sub": fq, "ips": sorted({x.address for x in ans})}
        except Exception:
            pass
        return None

    found = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for r in ex.map(check, prefixes):
            if r:
                found.append(r)
    return found

def _confirm_nx_by_soa(domain, timeout=4):
    """
    二次确认：向父域的权威服务器查询 SOA。
    如果返回 NOERROR 且有 SOA 记录，说明域名的父区存在，
    但对域名的 NS 查询无委派 —— 进一步佐证 NXDOMAIN。
    仅作为辅助，不单独作为判定依据。
    """
    tld = domain.rsplit(".", 1)[-1]
    servers = _get_tld_servers(tld)
    if not servers:
        return None
    try:
        import dns.message
        import dns.query
        q = dns.message.make_query(domain, "SOA")
        for ip in servers[:2]:
            try:
                resp = dns.query.udp(q, ip, timeout=timeout)
                for rrset in resp.authority:
                    if rrset.rdtype == 6:  # SOA
                        return True
                return False
            except Exception:
                continue
    except Exception:
        pass
    return None
