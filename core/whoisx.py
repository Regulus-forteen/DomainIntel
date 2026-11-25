# -*- coding: utf-8 -*-
"""
WHOIS 采集模块
用裸 socket 直连 43 端口，不依赖 whois 命令行（Windows 常没有）
.cn / .com.cn -> whois.cnnic.cn
.com / .net  -> whois.verisign-grs.com（thin，需二次查注册商）
其余 TLD  -> whois.iana.org 找 refer
"""
import socket
import re
import time

WHOIS_SERVERS = {
    "cn": "whois.cnnic.cn",
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "cc": "ccwhois.verisign-grs.com",
    "org": "whois.pir.org",
    "io": "whois.nic.io",
    "top": "whois.nic.top",
    "xyz": "whois.nic.xyz",
    "vip": "whois.nic.vip",
    "cc": "ccwhois.verisign-grs.com",
}

# 二级后缀，取根域时要保留三段
SECOND_LEVEL = (".com.cn", ".net.cn", ".org.cn", ".gov.cn", ".edu.cn", ".ac.cn")


def _root_of(domain):
    """从子域提取可查询 WHOIS 的根域"""
    d = domain.lower().rstrip(".")
    for s in SECOND_LEVEL:
        if d.endswith(s):
            parts = d.split(".")
            return ".".join(parts[-3:])
    parts = d.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else d


def _raw_query(domain, server, timeout=12):
    try:
        s = socket.create_connection((server, 43), timeout=timeout)
        s.sendall((domain + "\r\n").encode())
        buf = b""
        while True:
            d = s.recv(8192)
            if not d:
                break
            buf += d
        s.close()
        return buf.decode("utf-8", "ignore")
    except Exception as e:
        return "__ERR__ %s: %s" % (type(e).__name__, e)


def _parse(txt):
    o = {}

    def g(*pats):
        for p in pats:
            m = re.search(p, txt, re.I | re.M)
            if m:
                v = m.group(1).strip()
                if v and v.lower() not in ("redacted for privacy", "not disclosed", "n/a", "-"):
                    return v
        return None

    # 部分注册局响应每行带前导空格，正则必须容忍 ^\s*
    o["registrar"] = g(r"^\s*Sponsoring Registrar:\s*(.+)$", r"^\s*Registrar:\s*(.+)$")
    o["registrant"] = g(r"^\s*Registrant:\s*(.+)$",
                        r"^\s*Registrant Organization:\s*(.+)$",
                        r"^\s*Registrant Name:\s*(.+)$")
    o["email"] = g(r"^\s*Registrant Contact Email:\s*(.+)$",
                   r"^\s*Registrant Email:\s*(.+)$")
    o["reg_time"] = g(r"^\s*Registration Time:\s*(.+)$", r"^\s*Creation Date:\s*(.+)$")
    o["exp_time"] = g(r"^\s*Expiration Time:\s*(.+)$", r"^\s*Registry Expiry Date:\s*(.+)$")
    o["upd_time"] = g(r"^\s*Updated Date:\s*(.+)$", r"^\s*Last Updated On:\s*(.+)$")
    o["country"] = g(r"^\s*Registrant Country:\s*(.+)$", r"^\s*Country:\s*(.+)$")
    o["phone"] = g(r"^\s*Registrant Phone:\s*(.+)$")
    o["org"] = g(r"^\s*Registrant Organization:\s*(.+)$")

    o["status"] = [x.strip() for x in
                   re.findall(r"^\s*Domain Status:\s*(.+?)(?:\s+https?://\S+)?$", txt, re.I | re.M)]
    o["ns"] = sorted({x.strip().lower()
                      for x in re.findall(r"^\s*Name Server:\s*(.+)$", txt, re.I | re.M)})
    o["dnssec"] = g(r"^\s*DNSSEC:\s*(.+)$")
    o["abuse_email"] = g(r"^\s*Registrar Abuse Contact Email:\s*(.+)$")
    return o


def whois(domain):
    """查询 WHOIS，返回解析字段 + 原始报文"""
    root = _root_of(domain)
    tld = root.rsplit(".", 1)[-1].lower()
    server = WHOIS_SERVERS.get(tld)

    if not server:
        t = _raw_query(root, "whois.iana.org")
        m = re.search(r"^\s*whois:\s*(\S+)", t, re.I | re.M)
        server = m.group(1) if m else None
        if not server:
            return {"query": root, "error": "不支持的 TLD（未能从 IANA 找到 whois 服务器）"}

    txt = _raw_query(root, server)
    if txt.startswith("__ERR__"):
        return {"query": root, "error": txt[:120]}

    # CNNIC 限流
    if "Queried interval is too short" in txt or "too many" in txt.lower():
        time.sleep(3)
        txt = _raw_query(root, server)

    # .com/.net 是 thin whois，需二次查注册商拿注册人
    if server == "whois.verisign-grs.com":
        m = re.search(r"^\s*Registrar WHOIS Server:\s*(\S+)", txt, re.I | re.M)
        if m:
            t2 = _raw_query(root, m.group(1))
            if not t2.startswith("__ERR__"):
                txt = txt + "\n\n" + t2

    o = _parse(txt)
    o["query"] = root
    o["whois_server"] = server
    o["raw"] = txt[:6000]

    low = txt.lower()
    if ("no match for" in low or "no matching record" in low
            or "not found" in low or "no entries found" in low):
        o["not_registered"] = True

    return o


def format_summary(w):
    """一行摘要"""
    if w.get("error"):
        return "WHOIS 失败: " + str(w["error"])[:40]
    if w.get("not_registered"):
        return "未注册（注册局无记录）"
    bits = []
    if w.get("registrant"):
        bits.append("注册人=" + w["registrant"])
    if w.get("email"):
        bits.append("邮箱=" + w["email"])
    if w.get("registrar"):
        bits.append("注册商=" + w["registrar"])
    if w.get("reg_time"):
        bits.append("注册=" + str(w["reg_time"])[:10])
    return " | ".join(bits) or "已注册，信息未公开"