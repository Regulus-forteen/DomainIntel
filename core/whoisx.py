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

    # 隐私保护判定
    try:
        o["privacy"] = detect_privacy(txt, o)
    except Exception:
        o["privacy"] = {"enabled": False, "matched": [], "evidence": [],
                        "registrar_privacy": False}

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

# ---------------------------------------------------------------- 隐私保护识别
_PRIVACY_NAME_PAT = [
    r"redacted for privacy", r"^redacted$", r"not disclosed", r"^n/?a$",
    r"^privacy", r"privacy service", r"whois privacy", r"domain privacy",
    r"withheld for privacy", r"data protected", r"gdpr masked",
    r"statutory masking", r"identity protected", r"contact privacy",
    r"domains by proxy", r"withheld", r"protected$", r"^not available$",
]


def _is_private_value(v):
    """判断单个字段值是否是隐私占位"""
    if not v:
        return False
    s = str(v).strip().lower()
    if s in ("", "-", "n/a", "na", "none", "null", "not available"):
        return True
    for pat in _PRIVACY_NAME_PAT:
        if re.search(pat, s):
            return True
    return False


def _is_private_email(v):
    """邮箱侧：占位邮箱或含隐私关键词"""
    if not v:
        return False
    s = str(v).strip().lower()
    for k in ("privacy@", "protect@", "redacted", "withheld",
              "domain-contact.org", "whoisprotect", "privacyguardian",
              "contact-form", "donotsell", "gdpr"):
        if k in s:
            return True
    if s.startswith("abuse@") and _is_private_value(s):
        return True
    return False


def detect_privacy(txt, parsed=None):
    """
    综合判定 WHOIS 是否启用了隐私保护
    返回 {
      enabled: bool,
      matched: [命中的字段名...],
      evidence: [命中的原文片段...],
      registrar_privacy: bool   # 注册商本身提供隐私服务（如 Domains By Proxy）
    }
    """
    parsed = parsed or {}
    low = (txt or "").lower()
    matched = []
    evidence = []

    # 1) 结构化字段判定
    field_map = {
        "registrant": ("注册人", parsed.get("registrant")),
        "email": ("注册邮箱", parsed.get("email")),
        "phone": ("电话", parsed.get("phone")),
        "country": ("国家", parsed.get("country")),
        "org": ("组织", parsed.get("org")),
    }
    for key, (label, v) in field_map.items():
        if key == "email":
            if _is_private_email(v):
                matched.append(label)
                if v:
                    evidence.append(v[:50])
        else:
            if _is_private_value(v):
                matched.append(label)
                if v:
                    evidence.append(str(v)[:50])

    # 2) 原文关键词判定
    kw_hits = []
    for kw in ("隐私保护", "whois privacy", "privacy protect", "隐私服务",
               "redacted for privacy", "data protected", "domain privacy",
               "withheld for privacy", "privacy service",
               "whoisproxy", "whois proxy", "gdpr masked"):
        if kw in low:
            kw_hits.append(kw)

    if kw_hits:
        evidence.extend(kw_hits[:3])
        # 关键词命中但字段没识别到时，至少标邮箱
        if not matched:
            matched.append("注册信息")

    # 3) 注册商本身是隐私代理
    reg = (parsed.get("registrar") or "").lower()
    reg_privacy = any(k in reg for k in
                      ("privacy", "proxy", "protect", "withheld",
                       "domains by proxy", "identity"))

    enabled = bool(matched or kw_hits or reg_privacy)
    return {
        "enabled": enabled,
        "matched": sorted(set(matched)),
        "evidence": list(dict.fromkeys(evidence))[:5],
        "registrar_privacy": reg_privacy,
    }


def privacy_text(pinfo):
    """生成给人看的隐私保护说明"""
    if not pinfo or not pinfo.get("enabled"):
        return None
    m = pinfo.get("matched") or []
    if m:
        return ("该域名已采取 WHOIS 隐私保护服务（隐藏字段：%s）"
                % "、".join(m))
    return "该域名已采取 WHOIS 隐私保护服务"

