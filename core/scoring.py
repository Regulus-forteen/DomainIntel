# -*- coding: utf-8 -*-
"""
风险评分模块 v2

设计原则（基于真实样本回归）：
1. 「IP 归属」「动态解析」「Cloudflare」「隐私保护」全部降为中性 —— 官方站同样命中，
   没有区分度（实测 typora.io 用 Facebook 段、5 个 IP、CF、注册人 REDACTED）
2. 权重集中在真正有区分度的四项：
   域名年龄、注册当天签证书、域名相似度、注册商性质
3. 引入品牌库 + 相似度算法，取代硬编码关键词
4. 老域名 / 正规注册商 / 品牌官方域名 给负分
5. 输出证据清单，标注强弱，不只给一个数字
"""
import json
import re
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
BRANDS_FILE = HERE / "brands.json"

_cache = {}


def _load():
    if _cache.get("data"):
        return _cache["data"]
    try:
        data = json.loads(BRANDS_FILE.read_text(encoding="utf-8"))
    except Exception:
        data = {"brands": [], "safe_registrars": [], "haven_registrars": [],
                "privacy_placeholder_emails": []}
    _cache["data"] = data
    return data


# ---------------------------------------------------------------- 相似度
EN2CN_LOOKALIKE = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
    "$": "s", "@": "a", "rn": "m", "vv": "w", "cl": "d",
}


def _norm(s):
    s = s.lower()
    for k, v in EN2CN_LOOKALIKE.items():
        s = s.replace(k, v)
    return re.sub(r"[^a-z0-9]", "", s)


def _levenshtein(a, b):
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _domain_root(domain):
    """取域名主体（去掉 www、去掉 TLD）"""
    d = domain.lower().split(":")[0]
    parts = d.split(".")
    for suf in (".com.cn", ".net.cn", ".org.cn", ".gov.cn", ".edu.cn", ".ac.cn"):
        if d.endswith(suf):
            return ".".join(parts[:-3]), suf
    if len(parts) >= 2:
        return ".".join(parts[:-1]), "." + parts[-1]
    return d, ""


def match_brand(domain):
    """
    判断域名是否在仿冒某品牌。
    返回 {'hit': bool, 'brand': str, 'official': [...], 'reason': str, 'is_official': bool}
    """
    data = _load()
    body, _tld = _domain_root(domain)
    body_n = _norm(body)
    # 去掉常见仿冒前后缀后的核心
    core = re.sub(
        r"^(www|pc|app|apps|cn|ch|m|dl|download|client|official|www-dl)[-_]?|[-_]?"
        r"(app|apps|cn|com|download|official|vip|web|client|pc|pro|plus|online|site|\d{1,4})$",
        "", body_n)

    for b in data.get("brands", []):
        name = b.get("name", "")
        aliases = [a.lower() for a in b.get("aliases", [])]
        officials = [o.lower() for o in b.get("official", [])]

        # 是否就是官方域名
        for o in officials:
            od, _ = _domain_root(o)
            if body == od or domain.lower() == o:
                return {"hit": True, "brand": name, "official": officials,
                        "reason": "域名即该品牌官方域名", "is_official": True}

        # 短别名（<4 字符）只在域名核心完全等于别名时才匹配，避免 idm/dism 互误
        short_mode = (len(_norm(aliases[0])) < 4) if aliases else False

        for al in aliases:
            al_n = _norm(al)
            if not al_n or len(al_n) < 3:
                continue
            if len(al_n) < 4:
                # 短别名：只允许「核心完全一致」或「核心以别名+长度<=2结尾」
                if core == al_n:
                    return {"hit": True, "brand": name, "official": officials,
                            "reason": "域名核心与品牌词「%s」完全相同" % al,
                            "is_official": False}
                continue

            # 1) 域名主体完全等于品牌词 —— 视为品牌自有（除非官方列表里没有它，
            #    这种情况按"用了别人品牌名"处理，给一次命中）
            if body_n == al_n:
                return {"hit": True, "brand": name, "official": officials,
                        "reason": "域名主体与品牌词「%s」完全相同" % al,
                        "is_official": False}

            # 2) 域名包含品牌词根，且有多余字符（仿冒典型：品牌+前后缀）
            if al_n in body_n and len(body_n) > len(al_n):
                extra = body_n.replace(al_n, "", 1)
                return {"hit": True, "brand": name, "official": officials,
                        "reason": "域名含品牌词「%s」并附带前后缀「%s」" % (al, extra),
                        "is_official": False}

            # 3) 品牌词根与域名核心是前缀关系（如 deepseekk / deepseeka）
            if core and core != al_n:
                if core.startswith(al_n) and len(core) - len(al_n) <= 4:
                    return {"hit": True, "brand": name, "official": officials,
                            "reason": "域名核心「%s」以品牌词「%s」为前缀（多余 %d 字符）"
                                      % (core, al, len(core) - len(al_n)),
                            "is_official": False}
                if al_n.startswith(core) and len(al_n) - len(core) <= 3:
                    return {"hit": True, "brand": name, "official": officials,
                            "reason": "域名核心「%s」是品牌词「%s」的截断变体"
                                      % (core, al),
                            "is_official": False}

            # 4) 编辑距离 <= 2 且长度接近（错拼变体：nexosmods / nexusmops）
            if abs(len(core) - len(al_n)) <= 2:
                d = _levenshtein(core, al_n)
                if 0 < d <= 2:
                    return {"hit": True, "brand": name, "official": officials,
                            "reason": "域名与品牌「%s」编辑距离 %d（疑似错拼仿冒）" % (al, d),
                            "is_official": False}

            # 5) 品牌词被打散重排（如 nu exo sm ods）
            if len(al_n) >= 5 and core and al_n[:3] in core and al_n[-2:] in core:
                return {"hit": True, "brand": name, "official": officials,
                        "reason": "域名词根与品牌「%s」部分吻合" % al,
                        "is_official": False}

    return {"hit": False}


# ---------------------------------------------------------------- 工具
def _parse_dt(s):
    if not s:
        return None
    s = str(s).strip().replace("Z", "+00:00")
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            continue
    return None


def _reg_hours(reg_time, cert_before):
    """注册时间与证书签发时间的间隔（小时）"""
    a = _parse_dt(reg_time)
    b = _parse_dt(cert_before)
    if not a or not b:
        return None
    return abs((b - a).total_seconds()) / 3600.0


# ---------------------------------------------------------------- 主评分
def score_v2(r):
    """
    返回 {
      'score': int, 'level': str,
      'strong': [(证据, 分值)], 'weak': [证据], 'deduct': [(证据, 分值)]
    }
    """
    w = r.get("whois") or {}
    dns = r.get("dns") or {}
    h = r.get("http_best") or {}
    cert = r.get("cert") or {}
    httpa = (r.get("http") or {}).get("http") or {}
    httpsa = (r.get("http") or {}).get("https") or {}
    data = _load()

    strong, weak, deduct = [], [], []

    # ---------- 硬性排除：域名确实不存在 ----------
    # 注意：注册局查询失败不等于域名不存在。
    # 只有「注册局明确 NXDOMAIN」+「无任何解析」+「页面拿不到」三者同时成立才算失效。
    auth = r.get("auth_check") or {}
    auth_nx = (auth.get("status") == "NXDOMAIN")
    whois_nr = bool(w.get("not_registered"))
    dns_has_a = bool((r.get("dns") or {}).get("A")) or \
        bool((r.get("dns_multi") or {}).get("ip_pool"))
    page_alive = bool(httpa.get("status")) or bool(httpsa.get("status")) or bool(h.get("title"))

    if (auth_nx or whois_nr) and not dns_has_a and not page_alive:
        return {"score": 0, "level": "已失效", "strong": [],
                "weak": ["注册局无记录且无任何解析"], "deduct": []}

    # 注册局查不到但站点活着 —— 记一条提示，继续正常评分
    if (auth_nx or whois_nr) and (dns_has_a or page_alive):
        weak.append("注册局查询无记录，但域名有解析/站点可访问（可能是 WHOIS 限流或延迟）")

    # ---------- 品牌仿冒 ----------
    m = match_brand(r.get("domain", ""))
    if m.get("hit"):
        if m.get("is_official"):
            deduct.append(("域名即品牌官方域名（%s）" % m["brand"], -30))
        else:
            strong.append((m["reason"], 25))

    # ---------- 标题含品牌词但域名不是官方 ----------
    title = (h.get("title") or "")
    if title and not m.get("is_official"):
        body, _ = _domain_root(r.get("domain", ""))
        for b in data.get("brands", []):
            bname = b.get("name", "")
            officials = [o.lower() for o in b.get("official", [])]
            # 官方域名列表里没有当前域名
            is_off = any(body == _domain_root(o)[0] for o in officials)
            if is_off:
                continue
            # 标题里出现品牌名（去掉 + + 等符号后比对）
            tl = _norm(title.replace("+", ""))
            bn = _norm(bname.replace("+", ""))
            if bn and len(bn) >= 3 and bn in tl:
                strong.append(("页面标题含品牌名「%s」但域名非该品牌官方"
                               % bname, 25))
                break

    # ---------- 域名年龄 ----------
    reg_time = w.get("reg_time")
    age_days = None
    dt = _parse_dt(reg_time)
    if dt:
        age_days = (datetime.now(timezone.utc) - dt).days
        if age_days < 0:
            age_days = 0
        if age_days <= 30:
            strong.append(("域名注册仅 %d 天" % age_days, 30))
        elif age_days <= 90:
            strong.append(("域名注册 %d 天（较新）" % age_days, 15))
        elif age_days >= 365 * 5:
            deduct.append(("域名已存在 %d 年（老域名）" % (age_days // 365), -20))

    # ---------- 注册当天即签证书 ----------
    gap = _reg_hours(reg_time, cert.get("not_before"))
    if gap is not None:
        if gap <= 24:
            strong.append(("域名注册后 %.1f 小时内即签发证书（自动化建站特征）" % gap, 25))
        elif gap <= 72:
            strong.append(("域名注册后 %.0f 小时内签发证书" % gap, 12))

    # ---------- 注册商性质 ----------
    registrar = (w.get("registrar") or "")
    for hz in data.get("haven_registrars", []):
        if hz.lower() in registrar.lower():
            has_privacy = not w.get("registrant")
            strong.append(("注册商为 %s%s" % (registrar[:32],
                                             "（配合隐私保护）" if has_privacy else ""), 15))
            break
    for sf in data.get("safe_registrars", []):
        if sf.lower() in registrar.lower():
            deduct.append(("注册商为正规企业级服务商 %s" % registrar[:32], -10))
            break

    # ---------- VirusTotal 报毒：最强硬证据 ----------
    pa = r.get("payload_analysis") or []
    vt_mal = 0
    vt_total = 0
    vt_label = ""
    vt_files = 0
    for x in pa:
        v = x.get("vt") or {}
        st = v.get("stats") or {}
        m = st.get("malicious", 0)
        if m > 0:
            vt_files += 1
            if m > vt_mal:
                vt_mal = m
                vt_total = st.get("total", 0)
                vt_label = v.get("label") or ""
    if vt_mal > 0:
        strong.append(("分发的样本经 VirusTotal 检测 %d/%d 引擎报毒%s（%d 个文件）"
                       % (vt_mal, vt_total,
                          "，威胁类型 " + vt_label if vt_label else "",
                          vt_files), 50))

    # ---------- 页面载荷（四层判定）----------
    ps = h.get("payload_strong") or []       # 外站 + 可执行：最强
    pw = h.get("payload_weak") or []         # 本站 + 可执行
    pdeep = h.get("payload_deep") or []      # 二层抓到的
    dpage = h.get("download_pages") or []    # 下载页（不算载荷）
    lure = h.get("lure_words") or []
    bks = h.get("buckets") or []

    if ps:
        strong.append(("页面指向外部站点的可执行文件 %d 个（载荷分离部署）"
                       % len(ps), 35))
        if any(re.search(r"(oss|tos|cos|kodo)[a-z0-9\-]*\.(aliyuncs|volces|myqcloud)",
                         x, re.I) for x in ps):
            strong.append(("载荷直链位于对象存储桶（规避审核）", 20))
    elif pdeep:
        strong.append(("下载页内指向可执行文件 %d 个" % len(pdeep), 30))
    elif pw:
        strong.append(("页面存在站内可执行文件链接 %d 个" % len(pw), 15))

    if bks:
        strong.append(("页面引用对象存储桶 %s" % bks[0][:40], 25))

    # 网盘分发（黑产常用，绕过域名封禁）
    netdisks = h.get("netdisks") or []
    if netdisks:
        names = sorted({x.get("netdisk", "") for x in netdisks})
        strong.append(("页面引导至网盘下载（%s，共 %d 条）"
                       % ("、".join(names), len(netdisks)), 25))

    # 跳转网关
    gws = h.get("gateways") or []
    decoded = [g for g in gws if g.get("target")]
    if decoded:
        strong.append(("使用跳转网关分发（%d 条，含编码目标地址）" % len(decoded), 20))
    elif gws:
        strong.append(("页面存在跳转统计链接 %d 条" % len(gws), 10))

    # 有下载页但没拿到载荷 -> 说明有分发意图，给少量分
    if dpage and not (ps or pdeep or pw or netdisks):
        strong.append(("页面存在下载页入口 %d 个（未取到载荷）" % len(dpage), 8))

    # 诱导下载文案（需与下载行为同时出现才计分）
    if lure and (ps or pw or pdeep or dpage or netdisks):
        strong.append(("页面含诱导下载文案：%s" % "、".join(lure[:4]), 10))

    # JS 内嵌下载路径（按钮 onclick 里藏的可执行文件）
    jsdl = h.get("js_downloads") or []
    if jsdl and not (ps or pw or pdeep):
        strong.append(("下载按钮通过 JS 调用触发（%s）"
                       % (jsdl[0].split("/")[-1][:32]), 20))

    # 可疑外链域名（高风险 TLD + 随机串）
    sus_hosts = h.get("suspicious_hosts") or []
    if sus_hosts:
        strong.append(("页面引用可疑域名 %s（随机串 + 高风险后缀）"
                       % sus_hosts[0][:36], 20))

    # 引用品牌真官网伪装可信度
    refs = h.get("refs_official") or []
    if refs and not m.get("is_official"):
        b0 = refs[0]
        strong.append(("页面引用「%s」的真正官网 %s 以伪装可信度"
                       % (b0.get("brand"), b0.get("host")), 15))

    # ---------- 页面体积（克隆站特征，需与新注册域名联动，避免误伤官方老站） ----------
    size = h.get("len") or 0
    if size >= 300000 and age_days is not None and age_days <= 180:
        strong.append(("页面体积 %d KB 且域名仅注册 %d 天（整站克隆特征）"
                       % (size // 1024, age_days), 15))

    # ---------- 伪造备案 ----------
    html = (h.get("html") or "")
    if re.search(r"(京|沪|粤|蜀|浙|苏|闽|鲁|豫|鄂|湘)ICP备", html):
        # 有备案号但域名不在备案体系内的，视为可疑
        strong.append(("页面含 ICP 备案号（需核验真伪）", 10))

    # ---------- HTTP 完全不可达 ----------
    if httpa.get("error") and httpsa.get("error"):
        weak.append("HTTP/HTTPS 均不可达")

    # ---------- 中性（仅展示） ----------
    multi = r.get("dns_multi") or {}
    if multi.get("dynamic"):
        weak.append("DNS 动态解析 %d 个 IP（中性，CDN 亦然）" % multi.get("distinct_ip_count", 0))
    if "cloudflare" in (h.get("server") or "").lower():
        weak.append("使用 Cloudflare（中性）")
    if w.get("registrar") and not w.get("registrant"):
        weak.append("注册人信息未公开（中性，官方站常见）")
    tld = r.get("domain", "").rsplit(".", 1)[-1].lower()
    if tld in ("top", "xyz", "cyou", "icu", "buzz", "click", "shop", "vip", "work", "loan"):
        weak.append("使用高风险后缀 .%s" % tld)

    # ---------- 汇总 ----------
    total = sum(v for _, v in strong) + sum(v for _, v in deduct)
    total = max(0, min(100, total))

    if total >= 70:
        level = "高危"
    elif total >= 45:
        level = "可疑"
    elif total >= 20:
        level = "低危"
    else:
        level = "正常"

    out = {"score": total, "level": level,
           "strong": strong, "weak": weak, "deduct": deduct}
    if age_days is not None:
        out["age_days"] = age_days
    return out