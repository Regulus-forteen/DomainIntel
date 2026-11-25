# -*- coding: utf-8 -*-
"""
abuse 举报模块
- 从 WHOIS 提取/推导注册商 abuse 邮箱
- 按注册商分组
- 生成举报邮件草稿
- 审核后批量发送
"""
import json
import re
import time
import random
import smtplib
import datetime
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from email.utils import formataddr

BASE_DIR = Path(__file__).resolve().parents[1]
DRAFT_DIR = BASE_DIR / "output" / "abuse_drafts"
DRAFT_DIR.mkdir(parents=True, exist_ok=True)

from . import settings


# ---------------------------------------------------------------- abuse 邮箱
# 已知注册商 -> abuse 邮箱（手工维护，命中优先）
KNOWN_ABUSE = {
    "key-systems": "abuse@key-systems.net",
    "web commerce communications": "abuse@webnic.cc",
    "rumahweb": "abuse@rumahweb.com",
    "namecheap": "abuse@namecheap.com",
    "godaddy": "abuse@godaddy.com",
    "namesilo": "abuse@namesilo.com",
    "gandi": "abuse@gandi.net",
    "tucows": "abuse@tucows.com",
    "pdr ltd": "abuse@publicdomainregistry.com",
    "dynadot": "abuse@dynadot.com",
    "porkbun": "abuse@porkbun.com",
    "sav.com": "abuse@sav.com",
    "networksolutions": "abuse@web.com",
    "dondominio": "abuse@dondominio.com",
    "gname": "abuse@gname.com",
    "alibaba": "domainabuse@service.aliyun.com",
    "hiChina".lower(): "domainabuse@service.aliyun.com",
    "xin net": "abuse@xinnet.com",
    "新网": "abuse@xinnet.com",
    "west.cn": "abuse@west.cn",
    "西部数码": "abuse@west.cn",
    "ename": "abuse@ename.com",
    "易名": "abuse@ename.com",
    "22.cn": "abuse@22.cn",
    "中誉智科": "abuse@gyzhike.com",
    "万商云集": "abuse@wanshangyunji.com",
    "domin": "abuse@dominethk.com",
    "csc corporate": "abuse@cscglobal.com",
    "markmonitor": "abuse@markmonitor.com",
    "realtime register": "abuse@realtimeregister.com",
    "hostinger": "abuse@hostinger.com",
    "hosting concepts": "abuse@openprovider.com",
    "edoms": "abuse@edoms.com",
}

# IANA 注册商域名映射（用于拼接 abuse@<domain>）
REGISTRAR_DOMAIN = {
    "key-systems": "key-systems.net",
    "web commerce communications": "webnic.cc",
    "rumahweb": "rumahweb.com",
    "namecheap": "namecheap.com",
    "godaddy": "godaddy.com",
    "namesilo": "namesilo.com",
    "gandi": "gandi.net",
    "tucows": "tucows.com",
}


def abuse_email_of(whois):
    """
    从 WHOIS 结构推导 abuse 邮箱，返回 (email, 来源说明)
    """
    if not whois:
        return None, "无 WHOIS 数据"

    # 1. WHOIS 里直接有 abuse 邮箱字段
    for key in ("abuse_email", "abuse_contact", "abuse"):
        v = whois.get(key)
        if v and "@" in str(v):
            return str(v).split()[0], "WHOIS 字段"

    registrar = (whois.get("registrar") or "").strip()
    if not registrar:
        return None, "无注册商信息"

    low = registrar.lower()

    # 2. 已知表命中
    for k, v in KNOWN_ABUSE.items():
        if k in low:
            return v, "已知映射（%s）" % registrar[:24]

    # 3. 从注册商域名拼接
    for k, dom in REGISTRAR_DOMAIN.items():
        if k in low:
            return "abuse@" + dom, "域名推导"

    # 4. 注册商名里带域名
    m = re.search(r"([a-z0-9\-]+\.(?:com|net|org|cn|cc|io))", low)
    if m:
        return "abuse@" + m.group(1), "名称推导"

    return None, "未能确定 abuse 邮箱（注册商：%s）" % registrar[:30]


# ---------------------------------------------------------------- 证据整理
def build_evidence(r):
    """把一个探测结果整理成证据链条目"""
    w = r.get("whois") or {}
    h = r.get("http_best") or {}
    cert = r.get("cert") or {}
    risk = r.get("risk") or {}
    dns = r.get("dns") or {}
    rel = r.get("rel") or {}

    ev = []
    # 仿冒
    brand_hit = [t for t, v in (risk.get("strong") or []) if "品牌" in t]
    if brand_hit:
        ev.append(("仿冒侵权", brand_hit[0]))

    # 载荷
    dls = h.get("download_links") or []
    if dls:
        ev.append(("分发恶意载荷", "页面存在可执行文件下载链接：%s" % dls[0]))
    if h.get("buckets"):
        ev.append(("载荷托管", "引用对象存储桶：%s" % h["buckets"][0]))

    # 网盘分发
    nds = h.get("netdisks") or []
    if nds:
        parts = ["[%s] %s" % (n.get("netdisk", ""), n["url"]) for n in nds[:4]]
        ev.append(("网盘分发", "该站将下载引导至网盘：%s" % "；".join(parts)))

    # 跳转网关
    gws = h.get("gateways") or []
    if gws:
        dec = [g for g in gws if g.get("target")]
        if dec:
            ev.append(("跳转网关", "通过 %s 跳转分发，编码目标可解码：%s"
                       % (dec[0]["url"].split("/")[2] if "://" in dec[0]["url"] else "-",
                          dec[0]["target"])))
        else:
            ev.append(("跳转预警", "页面存在跳转统计链接 %d 条" % len(gws)))

    # VT 检测结果（最硬的证据）
    pa = r.get("payload_analysis") or []
    for i, x in enumerate(pa[:3], 1):
        v = x.get("vt") or {}
        st = v.get("stats") or {}
        if v.get("found") and st.get("malicious", 0) > 0:
            ev.append((
                "恶意软件实锤（VirusTotal）",
                "该站分发的文件「%s」（SHA256: %s...）经 VirusTotal 多引擎检测，"
                "%d/%d 引擎判定为恶意，威胁类型：%s"
                % ((x.get("filename") or "-")[:40],
                   (x.get("sha256") or "")[:16],
                   st.get("malicious", 0), st.get("total", 0),
                   v.get("label") or "未知")))

    # 引用真官网
    refs = h.get("refs_official") or []
    if refs:
        r0 = refs[0]
        ev.append(("伪装可信度", "页面引用「%s」的真正官网 %s，以冒充官方"
                   % (r0.get("brand"), r0.get("host"))))

    # 克隆
    size = h.get("len") or 0
    if size >= 300000:
        ev.append(("整站克隆", "页面体积 %d KB，与目标站高度一致" % (size // 1024)))

    # 同源
    if rel.get("md5_group"):
        ev.append(("同源域名", "页面与 %s 完全一致（同一套模板）"
                   % ", ".join(rel["md5_group"][:5])))
    if rel.get("email_group"):
        ev.append(("同主体", "与 %s 共用注册邮箱" % ", ".join(rel["email_group"][:5])))

    # 自动化建站
    auto = [t for t, v in (risk.get("strong") or []) if "签发证书" in t]
    if auto:
        ev.append(("自动化建站", auto[0]))

    # 注册信息
    reg_info = []
    if w.get("registrant"):
        reg_info.append("注册人：%s" % w["registrant"])
    if w.get("email"):
        reg_info.append("注册邮箱：%s" % w["email"])
    if w.get("reg_time"):
        reg_info.append("注册时间：%s" % str(w["reg_time"])[:19])
    if dns.get("A"):
        reg_info.append("解析 IP：%s" % ", ".join(dns["A"][:3]))
    if cert.get("issuer_org"):
        reg_info.append("证书签发：%s" % cert["issuer_org"])
    if reg_info:
        ev.append(("注册与解析信息", "；".join(reg_info)))

    return ev


# ---------------------------------------------------------------- 邮件生成
SUBJECT_TPL = "举报：{domain} 仿冒 {brand} 并分发恶意载荷"

BODY_TPL = """{registrar} 安全团队：

您好。

我方在网络安全监测中发现，贵司管理的域名 {domain} 存在以下违规行为，特此举报。

{evidence_block}

域名基本信息：
  域名        : {domain}
  注册商      : {registrar}
  注册时间    : {reg_time}
  到期时间    : {exp_time}
  当前解析 IP : {ips}
  页面标题    : {title}

我方已对上述页面进行取证，相关证据（页面快照、Whois 记录、HTTP 响应）可随时提供。

请求贵司依据注册服务条款及 ICANN 相关规定，对该域名采取以下措施：
  1. 暂停域名解析；
  2. 或联系注册人要求其整改。

如需进一步信息，请通过下方邮箱联系。

此致

{reporter}
邮箱：{reporter_email}
日期：{date}
"""

def _reporter():
    r = settings.get("reporter") or {}
    return (r.get("name") or "（未设置）", r.get("email") or "（未设置）")

REPORTER, REPORTER_EMAIL = _reporter()


def render_mail(r, group_domains=None):
    """为一个域名或一组域名渲染邮件"""
    risk = r.get("risk") or {}
    w = r.get("whois") or {}
    h = r.get("http_best") or {}
    dns = r.get("dns") or {}
    ev = build_evidence(r)

    evidence_block = []
    for i, (kind, detail) in enumerate(ev, 1):
        evidence_block.append("%d. %s\n   %s" % (i, kind, detail))
    evidence_block = "\n\n".join(evidence_block) if evidence_block else "（无可用证据）"

    # 直接用品牌库匹配拿品牌名（比正则可靠）
    brand = ""
    try:
        from .scoring import match_brand
        mb = match_brand(r.get("domain", ""))
        if mb.get("hit") and mb.get("brand"):
            brand = mb["brand"]
    except Exception:
        pass
    if not brand:
        # 兜底：标题里提到 Dism++ 这类，取标题首个连续英文/中文品牌词
        title = (r.get("http_best") or {}).get("title") or ""
        m = re.match(r"\s*([A-Za-z][A-Za-z0-9\+\-\.]{1,20})", title)
        brand = m.group(1) if m else "相关品牌"

    body = BODY_TPL.format(
        registrar=(w.get("registrar") or "未知注册商")[:60],
        domain=r["domain"],
        evidence_block=evidence_block,
        reg_time=str(w.get("reg_time") or "-")[:19],
        exp_time=str(w.get("exp_time") or "-")[:19],
        ips=", ".join(dns.get("A", [])[:3]) or "-",
        title=(h.get("title") or "-")[:60],
        reporter=REPORTER,
        reporter_email=REPORTER_EMAIL,
        date=datetime.date.today().isoformat(),
    )
    subject = SUBJECT_TPL.format(domain=r["domain"], brand=brand)
    return subject, body


def group_by_registrar(results):
    """按注册商分组，返回 {registrar: [result, ...]}"""
    from collections import defaultdict
    g = defaultdict(list)
    for r in results:
        risk = r.get("risk") or {}
        # 只处理高危/可疑
        if risk.get("level") not in ("高危", "可疑"):
            continue
        registrar = (r.get("whois") or {}).get("registrar") or "未知注册商"
        g[registrar].append(r)
    return g


def generate_drafts(results, stamp=None):
    """
    生成邮件草稿，返回 [{registrar, abuse_email, source, subject, body, domains, file}]
    """
    stamp = stamp or datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = DRAFT_DIR / stamp
    out_dir.mkdir(parents=True, exist_ok=True)

    groups = group_by_registrar(results)
    drafts = []

    for registrar, items in groups.items():
        w0 = items[0].get("whois") or {}
        email, source = abuse_email_of(w0)

        if len(items) == 1:
            subject, body = render_mail(items[0])
            # 多域名时标题合并
        else:
            subject, body = render_mail(items[0])
            subject = "举报：%s 等 %d 个域名涉嫌仿冒并分发恶意软件" % (
                items[0]["domain"], len(items))
            # 逐个追加证据
            extra = []
            for r2 in items[1:]:
                extra.append("\n" + "=" * 60 + "\n")
                ev2 = build_evidence(r2)
                extra.append("域名 %s 的独立证据：" % r2["domain"])
                for i, (k, d) in enumerate(ev2, 1):
                    extra.append("  %d. %s：%s" % (i, k, d))
            body = body + "\n" + "\n".join(extra) + "\n"

        safe = re.sub(r"[^A-Za-z0-9]+", "_", registrar)[:40]
        fn = out_dir / ("%s.txt" % safe)
        content = (
            "收件人: %s\n" % (email or "【未找到】")
            + "邮箱来源: %s\n" % source
            + "注册商: %s\n" % registrar
            + "涉及域名(%d): %s\n" % (len(items), ", ".join(x["domain"] for x in items))
            + "=" * 70 + "\n"
            + "主题: %s\n" % subject
            + "=" * 70 + "\n\n"
            + body
        )
        fn.write_text(content, encoding="utf-8")

        drafts.append({
            "registrar": registrar,
            "abuse_email": email,
            "source": source,
            "subject": subject,
            "body": body,
            "domains": [x["domain"] for x in items],
            "file": str(fn),
        })

    return drafts, str(out_dir)


# ---------------------------------------------------------------- 发送
def load_mail_config():
    """读取邮件配置（统一走 settings）"""
    m = settings.get("mail") or {}
    if not m.get("sender_addr") or not m.get("password"):
        return None
    return {
        "smtp_server": m.get("smtp_server") or "smtp.163.com",
        "smtp_port": int(m.get("smtp_port") or 465),
        "sender_addr": m.get("sender_addr"),
        "password": m.get("password"),
    }


def send_one(cfg, to, subject, body, timeout=30):
    """发送单封邮件，返回 (ok, msg)"""
    try:
        msg = MIMEMultipart()
        msg["From"] = formataddr((str(Header("R-claw 安全通报", "utf-8")),
                                  cfg["sender_addr"]))
        msg["To"] = to
        msg["Subject"] = Header(subject, "utf-8")
        msg.attach(MIMEText(body, "plain", "utf-8"))

        server = smtplib.SMTP_SSL(cfg["smtp_server"], cfg.get("smtp_port", 465),
                                  timeout=timeout)
        server.login(cfg["sender_addr"], cfg["password"])
        server.sendmail(cfg["sender_addr"], [to], msg.as_string())
        server.quit()
        return True, "成功"
    except Exception as e:
        return False, "%s: %s" % (type(e).__name__, str(e)[:100])


def send_drafts(drafts, interval=25, progress_cb=None, log_path=None):
    """
    批量发送草稿
    interval: 每封间隔秒数（含随机抖动）
    """
    cfg = load_mail_config()
    if not cfg:
        return [], "未找到邮件配置（mail_config.json）"

    results = []
    for i, d in enumerate(drafts):
        to = d.get("abuse_email")
        if not to:
            results.append({"registrar": d["registrar"], "to": None,
                            "ok": False, "msg": "无 abuse 邮箱，跳过"})
            continue
        if progress_cb:
            progress_cb(i, len(drafts), d["registrar"], to)

        ok, msg = send_one(cfg, to, d["subject"], d["body"])
        results.append({"registrar": d["registrar"], "to": to,
                        "ok": ok, "msg": msg,
                        "time": datetime.datetime.now().isoformat(timespec="seconds")})

        if i < len(drafts) - 1:
            time.sleep(interval + random.uniform(0, 8))

    if log_path:
        try:
            lines = ["注册商,收件人,结果,说明,时间"]
            for x in results:
                lines.append("%s,%s,%s,%s,%s" % (
                    x["registrar"], x.get("to") or "", "成功" if x["ok"] else "失败",
                    x["msg"].replace(",", "，"), x.get("time") or ""))
            Path(log_path).write_text("\n".join(lines), encoding="utf-8-sig")
        except Exception:
            pass

    return results, None