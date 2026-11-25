# -*- coding: utf-8 -*-
"""
Word 报告生成

优先使用 office_tool 的样式化构建器（若可用），
否则回退到内置的简易实现，保证脱离外部工具也能跑。
"""
import datetime
from pathlib import Path

import docx
from docx.shared import Pt, Cm, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

_office_tool = None


def _try_office_tool():
    """尝试加载外部 office_tool（可选依赖）"""
    global _office_tool
    if _office_tool is not None:
        return _office_tool
    import sys
    # 常见位置：与本项目同级的 work-tool/tools/office-reader
    for base in Path(__file__).resolve().parents:
        cand = base / "work-tool" / "tools" / "office-reader"
        if (cand / "office_tool.py").exists():
            if str(cand) not in sys.path:
                sys.path.insert(0, str(cand))
            try:
                import office_tool
                _office_tool = office_tool
                return _office_tool
            except Exception:
                pass
    _office_tool = False
    return _office_tool


LEVEL_COLOR = {"高危": "CC0000", "可疑": "FF6600", "低危": "997700",
               "正常": "008800", "已失效": "666666", "未注册": "666666",
               "探测失败": "666666"}


def _P(text, style=None, font="宋体", size=None, bold=None, color=None, align=None):
    o = {"type": "paragraph", "text": str(text), "font": font}
    if style:
        o["style"] = style
    if size:
        o["size"] = size
    if bold is not None:
        o["bold"] = bold
    if color:
        o["color"] = color
    if align:
        o["align"] = align
    return o


def _C(v, bold=False, size=8):
    o = {"text": str(v), "font": "宋体", "size": size}
    if bold:
        o["bold"] = True
        o["font"] = "黑体"
    return o


def _T(header, rows, size=8):
    data = [[_C(x, True, size=size) for x in header]]
    for r in rows:
        data.append([_C(x, size=size) for x in r])
    return {"type": "table", "data": data}


# ---------------- 内置构建器（office_tool 不可用时） ----------------
def _add_para(doc, item):
    p = doc.add_paragraph()
    text = item.get("text", "")
    run = p.add_run(text)
    style = item.get("style")
    if style == "Title":
        run.font.size = Pt(22)
        run.bold = True
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    elif style and style.startswith("Heading"):
        lvl = int(style.split()[-1]) if style.split()[-1].isdigit() else 1
        run.font.size = Pt({1: 16, 2: 13, 3: 11}.get(lvl, 11))
        run.bold = True
    else:
        run.font.size = Pt(item.get("size") or 10)
        if item.get("bold"):
            run.bold = True
    run.font.name = item.get("font") or "宋体"
    try:
        run._element.rPr.rFonts.set(qn("w:eastAsia"), item.get("font") or "宋体")
    except Exception:
        pass
    color = item.get("color")
    if color:
        try:
            run.font.color.rgb = RGBColor.from_string(color)
        except Exception:
            pass
    if item.get("align") == "center":
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    elif item.get("align") == "right":
        p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    return p


def _add_table(doc, data):
    if not data:
        return
    ncol = max(len(r) for r in data)
    t = doc.add_table(rows=len(data), cols=ncol)
    t.style = "Table Grid"
    for ri, row in enumerate(data):
        for ci, cell in enumerate(row):
            if ci >= ncol:
                continue
            c = t.cell(ri, ci)
            text = cell.get("text", "") if isinstance(cell, dict) else str(cell)
            c.text = text
            for p in c.paragraphs:
                for run in p.runs:
                    run.font.size = Pt(8)
                    if ri == 0:
                        run.bold = True
    return t


def _build_fallback(content):
    doc = docx.Document()
    for item in content:
        if item.get("type") == "table":
            _add_table(doc, item.get("data", []))
        else:
            _add_para(doc, item)
    # 页面设置
    for sec in doc.sections:
        sec.page_width = Cm(21.0)
        sec.page_height = Cm(29.7)
        sec.left_margin = Cm(1.8)
        sec.right_margin = Cm(1.8)
        sec.top_margin = Cm(2.0)
        sec.bottom_margin = Cm(1.8)
    return doc


# ---------------- 样式美化 ----------------
def _force_fonts(doc):
    """
    给文档里所有 run 补上显式字体（含东亚字体），
    避免 Word 打开时因为缺少 rFonts 而回退到默认字体。
    """
    def _apply(run, name="宋体"):
        try:
            run.font.name = name
            rPr = run._element.get_or_add_rPr()
            rFonts = rPr.find(qn("w:rFonts"))
            if rFonts is None:
                rFonts = OxmlElement("w:rFonts")
                rPr.append(rFonts)
            rFonts.set(qn("w:ascii"), name)
            rFonts.set(qn("w:hAnsi"), name)
            rFonts.set(qn("w:eastAsia"), name)
            rFonts.set(qn("w:cs"), name)
        except Exception:
            pass

    # 正文段落
    for p in doc.paragraphs:
        style_font = "宋体"
        try:
            if p.style is not None:
                nm = p.style.name or ""
                if nm == "Title":
                    style_font = "黑体"
                elif nm.startswith("Heading"):
                    style_font = "黑体"
        except Exception:
            pass
        # 段落没有 run 时补一个空 run，保证字体设置生效
        if not p.runs:
            try:
                p.add_run("")
            except Exception:
                pass
        for r in p.runs:
            fname = r.font.name or style_font
            _apply(r, fname)

    # 表格
    for t in doc.tables:
        for row in t.rows:
            for cell in row.cells:
                for p in cell.paragraphs:
                    if not p.runs:
                        try:
                            p.add_run("")
                        except Exception:
                            pass
                    for r in p.runs:
                        _apply(r, r.font.name or "宋体")

    # 页眉页脚
    for sec in doc.sections:
        for part in (sec.header, sec.footer):
            try:
                for p in part.paragraphs:
                    for r in p.runs:
                        _apply(r, r.font.name or "宋体")
            except Exception:
                pass


def _set_normal_style(doc):
    """把 Normal 样式默认字体也改成宋体，兜底"""
    try:
        st = doc.styles["Normal"]
        st.font.name = "宋体"
        rPr = st.element.get_or_add_rPr()
        rFonts = rPr.find(qn("w:rFonts"))
        if rFonts is None:
            rFonts = OxmlElement("w:rFonts")
            rPr.append(rFonts)
        for attr in ("w:ascii", "w:hAnsi", "w:eastAsia", "w:cs"):
            rFonts.set(qn(attr), "宋体")
    except Exception:
        pass


def _border_shade(doc):
    for t in doc.tables:
        t.style = "Table Grid"
        t.autofit = True
        for ri, row in enumerate(t.rows):
            for cell in row.cells:
                tcPr = cell._tc.get_or_add_tcPr()
                b = OxmlElement("w:tcBorders")
                for e in ("top", "left", "bottom", "right"):
                    el = OxmlElement("w:%s" % e)
                    el.set(qn("w:val"), "single")
                    el.set(qn("w:sz"), "4")
                    el.set(qn("w:color"), "999999")
                    b.append(el)
                tcPr.append(b)
                if ri == 0:
                    s = OxmlElement("w:shd")
                    s.set(qn("w:val"), "clear")
                    s.set(qn("w:fill"), "D9E2F3")
                    tcPr.append(s)
                for p in cell.paragraphs:
                    p.paragraph_format.space_before = Pt(1)
                    p.paragraph_format.space_after = Pt(1)
                    for rr in p.runs:
                        rr.font.size = Pt(8)


def _setup_page(doc, header_text=""):
    for sec in doc.sections:
        sec.page_width = Cm(21.0)
        sec.page_height = Cm(29.7)
        sec.left_margin = Cm(1.8)
        sec.right_margin = Cm(1.8)
        sec.top_margin = Cm(2.0)
        sec.bottom_margin = Cm(1.8)
        fp = sec.footer.paragraphs[0] if sec.footer.paragraphs else sec.footer.add_paragraph()
        fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = fp.add_run()
        fld = OxmlElement("w:fldSimple")
        fld.set(qn("w:instr"), "PAGE")
        run._r.addnext(fld)
        for rr in fp.runs:
            rr.font.size = Pt(8)
        if header_text:
            hp = sec.header.paragraphs[0] if sec.header.paragraphs else sec.header.add_paragraph()
            hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
            hr = hp.add_run(header_text)
            hr.font.size = Pt(8)
            hr.font.color.rgb = RGBColor(0x99, 0x99, 0x99)


def _line_spacing(doc):
    for p in doc.paragraphs:
        if p.style.name.startswith("Heading") or p.style.name == "Title":
            continue
        p.paragraph_format.line_spacing = 1.3
        p.paragraph_format.space_after = Pt(3)


# ---------------- 主入口 ----------------
def build_docx(results, stats, out_path, title="域名情报采集报告"):
    now = datetime.datetime.now()
    C = []

    C.append(_P(title, style="Title", font="黑体", size=24, align="center"))
    C.append(_P("", font="宋体"))
    C.append(_P("Domain Intelligence Report", font="黑体", size=12,
                align="center", color="0066CC"))
    C.append(_P("", font="宋体"))
    C.append(_P("生成时间：%s" % now.strftime("%Y-%m-%d %H:%M"),
                font="仿宋", size=12, align="center"))
    C.append(_P("样本数量：%d 个域名" % stats.get("total", len(results)),
                font="仿宋", size=12, align="center"))
    C.append(_P("采集维度：DNS / 权威验证 / WHOIS / HTTP / TLS 证书 / IP 情报 / 载荷",
                font="仿宋", size=11, align="center"))
    C.append(_P("", font="宋体"))
    C.append(_P("本报告数据来自公开 DNS、WHOIS、HTTP 与证书信息，"
                "为被动与轻量主动探测，未对目标系统进行任何漏洞利用或暴力破解。",
                font="楷体", size=9, align="center", color="666666"))

    # 一、概览
    C.append(_P("一、总体概览", style="Heading 1", font="黑体"))
    lv = stats.get("by_level", {})
    C.append(_T(["指标", "数值"], [
        ["域名总数", stats.get("total", len(results))],
        ["DNS 有解析", stats.get("alive", 0)],
        ["动态解析（IP 轮换）", stats.get("dynamic", 0)],
        ["存在下载链接", stats.get("with_payload", 0)],
        ["高危", lv.get("高危", 0)],
        ["可疑", lv.get("可疑", 0)],
        ["低危", lv.get("低危", 0)],
        ["正常", lv.get("正常", 0)],
        ["已失效/未注册", lv.get("已失效", 0) + lv.get("未注册", 0)],
        ["总耗时（秒）", stats.get("elapsed", "-")],
    ]))

    # 二、风险清单
    C.append(_P("二、风险分级清单", style="Heading 1", font="黑体"))
    C.append(_P("按风险评分降序排列，评分依据见每个域名后的说明。",
                font="宋体", size=10))
    rows = []
    for r in sorted(results, key=lambda x: -(x.get("risk") or {}).get("score", 0)):
        risk = r.get("risk") or {}
        w = r.get("whois") or {}
        h = r.get("http_best") or {}
        ips = ",".join((r.get("dns") or {}).get("A", [])[:2]) or "-"
        rows.append([
            risk.get("score", 0), risk.get("level", "-"), r["domain"], ips,
            (w.get("registrant") or "-")[:8],
            (w.get("registrar") or "-")[:14],
            (h.get("title") or "-")[:24],
        ])
    C.append(_T(["评分", "等级", "域名", "解析 IP", "注册人", "注册商", "页面标题"], rows))

    # 三、高危详情
    high = [r for r in results
            if (r.get("risk") or {}).get("level") in ("高危", "可疑")]
    if high:
        C.append(_P("三、高危域名详情", style="Heading 1", font="黑体"))
        for i, r in enumerate(sorted(high, key=lambda x: -(x["risk"].get("score") or 0)), 1):
            risk = r["risk"]
            w = r.get("whois") or {}
            h = r.get("http_best") or {}
            cert = r.get("cert") or {}
            dns = r.get("dns") or {}
            multi = r.get("dns_multi") or {}
            auth = r.get("auth_check") or {}

            C.append(_P("%d. %s　[%s / %d 分]" % (i, r["domain"], risk.get("level"),
                                                risk.get("score")),
                        style="Heading 2", font="黑体"))

            C.append(_P("判定依据", font="黑体", size=10, bold=True))
            for reason in risk.get("reasons", []):
                C.append(_P("· " + reason, font="宋体", size=10))

            C.append(_P("基础信息", font="黑体", size=10, bold=True))
            C.append(_T(["字段", "值"], [
                ["注册局状态", auth.get("status", "-")],
                ["注册人", w.get("registrant") or "-"],
                ["注册邮箱", w.get("email") or "-"],
                ["注册商", w.get("registrar") or "-"],
                ["注册时间", str(w.get("reg_time") or "-")[:19]],
                ["到期时间", str(w.get("exp_time") or "-")[:19]],
                ["域名状态", ", ".join(w.get("status") or []) or "-"],
                ["NS", ", ".join(w.get("ns") or dns.get("NS") or []) or "-"],
                ["域名年龄", ("%d 天" % r["age_days"])
                 if r.get("age_days") is not None else "-"],
            ]))

            C.append(_P("解析情况", font="黑体", size=10, bold=True))
            dns_rows = [["A 记录", ", ".join(dns.get("A") or []) or "-"],
                        ["AAAA", ", ".join(dns.get("AAAA") or []) or "-"],
                        ["CNAME", ", ".join(dns.get("CNAME") or []) or "-"],
                        ["MX", ", ".join(dns.get("MX") or []) or "-"]]
            if multi:
                dns_rows.append(["动态调度", "是（%d 个 IP 轮换）"
                                 % multi.get("distinct_ip_count", 0)
                                 if multi.get("dynamic") else "否（单一 IP）"])
            C.append(_T(["类型", "记录"], dns_rows))

            if r.get("ip_infos"):
                C.append(_P("IP 情报", font="黑体", size=10, bold=True))
                ip_rows = []
                for ii in r["ip_infos"]:
                    ip_rows.append([
                        ii.get("ip", ""), ii.get("asn", "") or "-",
                        ((ii.get("as_name") or "")[:24]) or "-",
                        "%s %s" % (ii.get("country", ""), ii.get("city", "")),
                        ", ".join(str(p) for p in (ii.get("open_ports") or [])) or "-",
                    ])
                C.append(_T(["IP", "ASN", "归属组织", "位置", "开放端口"], ip_rows))

            if h:
                C.append(_P("站点信息", font="黑体", size=10, bold=True))
                C.append(_T(["字段", "值"], [
                    ["HTTP 状态", "%s / %s" % (
                        (r.get("http", {}).get("http", {}) or {}).get("status", "-"),
                        (r.get("http", {}).get("https", {}) or {}).get("status", "-"))],
                    ["页面标题", (h.get("title") or "-")[:60]],
                    ["Server", h.get("server") or "-"],
                    ["页面大小", h.get("len") or "-"],
                    ["Body MD5", (h.get("body_md5") or "-")[:16]],
                    ["favicon hash", str(h.get("favicon_hash") or "-")],
                ]))

                if h.get("download_links"):
                    C.append(_P("★ 直链载荷（可执行文件）", font="黑体", size=10,
                                bold=True, color="CC0000"))
                    for dl in h["download_links"][:6]:
                        C.append(_P(dl, font="Consolas", size=8))

                if h.get("netdisks"):
                    C.append(_P("★ 网盘分发", font="黑体", size=10,
                                bold=True, color="CC0000"))
                    for n in h["netdisks"][:8]:
                        line = "[%s] %s" % (n.get("netdisk", ""), n["url"])
                        if n.get("via"):
                            line += "　（经跳转网关）"
                        C.append(_P(line, font="Consolas", size=8))

                if h.get("gateways"):
                    C.append(_P("★ 跳转网关", font="黑体", size=10,
                                bold=True, color="CC0000"))
                    for g in h["gateways"][:5]:
                        C.append(_P(g["url"], font="Consolas", size=8))
                        if g.get("target"):
                            C.append(_P("　→ 解码：" + g["target"],
                                        font="Consolas", size=8, color="CC0000"))

                if h.get("buckets"):
                    C.append(_P("★ 对象存储桶", font="黑体", size=10,
                                bold=True, color="CC0000"))
                    for bk in h["buckets"]:
                        C.append(_P(bk, font="Consolas", size=8))

                if h.get("refs_official"):
                    C.append(_P("★ 引用品牌真官网（伪装可信度）", font="黑体",
                                size=10, bold=True, color="CC0000"))
                    for rf in h["refs_official"][:3]:
                        C.append(_P("　%s → %s" % (rf.get("brand"), rf.get("host")),
                                    font="Consolas", size=8))

            # 载荷分析
            pa = r.get("payload_analysis") or []
            if pa:
                C.append(_P("★ 载荷分析（VirusTotal）", font="黑体", size=10,
                            bold=True, color="CC0000"))
                prow = []
                for j, x in enumerate(pa[:4], 1):
                    v = x.get("vt") or {}
                    st = v.get("stats") or {}
                    if v.get("found"):
                        sc = "%d/%d 引擎报毒" % (st.get("malicious", 0),
                                              st.get("total", 0))
                    elif v.get("error"):
                        sc = v["error"][:30]
                    else:
                        sc = "VT 无记录"
                    prow.append(["载荷 %d" % j,
                                 (x.get("filename") or "-")[:30],
                                 ("%.1f MB" % (x.get("size", 0) / 1048576))
                                 if x.get("size") else "-",
                                 x.get("kind") or "-", sc])
                C.append(_T(["编号", "文件", "大小", "类型", "VT 检测"], prow))
                for j, x in enumerate(pa[:4], 1):
                    v = x.get("vt") or {}
                    st2 = v.get("stats") or {}

                    detail = []
                    if x.get("sha256"):
                        detail.append("SHA256：%s" % x["sha256"])
                    detail.append("状态：%s" % ("已上传分析" if x.get("uploaded")
                                              else ("VT 库中已有" if v.get("found")
                                                    else "未分析")))
                    if v.get("found"):
                        detail.append("检测结果：%d/%d 引擎报毒"
                                      % (st2.get("malicious", 0),
                                         st2.get("total", 0)))
                        if v.get("label"):
                            detail.append("威胁类型：%s" % v["label"])
                        if v.get("link"):
                            detail.append("VT 链接：%s" % v["link"])
                    elif v.get("error"):
                        detail.append("检测失败：%s" % v["error"][:60])

                    for line in detail:
                        C.append(_P("载荷 %d %s" % (j, line),
                                    font="宋体", size=9))

                    engines = v.get("engines") or []
                    if engines:
                        C.append(_P("载荷 %d 报毒引擎（共 %d 个）："
                                    % (j, len(engines)), font="宋体", size=9))
                        for e in engines[:12]:
                            C.append(_P("　%s: %s" % (e["engine"], e["result"][:48]),
                                        font="Consolas", size=8))
                        if len(engines) > 12:
                            C.append(_P("　…（仅列前 12 个）",
                                        font="楷体", size=8, color="666666"))

            if cert.get("subject"):
                C.append(_P("TLS 证书", font="黑体", size=10, bold=True))
                C.append(_T(["字段", "值"], [
                    ["Subject", cert.get("subject", "")[:70]],
                    ["签发者", (cert.get("issuer_org") or cert.get("issuer") or "-")[:50]],
                    ["有效期", "%s → %s" % (cert.get("not_before", "-"),
                                         cert.get("not_after", "-"))],
                    ["SAN", ", ".join(cert.get("san") or [])[:100] or "-"],
                ]))

            C.append(_P("", font="宋体"))

    # 四、全量明细
    C.append(_P("四、全量域名明细", style="Heading 1", font="黑体"))
    detail_rows = []
    for i, r in enumerate(results, 1):
        w = r.get("whois") or {}
        dns = r.get("dns") or {}
        h = r.get("http_best") or {}
        cert = r.get("cert") or {}
        detail_rows.append([
            i, r["domain"], ",".join(dns.get("A", [])[:2]) or "-",
            w.get("registrant") or "-", (w.get("email") or "-")[:22],
            (w.get("registrar") or "-")[:16],
            str(w.get("reg_time") or "-")[:10],
            (r.get("http_best") or {}).get("status") or "-",
            (h.get("title") or "-")[:20],
            (cert.get("issuer_org") or "-")[:12],
            (r.get("risk") or {}).get("level", "-"),
        ])
    C.append(_T(["#", "域名", "IP", "注册人", "邮箱", "注册商", "注册时间",
                 "状态", "标题", "证书", "等级"], detail_rows, size=7))

    # 五、关联分析
    C.append(_P("五、关联分析", style="Heading 1", font="黑体"))
    from collections import defaultdict

    def _group(fn):
        g = defaultdict(list)
        for r in results:
            k = fn(r)
            if k:
                g[k].append(r["domain"])
        return {k: v for k, v in g.items() if len(v) > 1}

    em_g = _group(lambda r: (r.get("whois") or {}).get("email"))
    ip_g = defaultdict(list)
    for r in results:
        for ip in (r.get("dns") or {}).get("A", []):
            ip_g[ip].append(r["domain"])
    ip_g = {k: v for k, v in ip_g.items() if len(v) > 1}
    reg_g = _group(lambda r: (r.get("whois") or {}).get("registrar"))

    if em_g:
        C.append(_P("5.1 同一注册邮箱（强同源证据）", style="Heading 2", font="黑体"))
        C.append(_T(["注册邮箱", "域名数", "域名"],
                    [[k, len(v), ", ".join(v[:8])]
                     for k, v in sorted(em_g.items(), key=lambda x: -len(x[1]))]))
    if ip_g:
        C.append(_P("5.2 同一 IP 托管", style="Heading 2", font="黑体"))
        C.append(_T(["IP", "域名数", "域名"],
                    [[k, len(v), ", ".join(v[:8])]
                     for k, v in sorted(ip_g.items(), key=lambda x: -len(x[1]))]))
    if reg_g:
        C.append(_P("5.3 注册商分布", style="Heading 2", font="黑体"))
        C.append(_T(["注册商", "域名数"],
                    [[k, len(v)] for k, v in sorted(reg_g.items(),
                                                    key=lambda x: -len(x[1]))]))

    # 六、处置建议
    C.append(_P("六、处置建议", style="Heading 1", font="黑体"))
    sus = [r for r in results
           if (r.get("risk") or {}).get("level") in ("高危", "可疑")]
    if sus:
        payload_r = [r for r in sus if (r.get("http_best") or {}).get("download_links")]
        if payload_r:
            C.append(_P("P0 - 恶意载荷", font="黑体", size=10, bold=True, color="CC0000"))
            for r in payload_r:
                for dl in (r["http_best"].get("download_links") or [])[:3]:
                    C.append(_P("· " + dl, font="Consolas", size=8))
            C.append(_P("→ 向对应云平台提交 abuse 投诉，要求下架文件并冻结账号。",
                        font="宋体", size=10))
        C.append(_P("P1 - 域名处置", font="黑体", size=10, bold=True, color="FF6600"))
        from collections import Counter
        regs = Counter((r.get("whois") or {}).get("registrar") or "未知" for r in sus)
        for rg, cnt in regs.most_common(5):
            C.append(_P("· %s：%d 个域名" % (rg, cnt), font="宋体", size=10))
        C.append(_P("→ 向各注册商提交滥用投诉并附本报告，要求停止解析。",
                    font="宋体", size=10))
        if ip_g:
            C.append(_P("P2 - 基础设施", font="黑体", size=10, bold=True))
            for ip, ds in sorted(ip_g.items(), key=lambda x: -len(x[1]))[:3]:
                C.append(_P("· %s（承载 %d 个域名）" % (ip, len(ds)),
                            font="宋体", size=10))
            C.append(_P("→ 向 IP 归属 ISP/IDC 投诉，要求关停托管服务。",
                        font="宋体", size=10))

    C.append(_P("", font="宋体"))
    C.append(_P("— 报告结束 —", font="宋体", size=9, align="center", color="999999"))
    C.append(_P("本报告由 Domain Intel 自动生成于 %s"
                % now.strftime("%Y-%m-%d %H:%M"),
                font="楷体", size=8, align="center", color="999999"))

    # ---- 构建 ----
    ot = _try_office_tool()
    if ot:
        try:
            doc = ot._build_word_doc({"content": C})
        except Exception:
            doc = _build_fallback(C)
    else:
        doc = _build_fallback(C)

    _set_normal_style(doc)
    _border_shade(doc)
    _line_spacing(doc)
    _setup_page(doc, header_text="域名情报采集报告 — " + now.strftime("%Y-%m-%d"))
    _force_fonts(doc)
    doc.save(out_path)
    return out_path