# -*- coding: utf-8 -*-
"""Excel / Markdown / JSON 报告生成"""
import json
import datetime
from collections import defaultdict, Counter

import openpyxl
from openpyxl.styles import Font, Alignment, PatternFill
from openpyxl.utils import get_column_letter

HEADER_FILL = PatternFill("solid", fgColor="D9E2F3")
LEVEL_FILL = {
    "高危": PatternFill("solid", fgColor="FFD9D9"),
    "可疑": PatternFill("solid", fgColor="FFE8CC"),
}


def build_xlsx(results, stats, out_path):
    """生成 Excel（多工作表：清单 / 风险 / 关联 / 载荷）"""
    wb = openpyxl.Workbook()

    # ---- Sheet1 全量清单 ----
    ws = wb.active
    ws.title = "域名清单"
    HDR = ["#", "域名", "风险分", "等级", "注册局状态", "A记录", "CNAME",
           "注册人", "注册邮箱", "注册商", "注册时间", "到期时间", "域名状态", "NS",
           "HTTP", "HTTPS", "页面标题", "Server", "BodyMD5", "favicon_hash",
           "证书签发者", "证书有效期", "ASN", "IP归属", "开放端口", "动态解析"]
    ws.append(HDR)
    for c in ws[1]:
        c.font = Font(name="黑体", bold=True, size=10)
        c.fill = HEADER_FILL
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)

    for i, r in enumerate(results, 1):
        w = r.get("whois") or {}
        dns = r.get("dns") or {}
        h = r.get("http_best") or {}
        cert = r.get("cert") or {}
        httpa = (r.get("http") or {}).get("http") or {}
        httpsa = (r.get("http") or {}).get("https") or {}
        auth = r.get("auth_check") or {}
        multi = r.get("dns_multi") or {}
        ii = (r.get("ip_infos") or [{}])[0]

        ws.append([
            i, r["domain"],
            (r.get("risk") or {}).get("score", 0),
            (r.get("risk") or {}).get("level", ""),
            auth.get("status", "-"),
            ",".join(dns.get("A") or []) or "-",
            ",".join(dns.get("CNAME") or []) or "-",
            w.get("registrant") or "-",
            w.get("email") or "-",
            w.get("registrar") or "-",
            (w.get("reg_time") or "-"),
            (w.get("exp_time") or "-"),
            ",".join(w.get("status") or []) or "-",
            ",".join(w.get("ns") or dns.get("NS") or []) or "-",
            httpa.get("status") or "-",
            httpsa.get("status") or "-",
            (h.get("title") or "-")[:80],
            h.get("server") or "-",
            (h.get("body_md5") or "-")[:16],
            h.get("favicon_hash") or "-",
            (cert.get("issuer_org") or "-"),
            "%s~%s" % (cert.get("not_before", "-"), cert.get("not_after", "-")),
            ii.get("asn") or "-",
            "%s %s" % (ii.get("country", ""), ii.get("isp") or ii.get("org") or ""),
            ",".join(str(p) for p in (ii.get("open_ports") or [])) or "-",
            "是(%d个IP)" % multi.get("distinct_ip_count", 0) if multi.get("dynamic") else "否",
        ])

    widths = [4, 32, 7, 8, 12, 20, 24, 10, 26, 22, 19, 19, 16, 26,
              7, 7, 42, 16, 17, 13, 22, 42, 14, 24, 18, 12]
    for i, wd in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = wd
    for row in ws.iter_rows(min_row=2):
        for c in row:
            c.font = Font(name="宋体", size=9)
            c.alignment = Alignment(vertical="center")
        lvl = row[3].value
        if lvl in LEVEL_FILL:
            for c in row:
                c.fill = LEVEL_FILL[lvl]
    ws.freeze_panes = "C2"
    ws.auto_filter.ref = ws.dimensions

    # ---- Sheet2 风险清单 ----
    ws2 = wb.create_sheet("风险清单")
    ws2.append(["等级", "评分", "域名", "主要判定依据"])
    for c in ws2[1]:
        c.font = Font(name="黑体", bold=True, size=10)
        c.fill = HEADER_FILL
        c.alignment = Alignment(horizontal="center", wrap_text=True)
    for r in sorted(results, key=lambda x: -(x.get("risk") or {}).get("score", 0)):
        risk = r.get("risk") or {}
        ws2.append([risk.get("level", ""), risk.get("score", 0), r["domain"],
                    "；".join(risk.get("reasons", []))])
    for i, wd in enumerate([8, 7, 32, 90], 1):
        ws2.column_dimensions[get_column_letter(i)].width = wd
    for row in ws2.iter_rows(min_row=2):
        for c in row:
            c.font = Font(name="宋体", size=9)
            c.alignment = Alignment(vertical="top", wrap_text=True)
        lvl = row[0].value
        if lvl in LEVEL_FILL:
            for c in row:
                c.fill = LEVEL_FILL[lvl]

    # ---- Sheet3 载荷与分发设施 ----
    ws3 = wb.create_sheet("载荷与分发设施")
    ws3.append(["域名", "类型", "地址", "备注"])
    for c in ws3[1]:
        c.font = Font(name="黑体", bold=True, size=10)
        c.fill = HEADER_FILL
    for r in results:
        h = r.get("http_best") or {}
        for dl in h.get("download_links") or []:
            ws3.append([r["domain"], "下载链接", dl, ""])
        for bk in h.get("buckets") or []:
            ws3.append([r["domain"], "对象存储桶", bk, "分发设施"])
    for i, wd in enumerate([32, 14, 80, 20], 1):
        ws3.column_dimensions[get_column_letter(i)].width = wd
    for row in ws3.iter_rows(min_row=2):
        for c in row:
            c.font = Font(name="宋体", size=9)
            c.alignment = Alignment(vertical="center")

    # ---- Sheet4 关联分析 ----
    ws4 = wb.create_sheet("关联分析")
    ws4.append(["关联维度", "值", "域名数", "涉及域名"])
    for c in ws4[1]:
        c.font = Font(name="黑体", bold=True, size=10)
        c.fill = HEADER_FILL

    email_map = defaultdict(list)
    ip_map = defaultdict(list)
    reg_map = defaultdict(list)
    ns_map = defaultdict(list)
    for r in results:
        w = r.get("whois") or {}
        if w.get("email"):
            email_map[w["email"]].append(r["domain"])
        if w.get("registrar"):
            reg_map[w["registrar"]].append(r["domain"])
        for ip in (r.get("dns") or {}).get("A", []):
            ip_map[ip].append(r["domain"])
        for ns in (w.get("ns") or (r.get("dns") or {}).get("NS") or []):
            ns_map[ns].append(r["domain"])

    for em, ds in sorted(email_map.items(), key=lambda x: -len(x[1])):
        ws4.append(["注册邮箱", em, len(ds), ", ".join(ds)])
    for ip, ds in sorted(ip_map.items(), key=lambda x: -len(x[1])):
        if len(ds) > 1:
            ws4.append(["同IP托管", ip, len(ds), ", ".join(ds)])
    for rg, ds in sorted(reg_map.items(), key=lambda x: -len(x[1])):
        ws4.append(["注册商", rg, len(ds), ", ".join(ds[:20])])
    for ns, ds in sorted(ns_map.items(), key=lambda x: -len(x[1])):
        if len(ds) > 1:
            ws4.append(["NS服务器", ns, len(ds), ", ".join(ds[:20])])

    for i, wd in enumerate([14, 42, 8, 80], 1):
        ws4.column_dimensions[get_column_letter(i)].width = wd
    for row in ws4.iter_rows(min_row=2):
        for c in row:
            c.font = Font(name="宋体", size=9)
            c.alignment = Alignment(vertical="top", wrap_text=True)

    # ---- Sheet5 统计 ----
    ws5 = wb.create_sheet("统计汇总")
    ws5.append(["统计项", "值"])
    for c in ws5[1]:
        c.font = Font(name="黑体", bold=True, size=10)
        c.fill = HEADER_FILL
    lv = stats.get("by_level", {})
    for k, v in [("域名总数", stats.get("total", 0)),
                 ("DNS 有解析", stats.get("alive", 0)),
                 ("动态解析", stats.get("dynamic", 0)),
                 ("存在下载链接", stats.get("with_payload", 0)),
                 ("高危", lv.get("高危", 0)),
                 ("可疑", lv.get("可疑", 0)),
                 ("低危", lv.get("低危", 0)),
                 ("正常", lv.get("正常", 0)),
                 ("已失效", lv.get("已失效", 0)),
                 ("未注册", lv.get("未注册", 0)),
                 ("独立注册邮箱数", len(email_map)),
                 ("独立 IP 数", len(ip_map)),
                 ("独立注册商数", len(reg_map)),
                 ]:
        ws5.append([k, v])
    ws5.column_dimensions["A"].width = 22
    ws5.column_dimensions["B"].width = 14
    for row in ws5.iter_rows(min_row=2):
        for c in row:
            c.font = Font(name="宋体", size=9)

    wb.save(out_path)
    return out_path


def build_markdown(results, stats, out_path):
    """生成 Markdown 报告"""
    now = datetime.datetime.now()
    L = []
    A = L.append
    A("# 域名情报采集报告")
    A("")
    A("- 生成时间：%s" % now.strftime("%Y-%m-%d %H:%M"))
    A("- 样本数量：%d" % stats.get("total", len(results)))
    A("")
    A("## 一、总览")
    A("")
    A("| 指标 | 数值 |")
    A("|---|---|")
    lv = stats.get("by_level", {})
    for k, v in [("域名总数", stats.get("total", 0)),
                 ("DNS 有解析", stats.get("alive", 0)),
                 ("动态解析", stats.get("dynamic", 0)),
                 ("存在下载链接", stats.get("with_payload", 0)),
                 ("高危", lv.get("高危", 0)),
                 ("可疑", lv.get("可疑", 0)),
                 ("低危", lv.get("低危", 0)),
                 ("正常", lv.get("正常", 0)),
                 ("已失效/未注册", lv.get("已失效", 0) + lv.get("未注册", 0))]:
        A("| %s | %s |" % (k, v))
    A("")

    A("## 二、全量明细")
    A("")
    A("| # | 域名 | 评分 | 等级 | IP | 注册人 | 注册商 | 标题 |")
    A("|---|---|---|---|---|---|---|---|")
    for i, r in enumerate(results, 1):
        w = r.get("whois") or {}
        dns = r.get("dns") or {}
        h = r.get("http_best") or {}
        risk = r.get("risk") or {}
        A("| %d | `%s` | %s | %s | %s | %s | %s | %s |" % (
            i, r["domain"], risk.get("score", 0), risk.get("level", ""),
            ",".join(dns.get("A", [])[:2]) or "-",
            w.get("registrant") or "-",
            (w.get("registrar") or "-")[:18],
            (h.get("title") or "-")[:30]))
    A("")

    payl = [r for r in results if (r.get("http_best") or {}).get("download_links")]
    if payl:
        A("## 三、载荷与分发设施")
        A("")
        for r in payl:
            A("### %s" % r["domain"])
            for dl in r["http_best"]["download_links"][:8]:
                A("- 下载：`%s`" % dl)
            for bk in r["http_best"].get("buckets") or []:
                A("- 存储桶：`%s`" % bk)
            A("")

    # 关联
    email_map = defaultdict(list)
    ip_map = defaultdict(list)
    for r in results:
        w = r.get("whois") or {}
        if w.get("email"):
            email_map[w["email"]].append(r["domain"])
        for ip in (r.get("dns") or {}).get("A", []):
            ip_map[ip].append(r["domain"])

    multi_em = {k: v for k, v in email_map.items() if len(v) > 1}
    multi_ip = {k: v for k, v in ip_map.items() if len(v) > 1}
    if multi_em or multi_ip:
        A("## 四、关联分析")
        A("")
        if multi_em:
            A("### 同一注册邮箱")
            A("")
            A("| 邮箱 | 域名数 | 域名 |")
            A("|---|---|---|")
            for em, ds in sorted(multi_em.items(), key=lambda x: -len(x[1])):
                A("| `%s` | %d | %s |" % (em, len(ds), ", ".join(ds)))
            A("")
        if multi_ip:
            A("### 同一 IP")
            A("")
            A("| IP | 域名数 | 域名 |")
            A("|---|---|---|")
            for ip, ds in sorted(multi_ip.items(), key=lambda x: -len(x[1])):
                A("| `%s` | %d | %s |" % (ip, len(ds), ", ".join(ds)))
            A("")

    open(out_path, "w", encoding="utf-8").write("\n".join(L))
    return out_path


def build_json(results, stats, out_path):
    out = {
        "generated": datetime.datetime.now().isoformat(timespec="seconds"),
        "stats": stats,
        "results": results,
    }
    # 去掉体积大的 html 字段
    for r in out["results"]:
        for k in ("http",):
            if k in r and isinstance(r[k], dict):
                for sch in r[k].values():
                    if isinstance(sch, dict):
                        sch.pop("html", None)
                        sch.pop("headers", None)
        if "http_best" in r and isinstance(r["http_best"], dict):
            r["http_best"].pop("html", None)
            r["http_best"].pop("headers", None)
        w = r.get("whois")
        if isinstance(w, dict):
            w.pop("raw", None)
    open(out_path, "w", encoding="utf-8").write(
        json.dumps(out, ensure_ascii=False, indent=1))
    return out_path