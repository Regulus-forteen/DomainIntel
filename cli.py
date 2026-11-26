# -*- coding: utf-8 -*-
"""
Domain Intel - 命令行版本（动态进度 + 动画）

用法：
    python cli.py domains.txt
    python cli.py -d "a.com,b.com" -w 8
    python cli.py domains.txt --no-payload --no-mail
    python cli.py domains.txt --send
"""
import os
import sys
import time
import threading
import argparse
import datetime
from pathlib import Path
from collections import Counter, defaultdict
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

if os.name == "nt":
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


class C:
    R = "\033[0m"
    B = "\033[1m"
    D = "\033[2m"
    RED = "\033[91m"
    GRN = "\033[92m"
    YEL = "\033[93m"
    BLU = "\033[94m"
    MAG = "\033[95m"
    CYA = "\033[96m"
    GRY = "\033[90m"


LEVEL_COLOR = {"高危": C.RED, "可疑": C.YEL, "低危": C.YEL,
               "正常": C.GRN, "已失效": C.GRY, "未注册": C.GRY,
               "探测失败": C.GRY}

STAGES = [
    ("auth", "权威验证"), ("dns", "DNS解析"), ("multi", "多轮采样"),
    ("whois", "WHOIS"), ("http", "HTTP探测"), ("cert", "TLS证书"),
    ("ip", "IP情报"), ("mn", "多节点"), ("score", "风险评分"),
]
STAGE_NAME = dict(STAGES)

SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


class Spinner:
    def __init__(self, text=""):
        self.text = text
        self.running = False
        self.th = None
        self.i = 0

    def start(self):
        self.running = True
        self.th = threading.Thread(target=self._run, daemon=True)
        self.th.start()

    def _run(self):
        while self.running:
            sys.stdout.write("\r%s %s\033[K" % (SPINNER[self.i % len(SPINNER)], self.text))
            sys.stdout.flush()
            self.i += 1
            time.sleep(0.08)

    def stop(self, final=""):
        self.running = False
        time.sleep(0.09)
        sys.stdout.write("\r" + " " * 96 + "\r")
        if final:
            print(final)
        sys.stdout.flush()


class StagePanel:
    """多线程阶段面板：固定槽位显示每个活跃域名的阶段进度"""

    MAX_SLOTS = 5

    def __init__(self):
        self.slots = {}
        self.order = []
        self.lock = threading.Lock()
        self.rendered_lines = 0

    def _slot(self, domain):
        if domain not in self.slots:
            self.slots[domain] = {"done": set(), "running": None}
            self.order.append(domain)
        return self.slots[domain]

    def set_running(self, domain, key):
        with self.lock:
            self._slot(domain)["running"] = key
            self._draw()

    def set_done(self, domain, key):
        with self.lock:
            s = self._slot(domain)
            s["done"].add(key)
            self._draw()

    def _draw(self):
        show = self.order[-self.MAX_SLOTS:]
        if self.rendered_lines:
            sys.stdout.write("\033[%dA" % self.rendered_lines)
        for d in show:
            s = self.slots[d]
            bar = []
            for k, _ in STAGES:
                if k in s["done"]:
                    bar.append(C.GRN + "█" + C.R)
                elif k == s["running"]:
                    bar.append(C.YEL + "▓" + C.R)
                else:
                    bar.append(C.GRY + "░" + C.R)
            nm = STAGE_NAME.get(s["running"], "") if s["running"] else ""
            line = "  %s %s%-30s%s %s%s%s" % (
                "".join(bar), C.D, d[:30], C.R, C.YEL, nm, C.R)
            sys.stdout.write("\r" + line + "\033[K\n")
        self.rendered_lines = len(show)
        sys.stdout.flush()

    def clear(self):
        if self.rendered_lines:
            sys.stdout.write("\033[%dA" % self.rendered_lines)
            for _ in range(self.rendered_lines):
                sys.stdout.write("\r" + " " * 96 + "\033[K\n")
            sys.stdout.write("\033[%dA" % self.rendered_lines)
            sys.stdout.flush()
            self.rendered_lines = 0


def _probe_with_stage(domain, options, stage_cb):
    from core import probe as probe_mod
    from core import dnsx, whoisx, httpx, ipx

    def st(key, snap=False):
        if stage_cb:
            stage_cb(domain, key, snap)

    t0 = time.time()
    d = domain.strip().lower().rstrip(".")
    r = {"domain": d, "ts": datetime.datetime.now().isoformat(timespec="seconds")}

    if options.get("auth_check", True):
        st("auth")
        r["auth_check"] = dnsx.authoritative_check(d)
        st("auth", True)

    st("dns")
    r["dns"] = dnsx.query_records(d)
    st("dns", True)

    if options.get("multi_round", True):
        st("multi")
        r["dns_multi"] = dnsx.multi_round(d)
        st("multi", True)

    st("whois")
    try:
        r["whois"] = whoisx.whois(d)
    except Exception as e:
        r["whois"] = {"error": str(e)[:100]}
    st("whois", True)

    ips = r["dns"].get("A", [])
    if not ips and r.get("dns_multi"):
        ips = [i for i in (r["dns_multi"].get("ip_pool") or {}) if ":" not in i]

    r["cert"] = {}
    r["ip_infos"] = []
    if ips:
        st("http")
        r["http"], r["http_best"] = httpx.collect_http(d)
        st("http", True)
        if options.get("cert", True):
            st("cert")
            r["cert"] = httpx.cert_probe(d)
            st("cert", True)
        st("ip")
        for ip in ips[:2]:
            ii = ipx.ip_info(ip)
            if options.get("port_scan", True):
                ii["open_ports"] = ipx.port_scan(ip)
            if options.get("reverse_ip", False):
                ii["reverse_ip"] = ipx.reverse_ip(ip)
            r["ip_infos"].append(ii)
        st("ip", True)
    else:
        r["http"], r["http_best"] = {}, {}

    if options.get("multi_node", False):
        st("mn")
        try:
            from core import multi_node as mn_mod
            r["multi_node"] = mn_mod.check_dns(d, max_nodes=15, timeout_wait=40)
        except Exception as e:
            r["multi_node"] = {"error": str(e)[:80]}
        st("mn", True)

    st("score")
    r["risk"] = probe_mod.score(r)
    r["elapsed"] = round(time.time() - t0, 1)
    st("score", True)
    return r


def parse_domains_arg(s):
    p = Path(s)
    if p.exists() and p.is_file():
        text = p.read_text(encoding="utf-8", errors="ignore")
    else:
        text = s
    seen, out = set(), []
    for line in text.replace(",", "\n").replace(";", "\n").splitlines():
        d = line.strip().lower()
        if not d or d.startswith("#"):
            continue
        for pre in ("http://", "https://"):
            if d.startswith(pre):
                d = d[len(pre):]
        d = d.split("/")[0].split("?")[0].strip().rstrip(".")
        if "." not in d or " " in d:
            continue
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def banner():
    print()
    print(C.CYA + "  ██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗" + C.R)
    print(C.CYA + "  ██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║" + C.R)
    print(C.BLU + "  ██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║" + C.R)
    print(C.BLU + "  ██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║" + C.R)
    print(C.MAG + "  ██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║" + C.R)
    print(C.MAG + "  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝" + C.R)
    print(C.GRY + "         I N T E L   ·   域名情报采集与举报工具 v1.0" + C.R)
    print()


def run(args):
    from core import probe as probe_mod
    from core import payload as payload_mod
    from core import abuse as abuse_mod
    from core import vt as vt_mod
    from report import docx_gen, xlsx_gen

    banner()

    domains = parse_domains_arg(args.domains)
    if not domains:
        print(C.RED + "  ✗ 未解析出有效域名" + C.R)
        return 1
    if args.limit and len(domains) > args.limit:
        domains = domains[:args.limit]

    print("  %s目标%s %s%d%s 个域名　%s并发 %d%s" % (
        C.D, C.R, C.B, len(domains), C.R, C.D, args.workers, C.R))
    print()

    opts = {
        "auth_check": not args.no_auth,
        "multi_round": not args.no_multi,
        "cert": not args.no_cert,
        "port_scan": not args.no_port,
        "reverse_ip": args.reverse_ip,
        "subdomain": args.subdomain,
        "multi_node": args.multi_node,
        "dynamic": args.dynamic,
        "vt_analysis": args.vt,
    }

    # ============ 阶段 1：探测 ============
    print(C.B + "  ╭─ 阶段 1/3  域名探测 " + "─" * 46 + C.R)
    print()
    results = []
    panel = StagePanel()
    anim = not args.no_anim

    def stage_cb(domain, key, is_done):
        if not anim:
            return
        if is_done:
            panel.set_done(domain, key)
        else:
            panel.set_running(domain, key)

    from concurrent.futures import ThreadPoolExecutor, as_completed
    t_start = time.time()
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(_probe_with_stage, d, opts, stage_cb): d for d in domains}
        for f in as_completed(futs):
            d = futs[f]
            try:
                results.append(f.result())
            except Exception as e:
                results.append({"domain": d, "error": str(e)[:120],
                                "risk": {"score": 0, "level": "探测失败",
                                         "reasons": [str(e)[:80]]}})

    if anim:
        panel.clear()

    try:
        probe_mod._mark_relations(results)
    except Exception:
        pass

    order = {d: i for i, d in enumerate(domains)}
    results.sort(key=lambda x: order.get(x["domain"], 9999))

    lv = Counter((r.get("risk") or {}).get("level", "未知") for r in results)
    stats = {
        "total": len(results), "by_level": dict(lv),
        "alive": sum(1 for r in results if (r.get("dns") or {}).get("A")),
        "dynamic": sum(1 for r in results
                       if (r.get("dns_multi") or {}).get("dynamic")),
        "with_payload": sum(1 for r in results
                            if (r.get("http_best") or {}).get("download_links")),
        "elapsed": round(time.time() - t_start, 1),
    }

    print("  %s✓%s 探测完成 %s%d%s 个　耗时 %ss" % (
        C.GRN, C.R, C.B, len(results), C.R, stats["elapsed"]))
    print()

    # ============ 结果表 ============
    print(C.B + "  ╭─ 探测结果 " + "─" * 56 + C.R)
    print("  %s#   %-30s %5s %-6s %-17s %s%s" % (
        C.D, "域名", "分数", "等级", "解析IP", "页面标题", C.R))
    print("  " + C.GRY + "─" * 98 + C.R)
    for i, r in enumerate(sorted(results,
                                 key=lambda x: -(x.get("risk") or {}).get("score", 0)), 1):
        risk = r.get("risk") or {}
        dns = r.get("dns") or {}
        h = r.get("http_best") or {}
        lvl = risk.get("level", "")
        col = LEVEL_COLOR.get(lvl, "")
        print("  %-3d %-30s %s%5d %-6s%s %-17s %s" % (
            i, r["domain"][:30], col, risk.get("score", 0), lvl, C.R,
            (",".join(dns.get("A", [])[:1]) or "-")[:17],
            (h.get("title") or "-")[:36]))
    print("  " + C.GRY + "─" * 98 + C.R)
    print("  %s总数 %d　高危 %d　可疑 %d　低危 %d　正常 %d　失效 %d%s" % (
        C.D, stats["total"], lv.get("高危", 0), lv.get("可疑", 0),
        lv.get("低危", 0), lv.get("正常", 0),
        lv.get("已失效", 0) + lv.get("未注册", 0), C.R))
    print()

    # ============ 阶段 2：载荷分析 ============
    do_payload = (not args.no_payload) or args.vt
    if args.vt:
        do_payload = True
    if args.no_payload and not args.vt:
        do_payload = False

    if do_payload:
        payloads = payload_mod.collect_payloads(results, only_risky=True)
        if payloads:
            print(C.B + "  ╭─ 阶段 2/3  载荷分析（VirusTotal） " + "─" * 32 + C.R)
            q = vt_mod.quota_stat()
            print("  %sVT 配额 %d/%d　待分析 %d 个载荷%s"
                  % (C.GRY, q["今日已用"], q["每日上限"], len(payloads), C.R))
            print()

            presults = []
            for i, (dom, url) in enumerate(payloads, 1):
                sp = Spinner("(%d/%d) 下载 %s" % (i, len(payloads), url[:56]))
                sp.start()
                x = payload_mod.analyze_payload(
                    url, idx=i, auto_upload=not args.no_upload,
                    progress_cb=lambda s, u: setattr(
                        sp, "text", "(%d/%d) %s %s" % (
                            i if False else i, len(payloads),
                            {"download": "下载", "vt_query": "查VT",
                             "vt_upload": "上传", "vt_wait": "等待结果",
                             "delete": "清理"}.get(s, s), u[:50])))
                x["domain"] = dom
                presults.append(x)

                v = x.get("vt") or {}
                st = v.get("stats") or {}
                mal = st.get("malicious", 0)
                if v.get("found") and mal > 0:
                    tag = "%s%d/%d 报毒 %s%s" % (C.RED, mal, st.get("total", 0),
                                                v.get("label", ""), C.R)
                elif v.get("found"):
                    tag = "%s0 报毒%s" % (C.GRN, C.R)
                else:
                    tag = "%s无记录%s" % (C.GRY, C.R)
                sp.stop("  %s✓%s %s %s" % (C.GRN, C.R, url[:56], tag))

            # 挂回域名 + 重新评分（VT 报毒 +50 在这里生效）
            for x in presults:
                for r in results:
                    if r["domain"] == x.get("domain"):
                        r.setdefault("payload_analysis", []).append(x)

            from core import scoring as _sc
            rescored = 0
            for r in results:
                if r.get("payload_analysis"):
                    old_score = (r.get("risk") or {}).get("score", 0)
                    r["risk"] = _sc.score_v2(r)
                    if (r["risk"].get("score", 0) != old_score):
                        rescored += 1
            if rescored:
                print()
                print("  %sVT 结果已并入评分，%d 个域名分数发生变化：%s"
                      % (C.GRN, rescored, C.R))
                for r in sorted(results, key=lambda x: -(x.get("risk") or {}).get("score", 0)):
                    rk = r.get("risk") or {}
                    col = LEVEL_COLOR.get(rk.get("level", ""), "")
                    print("    %-30s %s%3d %s%s" % (
                        r["domain"][:30], col, rk.get("score", 0),
                        rk.get("level", ""), C.R))
                # 更新统计
                lv2 = Counter((r.get("risk") or {}).get("level", "未知") for r in results)
                stats["by_level"] = dict(lv2)

            print()
            for x in presults:
                v = x.get("vt") or {}
                st = v.get("stats") or {}
                if not v.get("found"):
                    continue
                print("  %s▸ %s%s" % (C.CYA, (x.get("filename") or "")[:44], C.R))
                print("    SHA256  %s" % (x.get("sha256") or "-"))
                print("    类型    %s  %s" % (
                    ("%.1f MB" % (x.get("size", 0) / 1048576)) if x.get("size") else "-",
                    x.get("kind") or "-"))
                if st.get("malicious", 0) > 0:
                    print("    VT      %s%d/%d 报毒%s  %s" % (
                        C.RED, st["malicious"], st.get("total", 0), C.R,
                        v.get("label") or "-"))
                    for e in (v.get("engines") or [])[:4]:
                        print("            %s· %-15s%s %s" % (
                            C.GRY, e["engine"][:15], C.R, e["result"][:42]))
                else:
                    print("    VT      %s无引擎报毒%s" % (C.GRN, C.R))
                print("    本地    %s" % ("已删除" if x.get("deleted") else "未删除"))
                print()
        else:
            nd = sum(len((r.get("http_best") or {}).get("netdisks") or [])
                     for r in results)
            if nd:
                print(C.D + "  发现 %d 条网盘分发链接（无法直接下载，需人工处理）" + C.R)
            else:
                print(C.D + "  未发现可分析的载荷链接" + C.R)
            print()
    else:
        print(C.D + "  已跳过载荷分析" + C.R)
        print()

    # ============ 阶段 3：生成报告 ============
    print(C.B + "  ╭─ 阶段 3/3  生成报告 " + "─" * 46 + C.R)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path(args.out) if args.out else BASE_DIR / "output"
    outdir.mkdir(parents=True, exist_ok=True)

    files = {}
    for kind, fn, builder in [
        ("docx", "域名情报报告_%s.docx" % ts, docx_gen.build_docx),
        ("xlsx", "域名情报数据_%s.xlsx" % ts, xlsx_gen.build_xlsx),
        ("md", "域名情报报告_%s.md" % ts, xlsx_gen.build_markdown),
        ("json", "域名情报数据_%s.json" % ts, xlsx_gen.build_json),
    ]:
        sp = Spinner("生成 %s" % kind.upper())
        if anim:
            sp.start()
        try:
            p = outdir / fn
            builder(results, stats, str(p))
            files[kind] = p
            if anim:
                sp.stop("  %s✓%s %-6s %s" % (C.GRN, C.R, kind.upper(), fn))
            else:
                print("  ✓ %-6s %s" % (kind.upper(), fn))
        except Exception as e:
            if anim:
                sp.stop("  %s✗%s %-6s %s" % (C.RED, C.R, kind.upper(), str(e)[:56]))
            else:
                print("  ✗ %-6s %s" % (kind.upper(), str(e)[:56]))

    # ============ 举报邮件 ============
    drafts = []
    if not args.no_mail:
        print()
        print(C.B + "  ╭─ 举报邮件草稿 " + "─" * 52 + C.R)
        sp = Spinner("按注册商分组")
        if anim:
            sp.start()
        try:
            drafts, ddir = abuse_mod.generate_drafts(results, stamp=ts)
            if anim:
                sp.stop("  %s✓%s 生成 %d 封草稿" % (C.GRN, C.R, len(drafts)))
            print("  %s目录%s %s" % (C.D, C.R, ddir))
            for d in drafts:
                em = d.get("abuse_email") or C.RED + "【无邮箱】" + C.R
                print("    %s●%s %-36s → %s" % (C.CYA, C.R,
                                               d["registrar"][:36], em))
                print("      %s%s%s" % (C.D, d["subject"][:70], C.R))
        except Exception as e:
            if anim:
                sp.stop("  %s✗%s %s" % (C.RED, C.R, str(e)[:64]))

    # ============ 完成 ============
    print()
    print("  " + C.GRN + "█" * 98 + C.R)
    print("  %s✓ 全部完成%s　输出目录 %s" % (C.GRN + C.B, C.R, outdir))
    print("  " + C.GRN + "█" * 98 + C.R)
    print()

    if drafts and args.send:
        if input("  确认发送 %d 封举报邮件？(yes/NO) " % len(drafts)).strip().lower() == "yes":
            cfg = abuse_mod.load_mail_config()
            if not cfg:
                print("  " + C.RED + "✗ 未找到邮件配置 mail_config.json" + C.R)
            else:
                for i, d in enumerate(drafts, 1):
                    to = d.get("abuse_email")
                    if not to:
                        print("  %s-%s %s 无邮箱，跳过" % (C.GRY, C.R,
                                                       d["registrar"][:30]))
                        continue
                    sp = Spinner("发送 %d/%d → %s" % (i, len(drafts), to))
                    if anim:
                        sp.start()
                    ok, msg = abuse_mod.send_one(cfg, to, d["subject"], d["body"])
                    line = "  %s%s%s %s → %s" % (
                        C.GRN if ok else C.RED, "✓" if ok else "✗", C.R,
                        d["registrar"][:28], msg[:40])
                    if anim:
                        sp.stop(line)
                    else:
                        print(line)
                    if i < len(drafts):
                        time.sleep(args.interval)
    elif drafts:
        print(C.D + "  提示：加 --send 可直接发送；或手动发 output/abuse_drafts 下的草稿" + C.R)
        print()

    return 0


def main():
    ap = argparse.ArgumentParser(
        prog="cli.py",
        description="Domain Intel - 域名情报采集与举报工具（命令行版）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python cli.py domains.txt
  python cli.py -d "a.com,b.com" -w 8
  python cli.py domains.txt --no-payload --no-mail
  python cli.py domains.txt --send
""")
    ap.add_argument("domains", nargs="?",
                    help="域名列表文件或逗号分隔域名")
    ap.add_argument("-d", "--domain-list", dest="domain_list",
                    help="域名列表（等同位置参数，便于 --xxx 与 -d 混用）")
    ap.add_argument("-o", "--out", help="输出目录（默认 output/）")
    ap.add_argument("-w", "--workers", type=int, default=6, help="并发数，默认 6")
    ap.add_argument("--limit", type=int, help="最多处理多少个域名")
    ap.add_argument("--no-anim", action="store_true", help="关闭动画（适合重定向）")

    ap.add_argument("--no-auth", action="store_true", help="跳过权威验证")
    ap.add_argument("--no-multi", action="store_true", help="跳过多轮 DNS")
    ap.add_argument("--no-cert", action="store_true", help="跳过 TLS 证书")
    ap.add_argument("--no-port", action="store_true", help="跳过端口扫描")
    ap.add_argument("--reverse-ip", action="store_true", help="启用同 IP 反查")
    ap.add_argument("--subdomain", action="store_true", help="启用子域枚举")
    ap.add_argument("--multi-node", action="store_true", help="启用多节点 CDN 探测")
    ap.add_argument("--dynamic", action="store_true",
                    help="启用动态解析（Playwright 点击按钮抓 JS 生成的下载地址）")

    ap.add_argument("--vt", action="store_true",
                    help="启用载荷分析（下载样本 → 查/传 VT）")
    ap.add_argument("--no-payload", action="store_true", help="跳过载荷分析")
    ap.add_argument("--no-upload", action="store_true", help="VT 无记录时不自动上传")
    ap.add_argument("--no-mail", action="store_true", help="不生成举报邮件")
    ap.add_argument("--send", action="store_true", help="生成后直接发送")
    ap.add_argument("--interval", type=int, default=25, help="邮件发送间隔秒")

    args = ap.parse_args()
    src_arg = args.domains or args.domain_list
    if not src_arg:
        banner()
        ap.print_help()
        return 1
    args.domains = src_arg

    try:
        return run(args)
    except KeyboardInterrupt:
        print("\n\n  " + C.YEL + "已中断" + C.R)
        return 130


if __name__ == "__main__":
    sys.exit(main())