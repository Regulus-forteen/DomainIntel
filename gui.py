# -*- coding: utf-8 -*-
"""
Domain Intel - 域名情报采集工具

界面规则：
- 左侧是标签文字（在格子外），右侧是白色格子，格子内只放值
- 有数据就显示值；跑了但无数据填 None；还没跑则留空
- 格子始终保持白色，不做颜色标记
- 颜色只用于顶部的阶段指示条（绿=完成，黄=进行中，无=未开始）
- 按信息来源分区
"""

import os
import sys
import time
import queue
import threading
import datetime
import traceback
from pathlib import Path

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from core import probe as probe_mod
from core import dnsx, whoisx, httpx, ipx
from core import ctx as ct_mod
from core import abuse as abuse_mod
from core import payload as payload_mod
from core import vt as vt_mod
import gui_abuse
from report import docx_gen, xlsx_gen

OUT_DIR = BASE_DIR / "output"
OUT_DIR.mkdir(exist_ok=True)

STAGES = [
    ("auth", "权威验证"),
    ("dns", "DNS解析"),
    ("multi", "多轮采样"),
    ("whois", "WHOIS"),
    ("http", "HTTP探测"),
    ("cert", "TLS证书"),
    ("ip", "IP情报"),
    ("mn", "多节点"),
    ("score", "风险评分"),
]
STAGE_NAME = dict(STAGES)
STAGE_ORDER = {k: i for i, (k, _) in enumerate(STAGES)}

C_DONE = "#7FD17F"   # 完成：明显绿
C_RUN = "#FFC000"    # 进行中：明显橙黄

NONE = "None"   # 跑了但无数据时的占位


def parse_domains(text):
    seen, out = set(), []
    for line in text.replace(",", "\n").replace(";", "\n").replace("，", "\n").splitlines():
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


# ---------------------------------------------------------------------------
# 字段定义：按来源分区，每个字段带一个「所属阶段」，用于判断该显示值 / None / 空
# 返回 (分区, [(标签, 值或None)])
# ---------------------------------------------------------------------------
def _join(v, sep=", "):
    if not v:
        return None
    if isinstance(v, (list, tuple)):
        s = sep.join(str(x) for x in v)
        return s if s else None
    return str(v)


def build_sections(r, done_stages):
    """
    done_stages: 已完成的阶段集合
    规则：
      字段所属阶段未完成 -> ""
      阶段已完成但没数据   -> "None"
      有数据             -> 值
    """
    w = r.get("whois") or {}
    dns = r.get("dns") or {}
    multi = r.get("dns_multi") or {}
    auth = r.get("auth_check") or {}
    cert = r.get("cert") or {}
    h = r.get("http_best") or {}
    httpa = (r.get("http") or {}).get("http") or {}
    httpsa = (r.get("http") or {}).get("https") or {}
    risk = r.get("risk") or {}
    mn = r.get("multi_node") or {}
    ip0 = (r.get("ip_infos") or [{}])[0]

    def val(stage, v):
        if stage not in done_stages:
            return ""
        if v is None or v == "" or v == [] or v == {}:
            return NONE
        return str(v)

    S = []

    # ---- 基本 ----
    # 注册局状态：区分「查询失败」和「确实不存在」
    _as = auth.get("status") or ""
    if _as == "NXDOMAIN":
        _auth_txt = "NXDOMAIN（注册局无记录）"
    elif _as == "FAIL":
        _auth_txt = "查询失败（%s）" % (auth.get("reason") or "网络异常")
    elif _as == "EXISTS":
        _auth_txt = "EXISTS（已注册）"
    else:
        _auth_txt = _as or None

    rows = [
        ("域名", val("auth", r.get("domain"))),
        ("注册局状态", val("auth", _auth_txt)),
        ("风险评分", val("score", "%s / 100" % risk.get("score")) if risk else ""),
        ("风险等级", val("score", risk.get("level"))),
        ("域名年龄", val("score", ("%d 天" % r["age_days"])
                        if r.get("age_days") is not None else None)),
        ("探测耗时", val("score", ("%s 秒" % r.get("elapsed"))
                        if r.get("elapsed") else None)),
    ]
    S.append(("基本", rows))

    # ---- 注册信息 ----
    rows = [
        ("注册人", val("whois", w.get("registrant"))),
        ("注册邮箱", val("whois", w.get("email"))),
        ("注册商", val("whois", w.get("registrar"))),
        ("注册时间", val("whois", str(w.get("reg_time") or "")[:19])),
        ("到期时间", val("whois", str(w.get("exp_time") or "")[:19])),
        ("更新时间", val("whois", str(w.get("upd_time") or "")[:19])),
        ("国家", val("whois", w.get("country"))),
        ("域名状态", val("whois", _join(w.get("status")))),
        ("NS 记录", val("whois", _join(w.get("ns")))),
        ("DNSSEC", val("whois", w.get("dnssec"))),
        ("Abuse 邮箱", val("whois", w.get("abuse_email"))),
    ]
    S.append(("注册信息", rows))

    # ---- DNS ----
    rows = []
    for rt in ("A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA", "CAA"):
        rows.append((rt, val("dns", _join(dns.get(rt), "; "))))
    rows.append(("采样次数", val("multi", multi.get("total_queries"))))
    rows.append(("不同 IP 数", val("multi", multi.get("distinct_ip_count")
                                 if "distinct_ip_count" in multi else None)))
    rows.append(("动态调度", val("multi", ("是" if multi.get("dynamic") else "否")
                                 if multi else None)))
    S.append(("DNS 解析", rows))

    # ---- 站点 ----
    rows = [
        ("HTTP 状态", val("http", httpa.get("status") if httpa else None)),
        ("HTTPS 状态", val("http", httpsa.get("status") if httpsa else None)),
        ("最终地址", val("http", h.get("final_url"))),
        ("页面标题", val("http", h.get("title"))),
        ("Server", val("http", h.get("server"))),
        ("页面大小", val("http", h.get("len"))),
        ("Body MD5", val("http", h.get("body_md5"))),
        ("favicon hash", val("http", h.get("favicon_hash"))),
        ("特征词", val("http", _join(h.get("features")))),
        ("外链域名", val("http", _join((h.get("out_domains") or [])[:10]))),
    ]
    S.append(("站点信息", rows))

    # ---- 证书 ----
    rows = [
        ("Subject", val("cert", cert.get("subject"))),
        ("签发者", val("cert", cert.get("issuer_org") or cert.get("issuer"))),
        ("生效", val("cert", cert.get("not_before"))),
        ("到期", val("cert", cert.get("not_after"))),
        ("SAN", val("cert", _join(cert.get("san")))),
        ("SHA256", val("cert", cert.get("sha256"))),
    ]
    S.append(("TLS 证书", rows))

    # ---- IP ----
    rows = [
        ("IP 地址", val("ip", ip0.get("ip"))),
        ("ASN", val("ip", ("%s %s" % (ip0.get("asn") or "",
                                       ip0.get("as_name") or "")).strip())),
        ("地理位置", val("ip", " ".join(x for x in (ip0.get("country"),
                                                  ip0.get("region"),
                                                  ip0.get("city")) if x))),
        ("ISP", val("ip", ip0.get("isp"))),
        ("组织", val("ip", ip0.get("org"))),
        ("反向 DNS", val("ip", ip0.get("ptr"))),
        ("开放端口", val("ip", _join(ip0.get("open_ports")))),
        ("同 IP 其他域名", val("ip", _join((ip0.get("reverse_ip") or [])[:10]))),
    ]
    S.append(("IP 情报", rows))

    # ---- 载荷设施 ----
    dls = h.get("download_links") or []
    bks = h.get("buckets") or []
    nds = h.get("netdisks") or []
    gws = h.get("gateways") or []
    dpg = h.get("download_pages") or []
    lure = h.get("lure_words") or []
    refs = h.get("refs_official") or []

    rows = []
    # 直链可执行
    for i in range(3):
        rows.append(("直链载荷 %d" % (i + 1),
                     val("http", dls[i] if i < len(dls) else None)))
    # 网盘（标签固定，平台名放值里，避免动态标签导致控件匹配失败）
    for i in range(4):
        if i < len(nds):
            n = nds[i]
            show = "[%s] %s" % (n.get("netdisk", "网盘"), n["url"])
            if n.get("via"):
                show += "  （经网关）"
            rows.append(("网盘 %d" % (i + 1), val("http", show)))
        else:
            rows.append(("网盘 %d" % (i + 1), val("http", None)))
    # 网关
    for i in range(3):
        if i < len(gws):
            g = gws[i]
            tgt = g.get("target")
            rows.append(("跳转网关 %d" % (i + 1),
                         val("http", (g["url"] + ("  →  " + tgt if tgt else ""))
                             if g.get("url") else None)))
        else:
            rows.append(("跳转网关 %d" % (i + 1), val("http", None)))
    # 存储桶
    for i in range(2):
        rows.append(("存储桶 %d" % (i + 1),
                     val("http", bks[i] if i < len(bks) else None)))
    # 下载页
    for i in range(2):
        rows.append(("下载页 %d" % (i + 1),
                     val("http", dpg[i] if i < len(dpg) else None)))
    # 诱导文案
    rows.append(("诱导文案", val("http", "、".join(lure) if lure else None)))
    # 引用真官网
    if refs:
        txt = "; ".join("%s → %s" % (r.get("brand"), r.get("host")) for r in refs[:3])
        rows.append(("引用真官网", val("http", txt)))
    else:
        rows.append(("引用真官网", val("http", None)))

    S.append(("载荷设施", rows))

    # ---- 载荷分析（VT）----
    pa = r.get("payload_analysis") or []
    if pa:
        prow = []
        for i, x in enumerate(pa[:4], 1):
            v = x.get("vt") or {}
            st = v.get("stats") or {}
            if v.get("found"):
                score = "%d/%d 报毒" % (st.get("malicious", 0), st.get("total", 0))
            elif v.get("error"):
                score = v["error"][:24]
            else:
                score = "无记录"
            prow.append(("载荷 %d 文件" % i,
                         "%s（%s %s）" % ((x.get("filename") or "")[:26],
                                          (x.get("kind") or ""),
                                          ("%.1fMB" % (x.get("size", 0) / 1048576))
                                          if x.get("size") else "-")))
            prow.append(("载荷 %d SHA256" % i, (x.get("sha256") or "-")[:48]))
            prow.append(("载荷 %d VT" % i, score))
            if v.get("label"):
                prow.append(("载荷 %d 威胁类型" % i, v["label"]))
            if x.get("uploaded"):
                prow.append(("载荷 %d 已上传" % i, "是"))
            prow.append(("载荷 %d 本地" % i,
                         "已删除" if x.get("deleted") else "未删除"))
        S.append(("载荷分析", prow))

    # ---- 多节点 ----
    if mn:
        rows = [
            ("是否 CDN", val("mn", ("是" if mn.get("is_cdn") else "否"))),
            ("CDN 厂商", val("mn", _join(["%s×%d" % (k, v) for k, v
                                         in (mn.get("cdn_names") or {}).items()]))),
            ("不同 IP 数", val("mn", len(mn.get("ip_pool") or {}))),
            ("疑似源站", val("mn", _join(["%s(%d节点)" % (s["ip"], s["count"])
                                        for s in (mn.get("suspects") or [])]))),
        ]
    else:
        rows = [(k, "") for k in ("是否 CDN", "CDN 厂商", "不同 IP 数", "疑似源站")]
    S.append(("多节点", rows))

    # ---- 风险依据 ----
    reasons = risk.get("reasons") or []
    rows = []
    for i in range(6):
        rows.append(("依据 %d" % (i + 1),
                     val("score", reasons[i] if i < len(reasons) else None)))
    S.append(("风险依据", rows))

    return S


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Domain Intel - 域名情报采集")
        self.geometry("1200x860")

        self.results = []
        self.by_domain = {}
        self.stats = {}
        self.files = {}
        self.stop_flag = False
        self.working = False
        self.msg_q = queue.Queue()
        self.done_stages = set()
        self.live = None
        self.live_state = {}      # domain -> {snapshot, done_stages, status}          # 正在探测的临时结果

        self._value_labels = {}
        self._build()
        self._render_placeholder()
        self.after(100, self._poll)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ================= 界面 =================
    def _build(self):
        f1 = ttk.LabelFrame(self, text="域名列表（每行一个）")
        f1.pack(fill="x", padx=6, pady=4)

        self.txt_in = scrolledtext.ScrolledText(f1, height=4, wrap="none")
        self.txt_in.pack(fill="x", padx=4, pady=4)
        self.txt_in.insert("1.0", "# 每行一个域名\n")

        fb = ttk.Frame(f1)
        fb.pack(fill="x", padx=4, pady=(0, 4))
        self.v_auth = tk.BooleanVar(value=True)
        self.v_multi = tk.BooleanVar(value=True)
        self.v_cert = tk.BooleanVar(value=True)
        self.v_port = tk.BooleanVar(value=True)
        self.v_revip = tk.BooleanVar(value=False)
        self.v_sub = tk.BooleanVar(value=False)
        self.v_mnode = tk.BooleanVar(value=False)
        self.v_vt = tk.BooleanVar(value=False)
        for txt, var in [("权威验证", self.v_auth), ("多轮DNS", self.v_multi),
                         ("TLS证书", self.v_cert), ("端口扫描", self.v_port),
                         ("同IP反查", self.v_revip), ("子域枚举", self.v_sub),
                         ("多节点", self.v_mnode), ("VT分析", self.v_vt)]:
            ttk.Checkbutton(fb, text=txt, variable=var).pack(side="left", padx=(0, 8))
        ttk.Label(fb, text="并发").pack(side="left", padx=(8, 2))
        self.v_workers = tk.IntVar(value=5)
        ttk.Spinbox(fb, from_=1, to=12, width=4,
                    textvariable=self.v_workers).pack(side="left")
        ttk.Button(fb, text="导入", width=6,
                   command=self._load_file).pack(side="left", padx=(10, 2))
        ttk.Button(fb, text="清空", width=6, command=self._clear).pack(side="left")

        f2 = ttk.Frame(self)
        f2.pack(fill="x", padx=6, pady=2)
        self.btn_start = ttk.Button(f2, text="开始探测", width=12, command=self._start)
        self.btn_start.pack(side="left")
        self.btn_stop = ttk.Button(f2, text="停止", width=8, command=self._stop,
                                   state="disabled")
        self.btn_stop.pack(side="left", padx=4)
        ttk.Button(f2, text="导出报告", width=10,
                   command=self._export_menu).pack(side="left", padx=4)
        ttk.Button(f2, text="打开输出目录", width=12,
                   command=lambda: self._open(OUT_DIR)).pack(side="left", padx=4)
        ttk.Button(f2, text="CT 拓线", width=8,
                   command=self._open_ct).pack(side="left", padx=4)
        ttk.Button(f2, text="分析载荷", width=10,
                   command=self._analyze_payloads).pack(side="left", padx=4)
        ttk.Button(f2, text="生成举报邮件", width=14,
                   command=self._gen_abuse).pack(side="left", padx=4)

        # 进度 + 阶段
        f3 = ttk.LabelFrame(self, text="进度")
        f3.pack(fill="x", padx=6, pady=4)

        r1 = ttk.Frame(f3)
        r1.pack(fill="x", padx=4, pady=(4, 2))
        ttk.Label(r1, text="总体", width=6).pack(side="left")
        self.pb_total = ttk.Progressbar(r1, mode="determinate", length=420)
        self.pb_total.pack(side="left", padx=4)
        self.lbl_total = ttk.Label(r1, text="0 / 0", width=14)
        self.lbl_total.pack(side="left", padx=4)

        r2 = ttk.Frame(f3)
        r2.pack(fill="x", padx=4, pady=2)
        ttk.Label(r2, text="当前", width=6).pack(side="left")
        self.lbl_cur = ttk.Label(r2, text="-", anchor="w")
        self.lbl_cur.pack(side="left", padx=4, fill="x", expand=True)

        r3 = ttk.Frame(f3)
        r3.pack(fill="x", padx=4, pady=(2, 4))
        ttk.Label(r3, text="阶段", width=6).pack(side="left")
        self.stage_lb = {}
        for k, name in STAGES:
            lb = tk.Label(r3, text=name, width=10, relief="solid", bd=1,
                          bg="white", fg="#333333")
            lb.pack(side="left", padx=2)
            self.stage_lb[k] = lb

        # 域名选择
        f4 = ttk.Frame(self)
        f4.pack(fill="x", padx=6, pady=(2, 2))
        ttk.Label(f4, text="选中域名").pack(side="left")
        self.cmb = ttk.Combobox(f4, state="readonly", width=48)
        self.cmb.pack(side="left", padx=6)
        self.cmb.bind("<<ComboboxSelected>>", self._on_select)
        ttk.Button(f4, text="上一个", width=8,
                   command=lambda: self._step(-1)).pack(side="left", padx=2)
        ttk.Button(f4, text="下一个", width=8,
                   command=lambda: self._step(1)).pack(side="left", padx=2)
        self.lbl_pos = ttk.Label(f4, text="")
        self.lbl_pos.pack(side="left", padx=8)


        # 字段区：可滚动，标签在外，白色格子放值
        outer = ttk.LabelFrame(self, text="字段详情")
        outer.pack(fill="both", expand=True, padx=6, pady=(2, 4))

        style_bg = ttk.Style().lookup("TFrame", "background") or "SystemButtonFace"

        self.canvas = tk.Canvas(outer, borderwidth=0, highlightthickness=0,
                                bg=style_bg)
        vsb = ttk.Scrollbar(outer, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)

        self.grid_frame = tk.Frame(self.canvas, bg=style_bg)
        self._canvas_win = self.canvas.create_window(
            (0, 0), window=self.grid_frame, anchor="nw")

        def _on_frame_conf(e):
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))

        def _on_canvas_conf(e):
            # 内嵌 frame 宽度跟随画布，实现横向铺满
            self.canvas.itemconfigure(self._canvas_win, width=e.width)

        self.grid_frame.bind("<Configure>", _on_frame_conf)
        self.canvas.bind("<Configure>", _on_canvas_conf)

        def _wheel(e):
            self.canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
        self.canvas.bind_all("<MouseWheel>", _wheel)

        # 结果表
        f6 = ttk.LabelFrame(self, text="结果列表（双击同步到上方）")
        f6.pack(fill="x", padx=6, pady=(0, 4))
        cols = ("idx", "domain", "score", "level", "ips", "registrant", "title")
        heads = ("#", "域名", "评分", "等级", "解析IP", "注册人", "页面标题")
        widths = (36, 230, 50, 56, 160, 80, 240)
        wrap = ttk.Frame(f6)
        wrap.pack(fill="both", expand=True, padx=4, pady=4)

        self.tree = ttk.Treeview(wrap, columns=cols, show="headings", height=5)
        for c, hh, w in zip(cols, heads, widths):
            self.tree.heading(c, text=hh)
            self.tree.column(c, width=w, anchor="w",
                             stretch=(c in ("domain", "title")))
        vsb2 = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb2.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb2.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", self._on_tree_dbl)

        self.status = ttk.Label(self, text="就绪", anchor="w", relief="sunken")
        self.status.pack(fill="x", side="bottom")# ================= 字段渲染 =================
    def _render_placeholder(self):
        """无选中域名时，把字段区按骨架画出来（值留空）"""
        sections = build_sections({"domain": "", "risk": {}, "dns": {}}, set())
        self._draw_sections(sections)

    def _draw_sections(self, sections):
        """
        标签在格子外，白色格子内只放值。
        双列均匀分布：左侧列 标签+格子，右侧列 标签+格子。
        """
        for w in self.grid_frame.winfo_children():
            w.destroy()
        self._value_labels = {}

        LABEL_W = 15
        row = 0

        for title, rows in sections:
            # 分区标题（通栏）
            t = tk.Label(self.grid_frame, text=title, anchor="w",
                         font=("", 9, "bold"), padx=4, pady=3)
            t.grid(row=row, column=0, columnspan=4, sticky="ew", pady=(10, 2))
            row += 1

            half = (len(rows) + 1) // 2
            for i, (label, value) in enumerate(rows):
                block = 0 if i < half else 1
                r = row + (i if block == 0 else i - half)
                base_col = block * 2

                lb = tk.Label(self.grid_frame, text=label, anchor="w",
                              width=LABEL_W, font=("", 9))
                lb.grid(row=r, column=base_col, sticky="w", padx=(4, 2), pady=1)

                v = "" if value is None else str(value)
                ent = tk.Entry(self.grid_frame, relief="solid", bd=1,
                               font=("", 9), bg="white",
                               readonlybackground="white",
                               disabledbackground="white")
                ent.insert(0, v)
                ent.config(state="readonly")
                ent.grid(row=r, column=base_col + 1, sticky="ew",
                         padx=(0, 10), pady=1, ipady=2)
                self._value_labels[(title, label)] = ent

            row += half

        # 左列：标签固定宽、格子拉伸；右列同理
        self.grid_frame.columnconfigure(0, weight=0)
        self.grid_frame.columnconfigure(1, weight=1)
        self.grid_frame.columnconfigure(2, weight=0)
        self.grid_frame.columnconfigure(3, weight=1)

    def _update_values(self, sections):
        """只更新值，不重建控件"""
        if not getattr(self, "_value_labels", None):
            self._draw_sections(sections)
        for title, rows in sections:
            for label, value in rows:
                ent = self._value_labels.get((title, label))
                if ent is None:
                    continue
                v = "" if value is None else str(value)
                if ent.get() == v:
                    continue
                ent.config(state="normal")
                ent.delete(0, "end")
                ent.insert(0, v)
                ent.config(state="readonly")

    # ================= 阶段指示 =================
    def _reset_stages(self):
        for k, lb in self.stage_lb.items():
            lb.config(text=STAGE_NAME[k], bg="white", fg="#333333")

    def _set_stage(self, key):
        cur = STAGE_ORDER.get(key, -1)
        for k, lb in self.stage_lb.items():
            i = STAGE_ORDER[k]
            if i < cur:
                lb.config(text=STAGE_NAME[k], bg=C_DONE)
            elif i == cur:
                lb.config(text=STAGE_NAME[k], bg=C_RUN)
            else:
                lb.config(text=STAGE_NAME[k], bg="white")

    def _finish_stages(self):
        for k, lb in self.stage_lb.items():
            lb.config(text=STAGE_NAME[k], bg=C_DONE)

    def _set_stage_running(self, key):
        """把某阶段标为进行中，之前的标为完成，之后保持白"""
        cur = STAGE_ORDER.get(key, -1)
        for k, lb in self.stage_lb.items():
            i = STAGE_ORDER[k]
            if k in self.done_stages:
                lb.config(bg=C_DONE)
            elif i == cur:
                lb.config(bg=C_RUN)
            elif i < cur:
                lb.config(bg=C_DONE)
            else:
                lb.config(bg="white")

    def _set_stage_done(self, key):
        lb = self.stage_lb.get(key)
        if lb:
            lb.config(bg=C_DONE)

    def _on_progress(self, domain, key, snapshot):
        """后台线程推送：只更新状态，不动界面"""
        st = self.live_state.setdefault(
            domain, {"snapshot": {}, "done_stages": set(), "status": "run"})
        if snapshot is not None:
            merged = dict(st.get("snapshot") or {})
            merged.update(snapshot)
            merged.setdefault("domain", domain)
            st["snapshot"] = merged
            st["done_stages"].add(key)
            st["status"] = "run"
        else:
            st["status"] = "run"

    def _on_domain_done(self, r):
        """单个域名跑完：写入 live_state，状态标完成"""
        d = r.get("domain")
        st = self.live_state.setdefault(
            d, {"snapshot": {}, "done_stages": set(), "status": "run"})
        merged = dict(st.get("snapshot") or {})
        merged.update(r)
        merged["domain"] = d
        st["snapshot"] = merged
        st["done_stages"] = {k for k, _ in STAGES}
        st["status"] = "done"

    def _refresh_view(self):
        """把当前选中域名的状态渲染到字段区（扫描中也能看）"""
        d = self._cur_domain()
        if not d:
            return
        st = self.live_state.get(d)
        if not st:
            return

        snap = dict(st.get("snapshot") or {})
        snap.setdefault("domain", d)
        done = set(st.get("done_stages") or set())

        sections = build_sections(snap, done)
        self._update_values(sections)

        # 阶段条同步为该域名的状态
        if st.get("status") == "done":
            self._finish_stages()
        else:
            done_list = sorted(done, key=lambda x: STAGE_ORDER.get(x, 99))
            self._apply_stage_set(done)

        # 状态提示
        if st.get("status") == "done":
            risk = snap.get("risk") or {}
            self.status.config(text="%s 已完成 · %s %s"
                               % (d, risk.get("level", ""), risk.get("score", "")))
        else:
            done_names = [STAGE_NAME[k] for k in
                          sorted(done, key=lambda x: STAGE_ORDER.get(x, 99))]
            self.status.config(text="%s 进行中 · 已完成：%s"
                               % (d, "、".join(done_names) if done_names else "（开始中）"))

    def _apply_stage_set(self, done_set):
        """按完成集合渲染阶段条（最后一个完成的之后一格标为进行中）"""
        done_list = sorted(done_set, key=lambda x: STAGE_ORDER.get(x, 99))
        running = None
        if done_list:
            last = STAGE_ORDER[done_list[-1]]
            nxt = [k for k, i in STAGE_ORDER.items() if i == last + 1]
            running = nxt[0] if nxt else None
        for k, lb in self.stage_lb.items():
            if k in done_set:
                lb.config(bg=C_DONE, fg="#000000")
            elif k == running:
                lb.config(bg=C_RUN, fg="#000000")
            else:
                lb.config(bg="white", fg="#888888")

    def _set_selector_to(self, domain):
        """把下拉框切到指定域名"""
        vals = self.cmb["values"]
        for i, v in enumerate(vals):
            if v.startswith(domain + "  "):
                self.cmb.current(i)
                return True
        return False

    def _rebuild_selector(self):
        """重建下拉项，给每个域名加状态标记"""
        cur = self._cur_domain()
        vals = []
        # 完成的排前面（按分数），跑动的排后面
        done_items = []
        run_items = []
        for d, st in self.live_state.items():
            snap = st.get("snapshot") or {}
            risk = snap.get("risk") or {}
            if st.get("status") == "done":
                done_items.append((-(risk.get("score") or 0), d,
                                   "%s  [%s %s]" % (d, risk.get("level", ""),
                                                    risk.get("score", ""))))
            else:
                done_n = len(st.get("done_stages") or [])
                run_items.append((d, "%s  [跑动中 %d/%d]"
                                  % (d, done_n, len(STAGES))))
        done_items.sort()
        vals = [x[2] for x in done_items] + [x[1] for x in run_items]

        self.cmb["values"] = vals
        if cur:
            for i, v in enumerate(vals):
                if v.startswith(cur + "  "):
                    self.cmb.current(i)
                    return

    # ================= 动作 =================
    def _load_file(self):
        p = filedialog.askopenfilename(
            title="选择域名列表",
            filetypes=[("文本文件", "*.txt"), ("CSV", "*.csv"), ("所有文件", "*.*")])
        if not p:
            return
        try:
            txt = Path(p).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            txt = Path(p).read_text(encoding="gbk", errors="ignore")
        self.txt_in.delete("1.0", "end")
        self.txt_in.insert("1.0", txt)
        self.status.config(text="已导入 %s（%d 个域名）"
                           % (Path(p).name, len(parse_domains(txt))))

    def _clear(self):
        if self.working:
            return
        self.txt_in.delete("1.0", "end")
        self.tree.delete(*self.tree.get_children())
        self.results, self.by_domain, self.stats, self.files = [], {}, {}, {}
        self.cmb["values"] = []
        self.cmb.set("")
        self.pb_total["value"] = 0
        self.lbl_total.config(text="0 / 0")
        self.lbl_cur.config(text="-")
        self.lbl_pos.config(text="")
        self.done_stages = set()
        self._reset_stages()
        self._render_placeholder()
        self.status.config(text="就绪")

    def _start(self):
        if self.working:
            return
        domains = parse_domains(self.txt_in.get("1.0", "end"))
        if not domains:
            messagebox.showwarning("提示", "未解析出有效域名")
            return

        self.tree.delete(*self.tree.get_children())
        self.results, self.by_domain, self.files = [], {}, {}
        self.done_stages = set()
        self._user_picked = False
        self.live_state = {}
        self.stop_flag = False
        self.working = True
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.cmb["values"] = []
        self.cmb.set("")
        self.pb_total["maximum"] = len(domains)
        self.pb_total["value"] = 0
        self.lbl_total.config(text="0 / %d" % len(domains))
        self._reset_stages()
        self._render_placeholder()
        self.status.config(text="开始探测 %d 个域名" % len(domains))

        options = {
            "auth_check": self.v_auth.get(),
            "multi_round": self.v_multi.get(),
            "cert": self.v_cert.get(),
            "port_scan": self.v_port.get(),
            "reverse_ip": self.v_revip.get(),
            "subdomain": self.v_sub.get(),
            "multi_node": self.v_mnode.get(),
            "vt_analysis": self.v_vt.get(),
        }
        self._vt_options = dict(options)
        threading.Thread(target=self._worker,
                         args=(domains, options, self.v_workers.get()),
                         daemon=True).start()

    def _worker(self, domains, options, workers):
        def stage_cb(domain, key, snapshot=None):
            self.msg_q.put(("stage", domain, key, snapshot))

        def one(d):
            if self.stop_flag:
                return None
            return probe_with_stage(d, options, stage_cb)

        try:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            results = []
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futs = {ex.submit(one, d): d for d in domains}
                done = 0
                for f in as_completed(futs):
                    if self.stop_flag:
                        break
                    try:
                        r = f.result()
                    except Exception as e:
                        r = {"domain": futs[f], "error": str(e)[:150],
                             "risk": {"score": 0, "level": "探测失败",
                                      "reasons": [str(e)[:100]]}}
                    done += 1
                    if r:
                        results.append(r)
                        self.msg_q.put(("row", r, done, len(domains)))

            order = {d: i for i, d in enumerate(domains)}
            results.sort(key=lambda x: order.get(x["domain"], 9999))
            from collections import Counter
            lv = Counter(r.get("risk", {}).get("level", "未知") for r in results)
            stats = {
                "total": len(results), "by_level": dict(lv),
                "alive": sum(1 for r in results if (r.get("dns") or {}).get("A")),
                "dynamic": sum(1 for r in results
                               if (r.get("dns_multi") or {}).get("dynamic")),
                "with_payload": sum(1 for r in results
                                    if (r.get("http_best") or {}).get("download_links")),
                "elapsed": round(sum(r.get("elapsed", 0) for r in results), 1),
            }
            self.msg_q.put(("done", results, stats))
        except Exception:
            self.msg_q.put(("error", traceback.format_exc()[:900]))

    def _stop(self):
        self.stop_flag = True
        self.status.config(text="正在停止…")

    def _poll(self):
        touched = False
        try:
            # 一次最多处理 200 条，避免主线程被淹没
            for _ in range(200):
                m = self.msg_q.get_nowait()
                k = m[0]
                if k == "stage":
                    domain, key = m[1], m[2]
                    snap = m[3] if len(m) > 3 else None
                    self._on_progress(domain, key, snap)
                    touched = True
                elif k == "row":
                    _, r, done, total = m
                    self._add_row(r)
                    self.pb_total["value"] = done
                    self.lbl_total.config(text="%d / %d" % (done, total))
                    touched = True
                elif k == "done":
                    self._on_done(m[1], m[2])
                elif k == "files":
                    self.files = m[1]
                    self.status.config(text="报告已生成，可用「导出报告」另存")
                elif k == "payload_item":
                    _, i, total, domain, url = m
                    self.status.config(text="分析载荷 %d/%d  %s" % (i, total, domain))
                elif k == "payload_stage":
                    _, stage, url = m
                    label = {"download": "下载中", "vt_query": "查VT",
                             "vt_upload": "上传VT", "vt_wait": "等结果",
                             "delete": "删除中"}.get(stage, stage)
                    self.status.config(text="%s → %s" % (label, url[:70]))
                elif k == "payload_done":
                    rescore = m[2] if len(m) > 2 else False
                    self._on_payload_done(m[1], rescore)
                elif k == "payload_error":
                    self.btn_start.config(state="normal")
                    self.status.config(text="载荷分析出错")
                    messagebox.showerror("载荷分析出错", m[1])
                elif k == "error":
                    self._on_error(m[1])
        except queue.Empty:
            pass

        # 统一刷新：只刷当前选中的域名，不做任何自动跳转
        if touched:
            first_time = not self.cmb["values"]
            self._rebuild_selector()
            # 首次出现结果时，默认选中第一个
            if first_time and self.cmb["values"]:
                self.cmb.current(0)
            d = self._cur_domain()
            st = self.live_state.get(d) if d else None
            if st and st.get("status") == "run":
                self.lbl_cur.config(text="%s  ·  %d/%d 阶段"
                                    % (d, len(st.get("done_stages") or []),
                                       len(STAGES)))
            self._refresh_view()
        self.after(100, self._poll)

    def _add_row(self, r):
        risk = r.get("risk") or {}
        w = r.get("whois") or {}
        dns = r.get("dns") or {}
        h = r.get("http_best") or {}
        idx = len(self.results) + 1
        self.results.append(r)
        self.by_domain[r["domain"]] = r
        self.tree.insert("", "end", iid=r["domain"], values=(
            idx, r["domain"], risk.get("score", 0), risk.get("level", ""),
            ",".join(dns.get("A", [])[:2]) or "-",
            (w.get("registrant") or "-")[:10],
            (h.get("title") or "-")[:36]))
        self.tree.yview_moveto(1.0)
        self._on_domain_done(r)

        # 实时刷新正在显示的域名
        d = self._cur_domain()
        if d == r["domain"]:
            self.done_stages = {k for k, _ in STAGES}
            self._update_values(build_sections(r, self.done_stages))

    def _on_done(self, results, stats):
        self.working = False
        self.results = sorted(results,
                              key=lambda y: -(y.get("risk") or {}).get("score", 0))
        self.by_domain = {r["domain"]: r for r in self.results}
        self.stats = stats
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self._finish_stages()
        self.lbl_cur.config(text="-")
        self.done_stages = {k for k, _ in STAGES}

        self.tree.delete(*self.tree.get_children())
        for i, r in enumerate(self.results, 1):
            risk = r.get("risk") or {}
            w = r.get("whois") or {}
            dns = r.get("dns") or {}
            h = r.get("http_best") or {}
            self.tree.insert("", "end", iid=r["domain"], values=(
                i, r["domain"], risk.get("score", 0), risk.get("level", ""),
                ",".join(dns.get("A", [])[:2]) or "-",
                (w.get("registrant") or "-")[:10],
                (h.get("title") or "-")[:36]))

        # 全部完成，live_state 同步为最终结果
        for r in self.results:
            self._on_domain_done(r)
        self._rebuild_selector()
        if self.cmb["values"]:
            self.cmb.current(0)
            self._refresh_view()

        lv = stats.get("by_level", {})
        self.status.config(
            text="完成 %d 个 | 高危 %d 可疑 %d 低危 %d 正常 %d 失效 %d | 有载荷 %d" % (
                stats.get("total", 0), lv.get("高危", 0), lv.get("可疑", 0),
                lv.get("低危", 0), lv.get("正常", 0),
                lv.get("已失效", 0) + lv.get("未注册", 0),
                stats.get("with_payload", 0)))

        threading.Thread(target=self._gen_reports,
                         args=(self.results, stats), daemon=True).start()

        # 勾选了 VT 分析 → 自动跑载荷下载 + VT
        if self.v_vt.get() and getattr(self, "_vt_options", {}).get("vt_analysis"):
            self.after(300, self._auto_vt_analysis)

    def _gen_reports(self, results, stats):
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        files = {}
        jobs = [
            ("docx", "域名情报报告_%s.docx" % ts, docx_gen.build_docx),
            ("xlsx", "域名情报数据_%s.xlsx" % ts, xlsx_gen.build_xlsx),
            ("md", "域名情报报告_%s.md" % ts, xlsx_gen.build_markdown),
            ("json", "域名情报数据_%s.json" % ts, xlsx_gen.build_json),
        ]
        for kind, fn, builder in jobs:
            try:
                p = OUT_DIR / fn
                builder(results, stats, str(p))
                files[kind] = p
            except Exception as e:
                print("%s 生成失败: %s" % (kind, e))
        self.msg_q.put(("files", files))

    def _on_error(self, tb):
        self.working = False
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.status.config(text="出错")
        messagebox.showerror("运行出错", tb)

    # ================= 选择 =================
    def _on_tree_dbl(self, event):
        item = self.tree.identify_row(event.y)
        if not item:
            return
        for j, v in enumerate(self.cmb["values"]):
            if v.startswith(item + "  ["):
                self.cmb.current(j)
                self._on_select(None)
                break

    def _cur_domain(self):
        s = self.cmb.get()
        return s.split("  [")[0].strip() if s else None

    def _on_select(self, event):
        d = self._cur_domain()
        if not d:
            return
        vals = self.cmb["values"]
        self.lbl_pos.config(text="第 %d / %d 个" % (self.cmb.current() + 1, len(vals)))
        self._refresh_view()

    def _step(self, delta):
        vals = self.cmb["values"]
        if not vals:
            return
        i = max(0, self.cmb.current())
        ni = max(0, min(len(vals) - 1, i + delta))
        self.cmb.current(ni)
        self._on_select(None)

    # ================= 导出 =================
    def _auto_vt_analysis(self):
        """探测完成后自动执行：下载载荷 → 查VT → 删除 → 重新评分 → 重出报告"""
        if not self.results:
            return

        payloads = payload_mod.collect_payloads(self.results, only_risky=True)
        if not payloads:
            self.status.config(text="VT分析：未发现可下载的载荷链接")
            return

        self.status.config(text="VT分析：共 %d 个载荷，开始下载…" % len(payloads))

        def worker():
            def item_cb(i, total, domain, url):
                self.msg_q.put(("payload_item", i, total, domain, url))

            def prog_cb(stage, url):
                self.msg_q.put(("payload_stage", stage, url))

            try:
                res = payload_mod.analyze_many(payloads, auto_upload=True,
                                               progress_cb=prog_cb,
                                               item_cb=item_cb)
                self.msg_q.put(("payload_done", res, True))
            except Exception:
                import traceback
                self.msg_q.put(("payload_error", traceback.format_exc()[:600]))

        import threading
        threading.Thread(target=worker, daemon=True).start()

    def _analyze_payloads(self):
        """下载载荷 → 计算哈希 → 查 VT → 上传（如无记录）→ 删除"""
        if not self.results:
            messagebox.showwarning("提示", "请先完成探测")
            return

        payloads = payload_mod.collect_payloads(self.results, only_risky=True)
        if not payloads:
            messagebox.showinfo("提示", "未发现可分析的载荷链接")

            # 仍提示网盘情况
            nd_count = sum(len((r.get("http_best") or {}).get("netdisks") or [])
                           for r in self.results)
            if nd_count:
                messagebox.showinfo(
                    "说明", "发现 %d 条网盘分发链接（百度/UC/夸克等）。\n"
                    "网盘链接无法直接下载，需人工处理。" % nd_count)
            return

        if not messagebox.askyesno(
                "确认",
                "即将对 %d 个载荷链接执行：\n"
                "  1. 下载到 output/samples/（上限 600MB）\n"
                "  2. 计算 SHA256\n"
                "  3. 查询 VirusTotal（无记录则自动上传）\n"
                "  4. 分析完成后删除本地样本\n\n"
                "请确认已将 samples 目录加入杀软白名单。\n继续？" % len(payloads)):
            return

        self.status.config(text="开始分析 %d 个载荷…" % len(payloads))
        self.btn_start.config(state="disabled")
        self._payload_results = []

        def worker():
            def item_cb(i, total, domain, url):
                self.msg_q.put(("payload_item", i, total, domain, url))

            def prog_cb(stage, url):
                self.msg_q.put(("payload_stage", stage, url))

            try:
                res = payload_mod.analyze_many(payloads, auto_upload=True,
                                               progress_cb=prog_cb,
                                               item_cb=item_cb)
                self.msg_q.put(("payload_done", res))
            except Exception:
                import traceback
                self.msg_q.put(("payload_error", traceback.format_exc()[:600]))

        import threading
        threading.Thread(target=worker, daemon=True).start()

    def _on_payload_done(self, results, rescore=False):
        self._payload_results = results
        self.btn_start.config(state="normal")

        # 把载荷结果挂到域名，重新评分
        if rescore:
            from core import scoring
            for x in results:
                d = x.get("domain")
                if d and d in self.by_domain:
                    self.by_domain[d].setdefault("payload_analysis", []).append(x)
            for r in self.results:
                if r.get("payload_analysis"):
                    r["risk"] = scoring.score_v2(r)
            # 刷新列表与下拉
            self.results.sort(key=lambda y: -(y.get("risk") or {}).get("score", 0))
            self._rebuild_selector()
            self._refresh_view()
            # 重新生成报告
            from collections import Counter
            lv = Counter((r.get("risk") or {}).get("level", "未知") for r in self.results)
            self.stats["by_level"] = dict(lv)
            import threading
            threading.Thread(target=self._gen_reports,
                             args=(self.results, self.stats), daemon=True).start()

        ok_n = sum(1 for x in results if (x.get("vt") or {}).get("found"))
        mal_n = sum(1 for x in results
                    if ((x.get("vt") or {}).get("stats") or {}).get("malicious", 0) > 0)
        up_n = sum(1 for x in results if x.get("uploaded"))
        del_n = sum(1 for x in results if x.get("deleted"))

        msg = ("载荷分析完成：共 %d 个\n"
               "  VT 命中 %d 个，其中报毒 %d 个\n"
               "  新上传 %d 个\n"
               "  本地已删除 %d 个" % (len(results), ok_n, mal_n, up_n, del_n))
        self.status.config(text=msg.replace("\n", " | "))
        messagebox.showinfo("载荷分析完成", msg)

        # 把结果挂到对应域名，并刷新视图
        for x in results:
            d = x.get("domain")
            if d and d in self.by_domain:
                self.by_domain[d].setdefault("payload_analysis", []).append(x)
        self._refresh_view()

    def _gen_abuse(self):
        """生成举报邮件草稿并打开审核窗口"""
        if not self.results:
            messagebox.showwarning("提示", "请先完成探测")
            return
        high = [r for r in self.results
                if (r.get("risk") or {}).get("level") in ("高危", "可疑")]
        if not high:
            messagebox.showinfo("提示", "没有高危/可疑域名，无需举报")
            return

        n_high = len([r for r in high
                      if (r.get("risk") or {}).get("level") == "高危"])
        if not messagebox.askyesno(
                "确认", "共 %d 个高危、%d 个可疑域名。\n生成举报邮件草稿？"
                % (n_high, len(high) - n_high)):
            return

        try:
            drafts, out_dir = abuse_mod.generate_drafts(self.results)
        except Exception as e:
            messagebox.showerror("生成失败", str(e))
            return

        if not drafts:
            messagebox.showinfo("提示", "未生成任何草稿")
            return

        self.status.config(text="已生成 %d 封草稿 → %s" % (len(drafts), out_dir))
        gui_abuse.AbuseWindow(self, drafts, out_dir,
                              on_sent=lambda: self.status.config(
                                  text="举报邮件已发送，日志见 output/abuse_drafts"))

    def _export_menu(self):
        if not self.files:
            messagebox.showwarning("提示", "报告尚未生成，请先完成探测")
            return
        m = tk.Menu(self, tearoff=0)
        for kind, name in [("docx", "Word 报告"), ("xlsx", "Excel 数据"),
                           ("md", "Markdown 文本"), ("json", "JSON 原始数据")]:
            if kind in self.files:
                m.add_command(label=name, command=lambda k=kind: self._save_as(k))
        m.add_separator()
        m.add_command(label="打开输出目录", command=lambda: self._open(OUT_DIR))
        m.tk_popup(self.winfo_pointerx(), self.winfo_pointery())

    def _save_as(self, kind):
        p = self.files.get(kind)
        if not p or not Path(p).exists():
            messagebox.showwarning("提示", "文件不存在")
            return
        target = filedialog.asksaveasfilename(
            title="另存为", initialfile=Path(p).name,
            defaultextension=Path(p).suffix,
            filetypes=[("文件", "*" + Path(p).suffix)])
        if not target:
            return
        try:
            import shutil
            shutil.copy2(p, target)
            self.status.config(text="已保存：%s" % target)
            messagebox.showinfo("完成", "已保存到:\n" + target)
        except Exception as e:
            messagebox.showerror("失败", str(e))

    def _open(self, d):
        try:
            os.startfile(str(d))
        except Exception as e:
            messagebox.showerror("失败", str(e))

    def _open_ct(self):
        CTWindow(self)

    def _on_close(self):
        if self.working:
            if not messagebox.askyesno("确认", "探测仍在进行，确定退出？"):
                return
            self.stop_flag = True
        self.destroy()


class CTWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("证书透明度日志拓线")
        self.geometry("880x600")
        self._last = []

        top = ttk.Frame(self)
        top.pack(fill="x", padx=6, pady=6)
        ttk.Label(top, text="关键词").pack(side="left")
        self.e_kw = ttk.Entry(top, width=32)
        self.e_kw.pack(side="left", padx=6)
        self.btn = ttk.Button(top, text="查询", width=8, command=self._search)
        self.btn.pack(side="left", padx=2)
        self.lbl = ttk.Label(top, text="")
        self.lbl.pack(side="left", padx=10)

        ttk.Label(self, text="CT 日志记录所有签发过的 HTTPS 证书域名，"
                             "可据此发现同系列仿冒站（crt.sh 常限流）",
                  anchor="w").pack(fill="x", padx=8)

        wrap = ttk.Frame(self)
        wrap.pack(fill="both", expand=True, padx=6, pady=6)

        self.tree = ttk.Treeview(wrap, columns=("d", "t"), show="headings")
        self.tree.heading("d", text="域名")
        self.tree.heading("t", text="首次签发")
        self.tree.column("d", width=620, anchor="w")
        self.tree.column("t", width=110, anchor="w")
        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        bot = ttk.Frame(self)
        bot.pack(fill="x", padx=6, pady=(0, 6))
        ttk.Button(bot, text="复制全部", command=self._copy_all).pack(side="left")
        ttk.Button(bot, text="填回主窗口", command=self._to_main).pack(side="left", padx=6)

    def _search(self):
        kw = self.e_kw.get().strip()
        if not kw:
            return
        self.btn.config(state="disabled")
        self.lbl.config(text="查询中…")
        self.tree.delete(*self.tree.get_children())

        def run():
            try:
                r = ct_mod.search_ct(kw, use_crtsh=True)
                self.after(0, lambda: self._fill(r))
            except Exception as e:
                self.after(0, lambda: self.lbl.config(text="失败: " + str(e)[:60]))
                self.after(0, lambda: self.btn.config(state="normal"))

        threading.Thread(target=run, daemon=True).start()

    def _fill(self, r):
        self.lbl.config(text="共 %d 个域名" % r["count"])
        self.btn.config(state="normal")
        for item in r["domains"]:
            self.tree.insert("", "end",
                             values=(item["domain"], item["first_seen"] or "-"))
        self._last = [x["domain"] for x in r["domains"]]

    def _copy_all(self):
        if not self._last:
            return
        self.clipboard_clear()
        self.clipboard_append("\n".join(self._last))
        messagebox.showinfo("已复制", "已复制 %d 个域名" % len(self._last))

    def _to_main(self):
        if not self._last:
            return
        m = self.master
        if hasattr(m, "txt_in"):
            m.txt_in.delete("1.0", "end")
            m.txt_in.insert("1.0", "\n".join(self._last))
            m.status.config(text="已填入 %d 个域名" % len(self._last))
        self.destroy()


# ================= 带阶段的探测 =================
def probe_with_stage(domain, options, stage_cb=None):
    def st(key, snapshot=None):
        if stage_cb:
            stage_cb(domain, key, snapshot)

    t0 = time.time()
    d = domain.strip().lower().rstrip(".")
    r = {"domain": d, "ts": datetime.datetime.now().isoformat(timespec="seconds")}

    if options.get("auth_check", True):
        st("auth")
        r["auth_check"] = dnsx.authoritative_check(d)
        st("auth", r)

    st("dns")
    r["dns"] = dnsx.query_records(d)
    st("dns", r)

    if options.get("multi_round", True):
        st("multi")
        r["dns_multi"] = dnsx.multi_round(d)
        st("multi", r)

    st("whois")
    try:
        r["whois"] = whoisx.whois(d)
    except Exception as e:
        r["whois"] = {"error": str(e)[:100]}
    st("whois", r)

    ips = r["dns"].get("A", [])
    if not ips and r.get("dns_multi"):
        ips = [i for i in (r["dns_multi"].get("ip_pool") or {}) if ":" not in i]

    r["cert"] = {}
    r["ip_infos"] = []
    if ips:
        st("http")
        r["http"], r["http_best"] = httpx.collect_http(d)
        st("http", r)
        if options.get("cert", True):
            st("cert")
            r["cert"] = httpx.cert_probe(d)
            st("cert", r)
        st("ip")
        for ip in ips[:2]:
            ii = ipx.ip_info(ip)
            if options.get("port_scan", True):
                ii["open_ports"] = ipx.port_scan(ip)
            if options.get("reverse_ip", False):
                ii["reverse_ip"] = ipx.reverse_ip(ip)
            r["ip_infos"].append(ii)
        st("ip", r)
    else:
        r["http"], r["http_best"] = {}, {}

    if options.get("subdomain", False):
        st("ip")
        r["subdomains"] = dnsx.subdomain_probe(d)

    if options.get("multi_node", False):
        st("mn")
        try:
            from core import multi_node as mn_mod
            r["multi_node"] = mn_mod.check_dns(d, max_nodes=15, timeout_wait=40)
        except Exception as e:
            r["multi_node"] = {"error": str(e)[:80]}
        st("mn", r)

    st("score")
    r["risk"] = probe_mod.score(r)
    r["elapsed"] = round(time.time() - t0, 1)
    st("score", r)
    return r


def r_start(r):
    return time.time()


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
