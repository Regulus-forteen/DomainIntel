# -*- coding: utf-8 -*-
"""举报邮件审核窗口（Tkinter）"""
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading


class AbuseWindow(tk.Toplevel):
    """
    草稿审核 + 发送窗口
    drafts: core.abuse.generate_drafts() 的返回值
    """

    def __init__(self, master, drafts, out_dir, on_sent=None):
        super().__init__(master)
        self.title("举报邮件审核（%d 封）" % len(drafts))
        self.geometry("1060x760")
        self.drafts = drafts
        self.out_dir = out_dir
        self.on_sent = on_sent
        self.sending = False

        self._build()
        if drafts:
            self.lb.current(0)
            self._load(0)

    def _build(self):
        top = ttk.Frame(self)
        top.pack(fill="x", padx=6, pady=6)

        ttk.Label(top, text="草稿").pack(side="left")
        self.lb = tk.Listbox(top, height=6, width=52, font=("", 9))
        self.lb.pack(side="left", padx=6)
        self.lb.bind("<<ListboxSelect>>", self._on_pick)
        for d in self.drafts:
            mark = "" if d["abuse_email"] else "  [!无邮箱]"
            self.lb.insert("end", "%s  [%d个域名]%s"
                           % (d["registrar"][:32], len(d["domains"]), mark))

        side = ttk.Frame(top)
        side.pack(side="left", fill="y", padx=6)
        ttk.Button(side, text="打开草稿目录",
                   command=self._open_dir).pack(fill="x", pady=2)
        ttk.Label(side, text="发送间隔(秒)").pack(anchor="w", pady=(8, 0))
        self.v_interval = tk.IntVar(value=25)
        ttk.Spinbox(side, from_=5, to=120, width=6,
                    textvariable=self.v_interval).pack(anchor="w")
        self.btn_send = ttk.Button(side, text="全部发送", command=self._send_all)
        self.btn_send.pack(fill="x", pady=(8, 2))
        self.btn_send_sel = ttk.Button(side, text="只发选中", command=self._send_one)
        self.btn_send_sel.pack(fill="x", pady=2)

        info = ttk.Frame(self)
        info.pack(fill="x", padx=6, pady=(0, 4))
        self.lbl_to = ttk.Label(info, text="", font=("", 9, "bold"))
        self.lbl_to.pack(side="left")
        self.lbl_src = ttk.Label(info, text="", foreground="#666")
        self.lbl_src.pack(side="left", padx=12)

        body_frame = ttk.LabelFrame(self, text="邮件正文（可直接编辑）")
        body_frame.pack(fill="both", expand=True, padx=6, pady=4)

        self.txt = scrolledtext.ScrolledText(body_frame, wrap="word",
                                             font=("Consolas", 9))
        self.txt.pack(fill="both", expand=True, padx=4, pady=4)

        bottom = ttk.Frame(self)
        bottom.pack(fill="x", padx=6, pady=(0, 6))
        self.pb = ttk.Progressbar(bottom, mode="determinate", length=300)
        self.pb.pack(side="left")
        self.lbl_status = ttk.Label(bottom, text="就绪")
        self.lbl_status.pack(side="left", padx=10)

        self.log = ttk.Treeview(self, columns=("r", "t", "s"),
                                show="headings", height=4)
        self.log.heading("r", text="注册商")
        self.log.heading("t", text="收件人")
        self.log.heading("s", text="结果")
        self.log.column("r", width=220)
        self.log.column("t", width=240)
        self.log.column("s", width=400)
        self.log.pack(fill="x", padx=6, pady=(0, 6))

    def _on_pick(self, event):
        idx = self.lb.curselection()
        if idx:
            self._load(idx[0])

    def _load(self, i):
        d = self.drafts[i]
        self.lbl_to.config(text="收件人：%s" % (d["abuse_email"] or "【未找到】"))
        self.lbl_src.config(text="来源：%s　域名：%s"
                            % (d["source"], ", ".join(d["domains"])))
        self.txt.delete("1.0", "end")
        self.txt.insert("1.0", "主题：%s\n%s\n%s" %
                        (d["subject"], "=" * 70, d["body"]))

    def _open_dir(self):
        import os
        try:
            os.startfile(self.out_dir)
        except Exception as e:
            messagebox.showerror("失败", str(e))

    def _sync_body(self, i):
        """把编辑框里的内容同步回草稿"""
        text = self.txt.get("1.0", "end")
        if "=" * 70 in text:
            head, rest = text.split("=" * 70, 1)
            if head.startswith("主题："):
                self.drafts[i]["subject"] = head[3:].strip()
            self.drafts[i]["body"] = rest.strip() + "\n"

    def _do_send(self, items):
        from core import abuse

        self.sending = True
        self.btn_send.config(state="disabled")
        self.btn_send_sel.config(state="disabled")
        self.pb["maximum"] = len(items)
        self.pb["value"] = 0

        cfg = abuse.load_mail_config()
        if not cfg:
            messagebox.showerror("错误", "未找到邮件配置 mail_config.json")
            self.sending = False
            self.btn_send.config(state="normal")
            self.btn_send_sel.config(state="normal")
            return

        log_path = self.out_dir + "/send_log.csv"

        def run():
            for n, d in enumerate(items):
                to = d.get("abuse_email")
                self.after(0, lambda n=n, d=d: self.lbl_status.config(
                    text="发送中 %d/%d → %s" % (n + 1, len(items), d["registrar"][:28])))
                if not to:
                    self.after(0, lambda d=d: self.log.insert(
                        "", "end", values=(d["registrar"][:30], "-", "跳过：无邮箱")))
                    continue
                ok, msg = abuse.send_one(cfg, to, d["subject"], d["body"])
                self.after(0, lambda d=d, to=to, ok=ok, msg=msg: self.log.insert(
                    "", "end", values=(d["registrar"][:30], to,
                                       ("成功" if ok else "失败：" + msg[:60]))))
                self.after(0, lambda n=n: self.pb.configure(value=n + 1))
                if n < len(items) - 1:
                    import time
                    import random
                    time.sleep(self.v_interval.get() + random.uniform(0, 6))

            self.after(0, self._done_send)

        threading.Thread(target=run, daemon=True).start()

    def _done_send(self):
        self.sending = False
        self.btn_send.config(state="normal")
        self.btn_send_sel.config(state="normal")
        self.lbl_status.config(text="发送完成")
        if self.on_sent:
            self.on_sent()

    def _send_all(self):
        if self.sending:
            return
        if not messagebox.askyesno(
                "确认", "即将发送 %d 封举报邮件，每封间隔 %d 秒。\n确定继续？"
                % (len(self.drafts), self.v_interval.get())):
            return
        self._do_send(self.drafts)

    def _send_one(self):
        if self.sending:
            return
        idx = self.lb.curselection()
        if not idx:
            messagebox.showwarning("提示", "请先在左侧选中一封")
            return
        i = idx[0]
        self._sync_body(i)
        d = self.drafts[i]
        if not d.get("abuse_email"):
            messagebox.showwarning("提示", "该注册商未找到 abuse 邮箱")
            return
        if not messagebox.askyesno("确认", "发送给 %s ？" % d["abuse_email"]):
            return
        self._do_send([d])