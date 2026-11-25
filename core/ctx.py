# -*- coding: utf-8 -*-
"""
证书透明度（CT）日志查询 - 用于拓线发现同系列域名
主接口：crt.sh（经常抽风，带重试）
备接口：Cert Spotter
"""
import time
import json
import re

import requests
import urllib3

urllib3.disable_warnings()

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36"}


def _certspotter(query, timeout=25):
    """Cert Spotter - 比 crt.sh 稳定"""
    out = []
    try:
        r = requests.get("https://api.certspotter.com/v1/issuances",
                         params={"domain": query, "include_subdomains": "true",
                                 "expand": "dns_names"},
                         headers=UA, timeout=timeout, verify=False)
        if r.status_code == 200:
            for it in r.json():
                for n in it.get("dns_names", []):
                    n = n.lower().lstrip("*.").strip()
                    if n and "." in n:
                        out.append({"domain": n,
                                    "not_before": it.get("not_before", "")[:10]})
    except Exception:
        pass
    return out


def _crtsh(query, timeout=40, retries=2):
    """crt.sh - 经常 502/429，重试"""
    out = []
    for attempt in range(retries):
        try:
            r = requests.get("https://crt.sh/",
                             params={"q": "%%%s%%" % query, "output": "json"},
                             headers=UA, timeout=timeout, verify=False)
            if r.status_code == 200:
                for item in r.json():
                    for name in (item.get("name_value") or "").split("\n"):
                        name = name.strip().lower().lstrip("*.").strip()
                        if name and "." in name:
                            out.append({"domain": name,
                                        "not_before": (item.get("not_before") or "")[:10]})
                break
            elif r.status_code in (429, 502, 503):
                time.sleep(6 + attempt * 4)
            else:
                break
        except Exception:
            time.sleep(4)
    return out


def search_ct(keyword, use_crtsh=True):
    """
    按关键词查证书透明度日志。
    例：keyword='deepseek' 会返回所有含 deepseek 的证书域名
    返回去重后的域名列表 + 每个域名的首次签发时间
    """
    records = []
    records += _certspotter(keyword)
    if use_crtsh:
        records += _crtsh(keyword)

    seen = {}
    for r in records:
        d = r["domain"]
        if d not in seen or (r["not_before"] and r["not_before"] < seen[d]):
            seen[d] = r["not_before"]

    return {
        "keyword": keyword,
        "count": len(seen),
        "domains": sorted(
            [{"domain": k, "first_seen": v} for k, v in seen.items()],
            key=lambda x: x["first_seen"] or ""
        ),
    }


def group_by_root(domains):
    """按根域归并"""
    from collections import defaultdict
    g = defaultdict(list)
    for d in domains:
        parts = d.split(".")
        if len(parts) >= 2:
            g[".".join(parts[-2:])].append(d)
    return dict(g)