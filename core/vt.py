# -*- coding: utf-8 -*-
"""
VirusTotal API v3 封装
- 配额管理（4次/分钟，500次/天）
- 本地缓存（不重复查询）
- 支持：查哈希 / 上传小文件 / 上传大文件 / 查分析结果
"""
import json
import time
import threading
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings()

from . import settings

BASE_DIR = Path(__file__).resolve().parents[1]
CACHE_FILE = BASE_DIR / "output" / "vt_cache.json"

VT_BASE = "https://www.virustotal.com/api/v3"

_lock = threading.Lock()


def _load_cfg():
    return settings.get("virustotal") or {}


def _load_cache():
    try:
        return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_cache(c):
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(c, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


class RateLimiter:
    """4 次/分钟 + 500 次/天"""

    def __init__(self, per_minute=4, per_day=500):
        self.per_minute = per_minute
        self.per_day = per_day
        self.calls = []          # 最近一分钟的时间戳
        self.day = time.strftime("%Y-%m-%d")
        self.day_calls = 0

    def wait(self):
        with _lock:
            today = time.strftime("%Y-%m-%d")
            if today != self.day:
                self.day = today
                self.day_calls = 0
            if self.day_calls >= self.per_day:
                raise RuntimeError("VT 每日配额已用完（%d 次）" % self.per_day)

            now = time.time()
            self.calls = [t for t in self.calls if now - t < 60]
            if len(self.calls) >= self.per_minute:
                wait = 60 - (now - self.calls[0]) + 0.5
                if wait > 0:
                    time.sleep(wait)
                now = time.time()
                self.calls = [t for t in self.calls if now - t < 60]

            self.calls.append(time.time())
            self.day_calls += 1

    def stat(self):
        return {"今日已用": self.day_calls, "每日上限": self.per_day,
                "本分钟已用": len([t for t in self.calls if time.time() - t < 60])}


_limiter = RateLimiter()


def _headers(cfg=None):
    cfg = cfg or _load_cfg()
    return {"x-apikey": cfg.get("api_key", ""), "Accept": "application/json"}


def get_report(hash_value, use_cache=True):
    """
    查文件报告
    返回 {found, stats, label, names, type, size, first_seen, link, error}
    """
    out = {"hash": hash_value, "found": False, "error": None,
           "no_record": False}
    cache = _load_cache()
    if use_cache and hash_value in cache:
        out.update(cache[hash_value])
        out["from_cache"] = True
        return out

    _limiter.wait()
    try:
        r = requests.get("%s/files/%s" % (VT_BASE, hash_value),
                         headers=_headers(), timeout=30, verify=False)
        if r.status_code == 404:
            # 关键：库中无记录 ≠ 查询失败，不设 error，交给上层决定是否上传
            out["no_record"] = True
            out["error"] = None
            return out
        if r.status_code == 401:
            out["error"] = "API Key 无效"
            return out
        if r.status_code == 403:
            out["error"] = "无权限（免费版可能不支持该操作）"
            return out
        if r.status_code == 429:
            out["error"] = "触发限流"
            return out
        if r.status_code != 200:
            out["error"] = "HTTP %s" % r.status_code
            return out

        j = r.json()
        attr = (j.get("data") or {}).get("attributes") or {}
        stats = attr.get("last_analysis_stats") or {}
        tc = attr.get("popular_threat_classification") or {}

        out.update({
            "found": True,
            "stats": {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "timeout": stats.get("timeout", 0),
                "total": sum(stats.values()) if stats else 0,
            },
            "label": tc.get("suggested_threat_label") or "",
            "categories": [c.get("value") for c in
                           (tc.get("popular_threat_category") or [])],
            "names": (attr.get("names") or [])[:8],
            "type": attr.get("type_description") or "",
            "size": attr.get("size") or 0,
            "first_seen": attr.get("first_submission_date"),
            "times_submitted": attr.get("times_submitted"),
            "link": "https://www.virustotal.com/gui/file/%s" % hash_value,
        })

        # 各引擎结果（只留报毒的）
        results = attr.get("last_analysis_results") or {}
        engines = []
        for eng, v in results.items():
            if v.get("category") in ("malicious", "suspicious"):
                engines.append({"engine": eng,
                                "result": v.get("result") or "",
                                "category": v.get("category")})
        out["engines"] = engines[:30]

        cache[hash_value] = out
        _save_cache(cache)
    except Exception as e:
        out["error"] = "%s: %s" % (type(e).__name__, str(e)[:100])
    return out


def upload_file(path, timeout=300):
    """
    上传文件分析
    返回 {ok, analysis_id, error}
    """
    p = Path(path)
    if not p.exists():
        return {"ok": False, "error": "文件不存在"}

    size = p.stat().st_size
    _limiter.wait()

    try:
        if size <= 32 * 1024 * 1024:
            url = "%s/files" % VT_BASE
        else:
            # 大文件：先取专用上传地址
            r0 = requests.get("%s/files/upload_url" % VT_BASE,
                              headers=_headers(), timeout=30, verify=False)
            if r0.status_code != 200:
                return {"ok": False, "error": "获取上传地址失败 HTTP %s" % r0.status_code}
            url = r0.json().get("data")

        with open(p, "rb") as f:
            files = {"file": (p.name, f, "application/octet-stream")}
            r = requests.post(url, headers=_headers(), files=files,
                              timeout=timeout, verify=False)

        if r.status_code not in (200, 201):
            return {"ok": False, "error": "上传失败 HTTP %s: %s"
                    % (r.status_code, r.text[:100])}

        j = r.json()
        return {"ok": True, "analysis_id": (j.get("data") or {}).get("id"),
                "error": None}
    except Exception as e:
        return {"ok": False, "error": "%s: %s" % (type(e).__name__, str(e)[:100])}


def get_analysis(analysis_id, wait=300, interval=15, progress_cb=None):
    """
    轮询分析结果
    progress_cb(elapsed, total, pct, text, stats) 每轮回调
    """
    import time as _t

    total = max(1, int(wait))
    start_ts = _t.time()
    poll = max(5, min(int(interval), 30))
    last = {}

    while True:
        elapsed = _t.time() - start_ts
        pct = min(99, int(elapsed / total * 100))
        try:
            _limiter.wait()
            resp = requests.get("%s/analyses/%s" % (VT_BASE, analysis_id),
                                headers=_headers(), timeout=30, verify=False)
            if resp.status_code != 200:
                raise RuntimeError("HTTP %s" % resp.status_code)
            r = resp.json()
        except Exception as e:
            if progress_cb:
                progress_cb(elapsed, total, pct, "查询出错：%s" % str(e)[:40], last)
            if elapsed >= total:
                return {"ok": False, "completed": False,
                        "error": "查询失败：%s" % str(e)[:60]}
            _t.sleep(poll)
            continue

        attrs = r.get("data", {}).get("attributes", {}) or {}
        status = attrs.get("status")
        stats = attrs.get("stats") or {}
        last = stats

        if status == "completed":
            engines = []
            for name, res in (attrs.get("results") or {}).items():
                if res.get("category") in ("malicious", "suspicious"):
                    engines.append({"engine": name,
                                    "result": (res.get("result") or "")[:60],
                                    "category": res.get("category")})
            label = ""
            for t in (attrs.get("popular_threat_classification") or {}).get(
                    "popular_threat_name") or []:
                if t.get("value"):
                    label = t["value"]
                    break
            if progress_cb:
                progress_cb(elapsed, total, 100, "分析完成", stats)
            return {"ok": True, "completed": True, "stats": stats,
                    "engines": engines, "label": label}

        if progress_cb:
            progress_cb(elapsed, total, pct,
                        "VT 排队中（已等 %ds / 最多 %ds）" % (int(elapsed), int(total)),
                        stats)

        if elapsed >= total:
            return {"ok": True, "completed": False,
                    "error": "超过 %ds 仍未完成，请稍后手动查询" % int(total),
                    "stats": stats}

        _t.sleep(poll)



def quota_stat():
    return _limiter.stat()