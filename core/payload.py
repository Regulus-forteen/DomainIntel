# -*- coding: utf-8 -*-
"""
载荷分析编排模块
流程：下载 → 计算哈希 → 查 VT 缓存/API → 无记录则上传并轮询 → 删除本地样本
"""
import time
import datetime

from . import sample, vt


def analyze_payload(url, idx=1, max_size=600 * 1024 * 1024,
                    auto_upload=True, wait_analysis=240, progress_cb=None):
    """
    完整分析单个载荷链接
    返回 dict：包含下载信息、哈希、VT 结果
    """
    out = {
        "url": url,
        "ts": datetime.datetime.now().isoformat(timespec="seconds"),
        "download": None,
        "vt": None,
        "uploaded": False,
        "deleted": False,
        "error": None,
    }

    if progress_cb:
        progress_cb("download", url)

    # 1. 下载
    dl = sample.download(url, idx=idx, max_size=max_size)
    out["download"] = {k: dl.get(k) for k in
                       ("ok", "sha256", "md5", "size", "kind", "error", "path")}

    if not dl.get("ok"):
        out["error"] = dl.get("error") or "下载失败"
        return out

    sha = dl["sha256"]
    out["sha256"] = sha
    out["size"] = dl["size"]
    out["kind"] = dl["kind"]
    out["filename"] = dl["path"].split("\\")[-1] if dl.get("path") else ""

    # 2. 查 VT
    if progress_cb:
        progress_cb("vt_query", url)
    rep = vt.get_report(sha)
    out["vt"] = rep

    # 3. 无记录则上传（no_record=True 表示库里确实没有；error 有值才是查询失败）
    should_upload = (auto_upload
                     and not rep.get("found")
                     and not rep.get("error"))
    if should_upload:
        if progress_cb:
            progress_cb("vt_upload", url)
        up = vt.upload_file(dl["path"])
        if up.get("ok"):
            out["uploaded"] = True
            out["analysis_id"] = up.get("analysis_id")
            if progress_cb:
                progress_cb("vt_wait", url)
            res = vt.get_analysis(up["analysis_id"], wait=wait_analysis)
            if res.get("ok") and res.get("completed"):
                stats = res.get("stats") or {}
                out["vt"] = {
                    "hash": sha, "found": True,
                    "from_analysis": True,
                    "stats": {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "undetected": stats.get("undetected", 0),
                        "harmless": stats.get("harmless", 0),
                        "timeout": stats.get("timeout", 0),
                        "total": sum(stats.values()) if stats else 0,
                    },
                    "link": "https://www.virustotal.com/gui/file/%s" % sha,
                }
            else:
                out["vt"] = {"hash": sha, "found": False,
                             "error": res.get("error") or "分析未完成",
                             "link": "https://www.virustotal.com/gui/file/%s" % sha}
        else:
            err = up.get("error") or "上传失败"
            out["vt_error"] = err
            out["vt"] = {"hash": sha, "found": False, "error": err,
                         "upload_failed": True}

    # 上传完成后本地样本就必须删掉（不论成功失败，避免残留）
    # 这里记录一下上传状态供界面显示
    if not out.get("uploaded") and out.get("vt", {}).get("upload_failed"):
        out["note"] = "VT 上传失败：%s" % (out["vt"].get("error") or "")

    # 4. 删除本地样本
    if progress_cb:
        progress_cb("delete", url)
    if dl.get("path"):
        ok, _ = sample.delete(dl["path"])
        out["deleted"] = ok

    return out


def analyze_many(payloads, auto_upload=True, progress_cb=None, item_cb=None):
    """
    批量分析
    payloads: [(domain, url), ...]
    返回 [result, ...]
    """
    results = []
    for i, (domain, url) in enumerate(payloads, 1):
        if item_cb:
            item_cb(i, len(payloads), domain, url)
        r = analyze_payload(url, idx=i, auto_upload=auto_upload,
                            progress_cb=progress_cb)
        r["domain"] = domain
        results.append(r)
    return results


def collect_payloads(results, only_risky=True):
    """
    从探测结果里收集所有载荷链接
    返回 [(domain, url), ...] 去重
    """
    seen = set()
    out = []
    for r in results:
        if only_risky:
            lvl = (r.get("risk") or {}).get("level")
            if lvl not in ("高危", "可疑"):
                continue
        h = r.get("http_best") or {}
        for u in (h.get("payload_strong") or []):
            if u not in seen:
                seen.add(u)
                out.append((r["domain"], u))
        for u in (h.get("payload_deep") or []):
            if u not in seen:
                seen.add(u)
                out.append((r["domain"], u))
        for u in (h.get("payload_weak") or []):
            if u not in seen:
                seen.add(u)
                out.append((r["domain"], u))
        for u in (h.get("download_links") or []):
            if u not in seen:
                seen.add(u)
                out.append((r["domain"], u))
    return out