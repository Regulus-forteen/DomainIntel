# -*- coding: utf-8 -*-
"""
载荷分析编排模块
流程：下载 → 计算哈希 → 查 VT 缓存/API → 无记录则上传并轮询 → 删除本地样本
"""
import time
import datetime

from . import sample, vt


def analyze_payload(url, idx=1, max_size=600 * 1024 * 1024,
                    auto_upload=True, wait_analysis=240, progress_cb=None,
                    live_cb=None, vt_progress_cb=None):
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
    if live_cb:
        live_cb({"index": idx, "stage": "下载中", "stage_key": "download",
                 "file": url.rsplit("/", 1)[-1][:30]})

    # 1. 下载
    dl = sample.download(url, idx=idx, max_size=max_size)
    out["download"] = {k: dl.get(k) for k in
                       ("ok", "sha256", "md5", "size", "kind", "error", "path")}

    if not dl.get("ok"):
        out["error"] = dl.get("error") or "下载失败"
        return out

    if live_cb:
        live_cb({"index": idx, "stage": "计算哈希", "stage_key": "hash",
                 "file": out.get("filename") or ""})
    sha = dl["sha256"]
    out["sha256"] = sha
    out["size"] = dl["size"]
    out["kind"] = dl["kind"]
    out["filename"] = dl["path"].split("\\")[-1] if dl.get("path") else ""

    # 2. 查 VT
    if progress_cb:
        progress_cb("vt_query", url)
    if live_cb:
        live_cb({"index": idx, "stage": "查询 VirusTotal", "stage_key": "vt_query",
                 "file": out.get("filename") or ""})
    rep = vt.get_report(sha)
    out["vt"] = rep

    # 3. 无记录则上传（no_record=True 表示库里确实没有；error 有值才是查询失败）
    should_upload = (auto_upload
                     and not rep.get("found")
                     and not rep.get("error"))
    if should_upload:
        if progress_cb:
            progress_cb("vt_upload", url)
        if live_cb:
            live_cb({"index": idx, "stage": "上传 VirusTotal", "stage_key": "vt_upload",
                     "file": out.get("filename") or ""})
        up = vt.upload_file(dl["path"])
        if up.get("ok"):
            out["uploaded"] = True
            out["analysis_id"] = up.get("analysis_id")
            if progress_cb:
                progress_cb("vt_wait", url)
            if live_cb:
                live_cb({"index": idx, "stage": "VT 分析中（最多 %ds）" % wait_analysis,
                         "stage_key": "vt_wait",
                         "file": out.get("filename") or ""})
            def _vprog(elapsed, total_w, pct, text, stats):
                if vt_progress_cb:
                    vt_progress_cb({
                        "pct": pct,
                        "text": text,
                        "elapsed": int(elapsed),
                        "total": int(total_w),
                        "stats": stats or {},
                    })
                if live_cb:
                    live_cb({"index": idx, "stage": text,
                             "stage_key": "vt_wait",
                             "file": out.get("filename") or ""})

            res = vt.get_analysis(up["analysis_id"], wait=wait_analysis,
                                  progress_cb=_vprog)
            if res.get("ok") and res.get("completed"):
                stats = res.get("stats") or {}
                total = (stats.get("malicious", 0) + stats.get("suspicious", 0)
                         + stats.get("undetected", 0) + stats.get("harmless", 0)
                         + stats.get("timeout", 0))
                out["vt"] = {
                    "hash": sha,
                    "found": True,
                    "from_analysis": True,
                    "label": res.get("label") or "",
                    "engines": res.get("engines") or [],
                    "stats": {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "undetected": stats.get("undetected", 0),
                        "harmless": stats.get("harmless", 0),
                        "timeout": stats.get("timeout", 0),
                        "total": total or sum(v for k, v in stats.items()
                                              if isinstance(v, int)),
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


def analyze_many(payloads, auto_upload=True, progress_cb=None, item_cb=None,
                 live_cb=None):
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
                            progress_cb=progress_cb, live_cb=live_cb)
        r["domain"] = domain
        results.append(r)
        if live_cb:
            live_cb({"index": i, "stage": "完成", "stage_key": "item_done",
                     "file": ""})
    return results


def collect_payloads(results, only_risky=True):
    """
    从探测结果里收集所有载荷链接
    返回 [(domain, url), ...] 去重

    only_risky=True 时不再直接跳过低分域名——只要页面里出现可执行文件，
    就值得送 VT 查一次（低分域名也可能是没被识别的仿冒站）。
    风险等级只用于排序，高危优先。
    """
    seen = set()
    out = []
    # 高危优先处理
    if only_risky:
        _lvl_rank = {"高危": 0, "可疑": 1, "低危": 2, "正常": 3}
        results = sorted(
            results,
            key=lambda x: _lvl_rank.get((x.get("risk") or {}).get("level"), 9))
    for r in results:
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


def analyze_many_p(payloads, auto_upload=True, progress_cb=None, item_cb=None,
                   live_cb=None, vt_progress_cb=None, workers=2):
    """
    并发版批量分析
    item_cb(i, total, domain, url)       开始处理某个载荷
    done_cb(domain, url, result)         每个载荷完成（通过 live_cb 的 item_done 事件）
    vt_progress_cb(i, domain, url, info) VT 轮询进度
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    total = len(payloads)
    results = []
    idx_map = {}

    def one(i, domain, url):
        if item_cb:
            item_cb(i, total, domain, url)

        def _live(info):
            if live_cb:
                info = dict(info or {})
                info["domain"] = domain
                info["url"] = url
                info["index"] = i
                info["total"] = total
                live_cb(info)

        def _vprog(info):
            if vt_progress_cb:
                vt_progress_cb(i, domain, url, info)

        r = analyze_payload(url, idx=i, auto_upload=auto_upload,
                            progress_cb=progress_cb, live_cb=_live,
                            vt_progress_cb=_vprog)
        r["domain"] = domain
        r["index"] = i
        return r

    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futs = {}
        for i, (domain, url) in enumerate(payloads, 1):
            futs[ex.submit(one, i, domain, url)] = (i, domain, url)
        for f in as_completed(futs):
            i, domain, url = futs[f]
            try:
                r = f.result()
            except Exception as e:
                r = {"domain": domain, "url": url, "index": i,
                     "error": "%s: %s" % (type(e).__name__, str(e)[:100]),
                     "vt": {"found": False, "error": str(e)[:60]}}
            results.append(r)
            if live_cb:
                live_cb({"index": i, "total": total, "stage": "完成",
                         "stage_key": "item_done", "domain": domain,
                         "url": url, "file": ""})

    results.sort(key=lambda x: x.get("index", 0))
    return results
