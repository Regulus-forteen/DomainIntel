# -*- coding: utf-8 -*-
"""
样本下载模块
- 下载到隔离目录
- 计算 SHA256 / MD5 / 大小 / 文件类型（魔数）
- 支持大小上限
- 支持删除
"""
import os
import re
import hashlib
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings()

BASE_DIR = Path(__file__).resolve().parents[1]
SAMPLE_DIR = BASE_DIR / "output" / "samples"

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

MAX_SIZE = 600 * 1024 * 1024   # 600 MB

MAGIC = [
    (b"PK\x03\x04", "ZIP/压缩包"),
    (b"PK\x05\x06", "ZIP(空)"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"7z\xbc\xaf\x27\x1c", "7Z"),
    (b"MZ", "PE可执行(Windows)"),
    (b"\x7fELF", "ELF可执行(Linux)"),
    (b"\xca\xfe\xba\xbe", "Mach-O/Java"),
    (b"\x1f\x8b", "GZIP"),
    (b"BZh", "BZIP2"),
    (b"\xd0\xcf\x11\xe0", "MS Office/OLE"),
    (b"<?xml", "XML"),
    (b"<!DOCTYPE", "HTML"),
    (b"<html", "HTML"),
]


def file_kind(path):
    """按魔数判断真实类型"""
    try:
        with open(path, "rb") as f:
            head = f.read(64)
        for sig, name in MAGIC:
            if head.startswith(sig):
                return name
        if head[:2] == b"\x89P":
            return "PNG"
        if b"<script" in head or b"<div" in head:
            return "HTML"
        return "未知"
    except Exception:
        return "读取失败"


def _safe_name(url, idx):
    """从 URL 生成安全文件名"""
    name = url.split("?")[0].rstrip("/").split("/")[-1] or "sample"
    name = re.sub(r"[^\w\.\-]", "_", name)[:80]
    if "." not in name:
        name += ".bin"
    return "%02d_%s" % (idx, name)


def download(url, idx=1, max_size=MAX_SIZE, timeout=120, progress_cb=None):
    """
    下载单个样本
    返回 {ok, path, sha256, md5, size, kind, error, url}
    """
    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
    out = {"url": url, "ok": False, "path": None, "sha256": None,
           "md5": None, "size": 0, "kind": None, "error": None}

    fn = SAMPLE_DIR / _safe_name(url, idx)
    try:
        # 先 HEAD 看大小
        try:
            h = requests.head(url, headers={"User-Agent": UA}, timeout=20,
                              verify=False, allow_redirects=True)
            clen = h.headers.get("Content-Length")
            if clen and clen.isdigit():
                size = int(clen)
                if size > max_size:
                    out["error"] = "文件过大（%d MB），超过 %d MB 上限，跳过" % (
                        size // 1024 // 1024, max_size // 1024 // 1024)
                    return out
        except Exception:
            pass

        sha = hashlib.sha256()
        md5 = hashlib.md5()
        total = 0
        with requests.get(url, headers={"User-Agent": UA}, timeout=timeout,
                          verify=False, stream=True, allow_redirects=True) as r:
            if r.status_code >= 400:
                out["error"] = "HTTP %s" % r.status_code
                return out
            with open(fn, "wb") as f:
                for chunk in r.iter_content(1024 * 256):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > max_size:
                        f.close()
                        try:
                            os.remove(fn)
                        except Exception:
                            pass
                        out["error"] = "下载过程中超过大小上限，已中止"
                        return out
                    f.write(chunk)
                    sha.update(chunk)
                    md5.update(chunk)
                    if progress_cb and total % (1024 * 1024) < 256 * 1024:
                        progress_cb(total)

        out.update({
            "ok": True,
            "path": str(fn),
            "sha256": sha.hexdigest(),
            "md5": md5.hexdigest(),
            "size": total,
            "kind": file_kind(fn),
        })
    except Exception as e:
        out["error"] = "%s: %s" % (type(e).__name__, str(e)[:120])
        try:
            if fn.exists() and fn.stat().st_size == 0:
                fn.unlink()
        except Exception:
            pass
    return out


def delete(path):
    """删除样本文件"""
    try:
        p = Path(path)
        if p.exists():
            p.unlink()
            return True, "已删除"
    except Exception as e:
        return False, str(e)[:80]
    return True, "文件不存在"


def clean_all():
    """清空样本目录"""
    n = 0
    try:
        for f in SAMPLE_DIR.glob("*"):
            if f.is_file():
                f.unlink()
                n += 1
    except Exception:
        pass
    return n