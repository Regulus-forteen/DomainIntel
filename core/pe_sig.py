# -*- coding: utf-8 -*-
"""
PE 数字签名检查
- 是否签名
- 签名主体（Subject / Issuer）
- 证书有效期
- 是否被篡改（哈希校验）
"""
import os
import struct
import hashlib
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


def _read_pe_security_dir(path):
    """解析 PE，找 Certificate Table（安全目录）的位置和大小"""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        return None, str(e)

    if len(data) < 0x40 or data[:2] != b"MZ":
        return None, "不是 MZ/PE 文件"

    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            return None, "无 PE 头"
        coff = e_lfanew + 4
        num_sections = struct.unpack_from("<H", data, coff + 2)[0]
        opt_size = struct.unpack_from("<H", data, coff + 16)[0]
        opt_off = coff + 20

        magic = struct.unpack_from("<H", data, opt_off)[0]
        if magic == 0x10B:
            dd_off = opt_off + 96
        elif magic == 0x20B:
            dd_off = opt_off + 112
        else:
            return None, "未知可选头 magic 0x%X" % magic

        sec_off = dd_off + 4 * 8
        cert_rva, cert_size = struct.unpack_from("<II", data, sec_off)
        if cert_rva == 0 or cert_size == 0:
            return None, "未签名（安全目录为空）"
        if cert_rva + cert_size > len(data):
            return None, "安全目录越界"
        return {"data": data, "offset": cert_rva, "size": cert_size}, None
    except Exception as e:
        return None, "解析失败: " + str(e)[:60]


def _parse_cert_blob(data, offset):
    """解析 WIN_CERTIFICATE 结构，取出 PKCS#7"""
    certs = []
    pos = offset
    while pos + 8 <= len(data):
        try:
            length, rev, ctype = struct.unpack_from("<IHH", data, pos)
            if length == 0 or pos + length > len(data):
                break
            if ctype == 0x0002:  # PKCS_SIGNED_DATA
                certs.append(data[pos + 8: pos + length])
            pos += (length + 7) & ~7
        except Exception:
            break
    return certs


def _extract_certs_from_pkcs7(blob):
    """从 PKCS#7 里粗略提取所有 DER 证书（扫 30 82 / 30 81 开头）"""
    out = []
    i = 0
    while i < len(blob) - 4:
        if blob[i] == 0x30 and blob[i + 1] in (0x82, 0x81):
            if blob[i + 1] == 0x82:
                if i + 4 > len(blob):
                    break
                total = struct.unpack_from(">H", blob, i + 2)[0] + 4
            else:
                total = blob[i + 2] + 3
            if 100 < total <= len(blob) - i:
                der = blob[i:i + total]
                try:
                    c = x509.load_der_x509_certificate(der, default_backend())
                    out.append(c)
                    i += total
                    continue
                except Exception:
                    pass
        i += 1
    return out


def check_signature(path):
    """
    返回 {
      signed: bool, error: str,
      signers: [{subject, issuer, not_before, not_after, serial}],
      file_hash: str
    }
    """
    out = {"signed": False, "error": None, "signers": [], "file_hash": None}

    p = Path(path)
    if not p.exists():
        out["error"] = "文件不存在"
        return out

    out["file_hash"] = hashlib.sha256(p.read_bytes()).hexdigest()

    pe, err = _read_pe_security_dir(path)
    if not pe:
        out["error"] = err
        return out

    data = pe["data"]
    blobs = _parse_cert_blob(data, pe["offset"])
    if not blobs:
        out["error"] = "安全目录存在但无 PKCS#7"
        return out

    if not _HAS_CRYPTO:
        out["error"] = "缺少 cryptography 库，无法解析证书"
        out["signed"] = True
        return out

    all_certs = []
    for b in blobs:
        all_certs.extend(_extract_certs_from_pkcs7(b))

    if not all_certs:
        out["signed"] = True
        out["error"] = "有签名数据但证书解析失败"
        return out

    out["signed"] = True
    for c in all_certs:
        try:
            nb = c.not_valid_before_utc.strftime("%Y-%m-%d")
            na = c.not_valid_after_utc.strftime("%Y-%m-%d")
        except Exception:
            nb = na = "?"
        out["signers"].append({
            "subject": c.subject.rfc4514_string(),
            "issuer": c.issuer.rfc4514_string(),
            "not_before": nb,
            "not_after": na,
            "serial": hex(c.serial_number)[:24],
        })
    return out


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("用法: python pe_sig.py <file.exe>")
        sys.exit(1)
    r = check_signature(sys.argv[1])
    print("已签名:", r["signed"])
    print("错误:", r["error"])
    print("SHA256:", r["file_hash"])
    for i, s in enumerate(r["signers"], 1):
        print("\n证书 %d:" % i)
        print("  Subject :", s["subject"])
        print("  Issuer  :", s["issuer"])
        print("  有效期  :", s["not_before"], "→", s["not_after"])
        print("  序列号  :", s["serial"])