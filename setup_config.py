# -*- coding: utf-8 -*-
"""
Domain Intel — 配置初始化
运行一次，从模板生成 core/config.json
"""
import json
import shutil
from pathlib import Path

BASE = Path(__file__).resolve().parent
CFG = BASE / "core" / "config.json"
TPL = BASE / "core" / "config.example.json"


def main():
    if CFG.exists():
        print("core/config.json 已存在，跳过。")
        print("如需重置，删除该文件后重新运行。")
        return

    if TPL.exists():
        shutil.copy2(TPL, CFG)
        print("已从模板生成 core/config.json")
    else:
        print("找不到 core/config.example.json")
        return

    print()
    print("请编辑 core/config.json 填入你的配置：")
    print("  - virustotal.api_key    VirusTotal API Key（免费版 4次/分，500次/天）")
    print("  - threatbook.api_key    微步沙箱 API Key（可选）")
    print("  - mail                  SMTP 发件配置（发送举报邮件时需要）")
    print("  - reporter              举报人署名")
    print()
    print("也可以用环境变量（优先级高于配置文件）：")
    print("  VT_API_KEY / TB_API_KEY / DI_SENDER / DI_MAIL_PASSWORD")


if __name__ == "__main__":
    main()