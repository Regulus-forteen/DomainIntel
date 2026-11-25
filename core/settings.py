# -*- coding: utf-8 -*-
"""
Domain Intel — 统一配置加载
配置优先级：环境变量 > ~/.domainintel.json > 项目内 config.json
"""
import os
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
LOCAL_CONFIG = Path(__file__).resolve().parent / "config.json"
USER_CONFIG = Path.home() / ".domainintel.json"

_defaults = {
    "virustotal": {
        "api_key": "",
        "daily_limit": 500,
        "minute_limit": 4,
    },
    "threatbook": {
        "api_key": "",
        "daily_limit": 300,
    },
    "mail": {
        "smtp_server": "smtp.163.com",
        "smtp_port": 465,
        "sender_addr": "",
        "password": "",
    },
    "reporter": {
        "name": "",
        "email": "",
    },
}


def _merge(base, over):
    out = dict(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load():
    cfg = json.loads(json.dumps(_defaults))

    for p in (LOCAL_CONFIG, USER_CONFIG):
        try:
            if p.exists():
                cfg = _merge(cfg, json.loads(p.read_text(encoding="utf-8")))
        except Exception:
            pass

    # 环境变量覆盖
    env_map = {
        "VT_API_KEY": ("virustotal", "api_key"),
        "TB_API_KEY": ("threatbook", "api_key"),
        "DI_SMTP_SERVER": ("mail", "smtp_server"),
        "DI_SMTP_PORT": ("mail", "smtp_port"),
        "DI_SENDER": ("mail", "sender_addr"),
        "DI_MAIL_PASSWORD": ("mail", "password"),
        "DI_REPORTER_NAME": ("reporter", "name"),
        "DI_REPORTER_EMAIL": ("reporter", "email"),
    }
    for env, (sec, key) in env_map.items():
        v = os.environ.get(env)
        if v:
            cfg.setdefault(sec, {})[key] = v
    return cfg


def get(section, key=None, default=None):
    cfg = load()
    if key is None:
        return cfg.get(section, default)
    return cfg.get(section, {}).get(key, default)