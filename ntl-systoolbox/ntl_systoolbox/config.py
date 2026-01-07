import os
import yaml

DEFAULT_CONFIG_PATH = "config.yaml"

def load_config(path: str | None = None) -> dict:
    config_file = path or os.getenv("NTL_CONFIG_FILE", DEFAULT_CONFIG_PATH)
    with open(config_file, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    # Surcharges simples par variables d'environnement
    db_user = os.getenv("NTL_DB_USER")
    db_pass = os.getenv("NTL_DB_PASSWORD")
    if db_user:
        cfg.setdefault("diagnostic", {}).setdefault("mysql", {})["user"] = db_user
        cfg.setdefault("backup_wms", {}).setdefault("mysql", {})["user"] = db_user
    if db_pass:
        cfg.setdefault("diagnostic", {}).setdefault("mysql", {})["password"] = db_pass
        cfg.setdefault("backup_wms", {}).setdefault("mysql", {})["password"] = db_pass

    return cfg
