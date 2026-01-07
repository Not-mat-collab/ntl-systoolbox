import json
import os
from datetime import datetime
from pathlib import Path
from enum import IntEnum

class ExitCode(IntEnum):
    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3

def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"

def ensure_dir(path: str | os.PathLike) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p

def write_json(output_dir: str, prefix: str, data: dict) -> Path:
    ensure_dir(output_dir)
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    path = Path(output_dir) / f"{prefix}_{ts}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return path

def print_human_and_json(human: str, json_data: dict | None = None):
    print(human)
    if json_data is not None:
        print("\n--- JSON ---")
        print(json.dumps(json_data, indent=2))
