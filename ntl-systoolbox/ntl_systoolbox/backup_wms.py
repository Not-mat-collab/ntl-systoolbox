import subprocess
from pathlib import Path
import csv
import mysql.connector
from .utils import now_iso, write_json, print_human_and_json, ExitCode, ensure_dir

def full_backup(cfg: dict) -> int:
    db = cfg["backup_wms"]["mysql"]
    backup_dir = ensure_dir(cfg["backup_wms"]["backup_dir"])
    mysqldump = cfg["backup_wms"]["mysqldump_path"]

    ts = now_iso().replace(":", "").replace("-", "")
    backup_file = backup_dir / f"wms_backup_{ts}.sql"

    cmd = [
        mysqldump,
        f"-h{db['host']}",
        f"-P{db['port']}",
        f"-u{db['user']}",
        f"-p{db['password']}",
        db["database"],
    ]

    try:
        with open(backup_file, "w", encoding="utf-8") as f:
            completed = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)
        ok = (completed.returncode == 0)
        error = None if ok else completed.stderr
    except Exception as e:
        ok = False
        error = str(e)

    data = {
        "timestamp": now_iso(),
        "type": "wms_full_backup",
        "backup_file": str(backup_file),
        "ok": ok,
        "error": error,
    }
    write_json(cfg["general"]["output_dir"], "backup_wms_full", data)
    human = f"Sauvegarde WMS: {'OK' if ok else 'KO'}"
    print_human_and_json(human, data)
    return ExitCode.OK if ok else ExitCode.CRITICAL

def export_table_csv(cfg: dict, table: str) -> int:
    db = cfg["backup_wms"]["mysql"]
    backup_dir = ensure_dir(cfg["backup_wms"]["backup_dir"])

    ts = now_iso().replace(":", "").replace("-", "")
    csv_file = backup_dir / f"{table}_{ts}.csv"

    try:
        conn = mysql.connector.connect(
            host=db["host"],
            port=db["port"],
            user=db["user"],
            password=db["password"],
            database=db["database"],
        )
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM {table}")
        columns = [desc[0] for desc in cursor.description]

        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(columns)
            for row in cursor:
                writer.writerow(row)

        cursor.close()
        conn.close()
        ok = True
        error = None
    except Exception as e:
        ok = False
        error = str(e)

    data = {
        "timestamp": now_iso(),
        "type": "wms_table_export",
        "table": table,
        "csv_file": str(csv_file),
        "ok": ok,
        "error": error,
    }
    write_json(cfg["general"]["output_dir"], "backup_wms_table", data)
    human = f"Export table {table}: {'OK' if ok else f'KO ({error})'}"
    print_human_and_json(human, data)
    return ExitCode.OK if ok else ExitCode.CRITICAL
