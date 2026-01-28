#!/usr/bin/env python3
import csv
import datetime
import getpass
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time

DB_NAME = "wms"
DB_HOST = "10.5.60.20"
DB_PORT = 3306
DB_USER = "wms_user"
BACKUP_DIR = "backups"
TABLE_TO_EXPORT = "stock_moves"

SCHEMA_VERSION = "1.0"
MODULE_NAME = "module2_wms_backup"

CSV_HEADERS = [
    "move_id",
    "product_name",
    "from_location",
    "to_location",
    "quantity",
    "move_type",
    "moved_at",
]


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


def ts_file(dt):
    return dt.strftime("%Y-%m-%d_%H-%M-%S_UTC")


def ts_iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def file_size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return None


def extract_error(text):
    if not text:
        return ""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and set(ln.strip()) != {"-"}]
    for line in lines:
        if "ERROR" in line.upper():
            return line
    return lines[-1] if lines else ""


def parse_tsv(output, cols):
    rows = []
    if not output:
        return rows
    for line in output.splitlines():
        if not line:
            continue
        parts = ["" if p == "NULL" else p for p in line.split("\t")]
        if len(parts) < cols:
            parts += [""] * (cols - len(parts))
        elif len(parts) > cols:
            parts = parts[:cols]
        rows.append(parts)
    return rows


def write_csv(path, headers, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(headers)
        w.writerows(rows)


def is_missing_table_error(msg):
    msg = (msg or "").lower()
    return "doesn't exist" in msg or "does not exist" in msg or "unknown table" in msg


def run_cmd(cmd, stdout_file=None):
    if stdout_file:
        with open(stdout_file, "wb") as f:
            p = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE)
        return p.returncode, "", p.stderr.decode("utf-8", errors="replace")
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    return p.returncode, p.stdout, p.stderr


def build_base_cmd(password):
    return [
        "mariadb",
        "--host",
        DB_HOST,
        "--port",
        str(DB_PORT),
        "--user",
        DB_USER,
        f"--password={password}",
        "--ssl=0",
        "--protocol=tcp",
        "--database",
        DB_NAME,
        "--connect-timeout=5",
    ]


def main():
    start = time.perf_counter()
    now = utc_now()
    tsf = ts_file(now)

    result = {
        "schema_version": SCHEMA_VERSION,
        "module": MODULE_NAME,
        "timestamp_utc": ts_iso(now),
        "execution": {
            "host": socket.gethostname(),
            "user": getpass.getuser(),
            "duration_ms": None,
        },
        "target": {
            "db_name": DB_NAME,
            "db_host": DB_HOST,
            "db_port": DB_PORT,
            "db_user": DB_USER,
        },
        "artifacts": {
            "sql_dump": {
                "status": "UNKNOWN",
                "file": None,
                "size_bytes": None,
                "sha256": None,
                "error": None,
            },
            "csv_export": {
                "status": "UNKNOWN",
                "table": TABLE_TO_EXPORT,
                "file": None,
                "rows_exported": None,
                "size_bytes": None,
                "sha256": None,
                "error": None,
            },
        },
        "summary": {"overall_status": "UNKNOWN", "message": "", "warnings": []},
        "exit_code": 3,
    }

    warnings = result["summary"]["warnings"]
    try:
        password = getpass.getpass(f"MariaDB password for {DB_USER}@{DB_HOST}: ")
        if not password:
            raise ValueError("Missing MariaDB password.")

        mariadb_path = shutil.which("mariadb")
        dump_path = shutil.which("mariadb-dump")
        if not mariadb_path:
            raise FileNotFoundError("mariadb client not found in PATH.")
        if not dump_path:
            result["artifacts"]["sql_dump"]["status"] = "CRITICAL"
            result["artifacts"]["sql_dump"]["error"] = "mariadb-dump not found in PATH."

        base_cmd = build_base_cmd(password)
        rc, out, err = run_cmd(base_cmd + ["--execute", "SELECT 1;"])
        if rc != 0:
            raise ConnectionError(extract_error(err) or "MariaDB connection failed.")

        os.makedirs(BACKUP_DIR, exist_ok=True)

        sql_file = os.path.join(BACKUP_DIR, f"{DB_NAME}_dump_{tsf}.sql")
        result["artifacts"]["sql_dump"]["file"] = sql_file
        if dump_path:
            dump_cmd = [
                "mariadb-dump",
                "--host",
                DB_HOST,
                "--port",
                str(DB_PORT),
                "--user",
                DB_USER,
                f"--password={password}",
                "--ssl=0",
                "--protocol=tcp",
                "--no-tablespaces",
                "--databases",
                DB_NAME,
            ]
            drc, _, derr = run_cmd(dump_cmd, stdout_file=sql_file)
            if drc == 0:
                result["artifacts"]["sql_dump"]["status"] = "OK"
            else:
                result["artifacts"]["sql_dump"]["status"] = "CRITICAL"
                result["artifacts"]["sql_dump"]["error"] = extract_error(derr) or "mariadb-dump failed."

        if os.path.exists(sql_file):
            result["artifacts"]["sql_dump"]["size_bytes"] = file_size(sql_file)
            result["artifacts"]["sql_dump"]["sha256"] = sha256_file(sql_file)

        csv_file = os.path.join(BACKUP_DIR, f"{TABLE_TO_EXPORT}_{tsf}.csv")
        result["artifacts"]["csv_export"]["file"] = csv_file

        query = f"""
SELECT
  sm.id AS move_id,
  p.name AS product_name,
  lf.name AS from_location,
  lt.name AS to_location,
  sm.quantity AS quantity,
  sm.move_type AS move_type,
  sm.moved_at AS moved_at
FROM {TABLE_TO_EXPORT} sm
JOIN products p ON sm.product_id = p.id
LEFT JOIN locations lf ON sm.from_location_id = lf.id
LEFT JOIN locations lt ON sm.to_location_id = lt.id
ORDER BY sm.moved_at;
""".strip()

        rc, out, err = run_cmd(base_cmd + ["--batch", "--silent", "--skip-column-names", "--execute", query])
        rows = []
        if rc != 0:
            emsg = extract_error(err) or "CSV export failed."
            if is_missing_table_error(emsg):
                result["artifacts"]["csv_export"]["status"] = "WARNING"
                result["artifacts"]["csv_export"]["error"] = emsg
                warnings.append(f"Table {TABLE_TO_EXPORT} not found; CSV header only.")
            else:
                result["artifacts"]["csv_export"]["status"] = "CRITICAL"
                result["artifacts"]["csv_export"]["error"] = emsg
        else:
            rows = parse_tsv(out, len(CSV_HEADERS))
            if rows:
                result["artifacts"]["csv_export"]["status"] = "OK"
            else:
                result["artifacts"]["csv_export"]["status"] = "WARNING"
                result["artifacts"]["csv_export"]["error"] = "No rows exported."
                warnings.append("CSV export returned no rows.")

        write_csv(csv_file, CSV_HEADERS, rows)
        result["artifacts"]["csv_export"]["rows_exported"] = len(rows)
        result["artifacts"]["csv_export"]["size_bytes"] = file_size(csv_file)
        result["artifacts"]["csv_export"]["sha256"] = sha256_file(csv_file)

    except ValueError as e:
        msg = str(e)
        result["artifacts"]["sql_dump"]["status"] = "CRITICAL"
        result["artifacts"]["sql_dump"]["error"] = msg
        result["artifacts"]["csv_export"]["status"] = "CRITICAL"
        result["artifacts"]["csv_export"]["error"] = msg
        result["summary"]["message"] = msg
    except FileNotFoundError as e:
        msg = str(e)
        result["artifacts"]["sql_dump"]["status"] = "CRITICAL"
        result["artifacts"]["sql_dump"]["error"] = msg
        result["artifacts"]["csv_export"]["status"] = "CRITICAL"
        result["artifacts"]["csv_export"]["error"] = msg
        result["summary"]["message"] = msg
    except ConnectionError as e:
        msg = str(e)
        result["artifacts"]["sql_dump"]["status"] = "CRITICAL"
        result["artifacts"]["sql_dump"]["error"] = msg
        result["artifacts"]["csv_export"]["status"] = "CRITICAL"
        result["artifacts"]["csv_export"]["error"] = msg
        result["summary"]["message"] = msg
    except Exception as e:
        result["summary"]["overall_status"] = "UNKNOWN"
        result["summary"]["message"] = f"Unexpected error: {e}"
        result["exit_code"] = 3
    finally:
        duration_ms = int((time.perf_counter() - start) * 1000)
        result["execution"]["duration_ms"] = duration_ms

        if result["summary"]["overall_status"] == "UNKNOWN":
            sql_status = result["artifacts"]["sql_dump"]["status"]
            csv_status = result["artifacts"]["csv_export"]["status"]
            if "CRITICAL" in (sql_status, csv_status):
                overall = "CRITICAL"
            elif "WARNING" in (sql_status, csv_status):
                overall = "WARNING"
            elif sql_status == "OK" and csv_status == "OK":
                overall = "OK"
            else:
                overall = "UNKNOWN"
            result["summary"]["overall_status"] = overall

        if not result["summary"]["message"]:
            if result["summary"]["overall_status"] == "OK":
                result["summary"]["message"] = "SQL dump and CSV export completed."
            elif result["summary"]["overall_status"] == "WARNING":
                result["summary"]["message"] = (
                    "Backup completed with warnings: " + warnings[0]
                    if warnings
                    else "Backup completed with warnings."
                )
            elif result["summary"]["overall_status"] == "CRITICAL":
                err = result["artifacts"]["sql_dump"]["error"] or result["artifacts"]["csv_export"]["error"]
                result["summary"]["message"] = err or "Backup failed."
            else:
                result["summary"]["message"] = "Backup ended with unexpected error."

        exit_map = {"OK": 0, "WARNING": 1, "CRITICAL": 2, "UNKNOWN": 3}
        result["exit_code"] = exit_map.get(result["summary"]["overall_status"], 3)

        print("=== BACKUP WMS ===")
        print(f"Status : {result['summary']['overall_status']}")
        print(f"Message : {result['summary']['message']}")
        print(f"Code : {result['exit_code']}")
        try:
            print(json.dumps(result, indent=2, ensure_ascii=True))
        except Exception:
            print(json.dumps({"error": "Failed to serialize JSON result.", "exit_code": result.get("exit_code", 3)}, indent=2))

    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
