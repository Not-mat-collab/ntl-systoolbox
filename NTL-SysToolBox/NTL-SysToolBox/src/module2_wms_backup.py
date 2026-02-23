#!/usr/bin/env python3
import csv
import datetime
import getpass
import hashlib
import json
import os
import socket
import sys
import time

try:
    import pymysql
except Exception:
    pymysql = None

DB_NAME = "wms"
DB_HOST = "10.5.60.20"
DB_PORT = 3306
DB_USER = "wms_user"
BACKUP_DIR = "backups/wms"
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


def write_csv(path, headers, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(headers)
        w.writerows(rows)


def sql_literal(val):
    if val is None:
        return "NULL"
    if isinstance(val, bool):
        return "1" if val else "0"
    if isinstance(val, (int, float)):
        return str(val)
    if isinstance(val, (datetime.date, datetime.datetime)):
        if isinstance(val, datetime.date) and not isinstance(val, datetime.datetime):
            return "'{}'".format(val.strftime("%Y-%m-%d"))
        return "'{}'".format(val.strftime("%Y-%m-%d %H:%M:%S"))
    if isinstance(val, bytes):
        try:
            val = val.decode("utf-8")
        except Exception:
            val = val.hex()
    s = str(val)
    s = s.replace("\\", "\\\\").replace("'", "''")
    return "'{}'".format(s)


def overall_status(sql_status, csv_status):
    if "CRITICAL" in (sql_status, csv_status):
        return "CRITICAL"
    if "WARNING" in (sql_status, csv_status):
        return "WARNING"
    if sql_status == "OK" and csv_status == "OK":
        return "OK"
    return "UNKNOWN"


def connect_db(password):
    if not pymysql:
        raise RuntimeError("PyMySQL is not installed. Run: pip install pymysql")
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=password,
        database=DB_NAME,
        port=DB_PORT,
        charset="utf8mb4",
        autocommit=True,
    )


def dump_sql(conn, path):
    with conn.cursor() as cur, open(path, "w", encoding="utf-8") as f:
        f.write(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}`;\n")
        f.write(f"USE `{DB_NAME}`;\n\n")
        cur.execute("SHOW TABLES;")
        tables = [row[0] for row in cur.fetchall()]
        for tbl in tables:
            cur.execute(f"SHOW CREATE TABLE `{tbl}`;")
            create_sql = cur.fetchone()[1]
            f.write(f"DROP TABLE IF EXISTS `{tbl}`;\n")
            f.write(create_sql + ";\n\n")
            cur.execute(f"SELECT * FROM `{tbl}`;")
            rows = cur.fetchall()
            if rows:
                col_names = [desc[0] for desc in cur.description]
                for row in rows:
                    values = ",".join(sql_literal(v) for v in row)
                    cols = ",".join(f"`{c}`" for c in col_names)
                    f.write(f"INSERT INTO `{tbl}` ({cols}) VALUES ({values});\n")
                f.write("\n")


def export_csv(conn):
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
    with conn.cursor() as cur:
        cur.execute(query)
        return list(cur.fetchall())


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
            "sql_dump": {"status": "UNKNOWN", "file": None, "size_bytes": None, "sha256": None, "error": None},
            "csv_export": {"status": "UNKNOWN", "table": TABLE_TO_EXPORT, "file": None, "rows_exported": None, "size_bytes": None, "sha256": None, "error": None},
        },
        "summary": {"overall_status": "UNKNOWN", "message": "", "warnings": []},
        "exit_code": 3,
    }

    warnings = result["summary"]["warnings"]

    try:
        password = getpass.getpass(f"MariaDB password for {DB_USER}@{DB_HOST}: ")
        if not password:
            raise ValueError("Missing MariaDB password.")

        os.makedirs(BACKUP_DIR, exist_ok=True)
        conn = connect_db(password)

        sql_file = os.path.join(BACKUP_DIR, f"{DB_NAME}_dump_{tsf}.sql")
        result["artifacts"]["sql_dump"]["file"] = sql_file
        try:
            dump_sql(conn, sql_file)
            result["artifacts"]["sql_dump"]["status"] = "OK"
        except Exception as e:
            result["artifacts"]["sql_dump"]["status"] = "CRITICAL"
            result["artifacts"]["sql_dump"]["error"] = str(e)

        if os.path.exists(sql_file):
            result["artifacts"]["sql_dump"]["size_bytes"] = file_size(sql_file)
            result["artifacts"]["sql_dump"]["sha256"] = sha256_file(sql_file)

        csv_file = os.path.join(BACKUP_DIR, f"{TABLE_TO_EXPORT}_{tsf}.csv")
        result["artifacts"]["csv_export"]["file"] = csv_file

        rows = []
        try:
            rows = export_csv(conn)
            if rows:
                result["artifacts"]["csv_export"]["status"] = "OK"
            else:
                result["artifacts"]["csv_export"]["status"] = "WARNING"
                result["artifacts"]["csv_export"]["error"] = "No rows exported."
                warnings.append("CSV export returned no rows.")
        except Exception as e:
            msg = str(e)
            code = getattr(e, "args", [None])[0]
            if code == 1146:
                result["artifacts"]["csv_export"]["status"] = "WARNING"
                result["artifacts"]["csv_export"]["error"] = msg
                warnings.append(f"Table {TABLE_TO_EXPORT} not found; CSV header only.")
            else:
                result["artifacts"]["csv_export"]["status"] = "CRITICAL"
                result["artifacts"]["csv_export"]["error"] = msg

        write_csv(csv_file, CSV_HEADERS, rows)
        result["artifacts"]["csv_export"]["rows_exported"] = len(rows)
        result["artifacts"]["csv_export"]["size_bytes"] = file_size(csv_file)
        result["artifacts"]["csv_export"]["sha256"] = sha256_file(csv_file)

        conn.close()

    except Exception as e:
        msg = str(e)
        result["artifacts"]["sql_dump"]["status"] = "CRITICAL"
        result["artifacts"]["sql_dump"]["error"] = msg
        result["artifacts"]["csv_export"]["status"] = "CRITICAL"
        result["artifacts"]["csv_export"]["error"] = msg
        result["summary"]["message"] = msg

    duration_ms = int((time.perf_counter() - start) * 1000)
    result["execution"]["duration_ms"] = duration_ms

    result["summary"]["overall_status"] = overall_status(
        result["artifacts"]["sql_dump"]["status"],
        result["artifacts"]["csv_export"]["status"],
    )

    if not result["summary"]["message"]:
        st = result["summary"]["overall_status"]
        if st == "OK":
            result["summary"]["message"] = "SQL dump and CSV export completed."
        elif st == "WARNING":
            result["summary"]["message"] = (
                "Backup completed with warnings: " + warnings[0]
                if warnings
                else "Backup completed with warnings."
            )
        elif st == "CRITICAL":
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
