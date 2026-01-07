import platform
import subprocess
import psutil  # à mettre dans requirements.txt
import mysql.connector
from .utils import now_iso, write_json, print_human_and_json, ExitCode

def check_ad_dns(cfg: dict) -> int:
    servers = cfg.get("diagnostic", {}).get("ad_dns_servers", [])
    results = []
    overall_ok = True

    for s in servers:
        # Ping simple comme 1er niveau. Plus tard : requêtes DNS, etc.
        try:
            completed = subprocess.run(["ping", "-c", "1", s], capture_output=True, text=True)
            ok = (completed.returncode == 0)
        except Exception:
            ok = False
        results.append({"server": s, "reachable": ok})
        if not ok:
            overall_ok = False

    data = {
        "timestamp": now_iso(),
        "type": "ad_dns_check",
        "results": results,
    }

    write_json(cfg["general"]["output_dir"], "diagnostic_ad_dns", data)

    human = "Diagnostic AD/DNS:\n" + "\n".join(
        f"- {r['server']}: {'OK' if r['reachable'] else 'KO'}" for r in results
    )
    print_human_and_json(human, data)

    return ExitCode.OK if overall_ok else ExitCode.CRITICAL

def check_mysql(cfg: dict) -> int:
    db_cfg = cfg.get("diagnostic", {}).get("mysql", {})
    try:
        conn = mysql.connector.connect(
            host=db_cfg["host"],
            port=db_cfg["port"],
            user=db_cfg["user"],
            password=db_cfg["password"],
            database=db_cfg["database"],
            connection_timeout=5,
        )
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        cursor.close()
        conn.close()
        ok = True
    except Exception as e:
        ok = False
        error = str(e)

    data = {
        "timestamp": now_iso(),
        "type": "mysql_check",
        "host": db_cfg.get("host"),
        "ok": ok,
        "error": None if ok else error,
    }

    write_json(cfg["general"]["output_dir"], "diagnostic_mysql", data)
    human = "MySQL: OK" if ok else f"MySQL: KO ({error})"
    print_human_and_json(human, data)

    return ExitCode.OK if ok else ExitCode.CRITICAL

def _collect_local_system_info() -> dict:
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "uptime_seconds": psutil.boot_time(),
        "cpu_percent": psutil.cpu_percent(interval=1),
        "memory": psutil.virtual_memory()._asdict(),
        "disks": {p.mountpoint: psutil.disk_usage(p.mountpoint)._asdict()
                  for p in psutil.disk_partitions(all=False)},
    }

def check_windows_server(cfg: dict, host: str) -> int:
    # Version simple : si host == "local" on collecte en local.
    # Plus tard, tu pourras ajouter WinRM/PowerShell distant.
    if host.lower() in ("localhost", "127.0.0.1", "local"):
        info = _collect_local_system_info()
    else:
        info = {"remote_host": host, "note": "TODO: interrogation distante"}

    info["timestamp"] = now_iso()
    info["target"] = host
    info["type"] = "windows_server_status"

    write_json(cfg["general"]["output_dir"], "diagnostic_windows", info)
    print_human_and_json(f"Etat Windows pour {host}", info)
    return ExitCode.OK

def check_ubuntu_server(cfg: dict, host: str) -> int:
    if host.lower() in ("localhost", "127.0.0.1", "local"):
        info = _collect_local_system_info()
    else:
        info = {"remote_host": host, "note": "TODO: interrogation distante (SSH)"}

    info["timestamp"] = now_iso()
    info["target"] = host
    info["type"] = "ubuntu_server_status"

    write_json(cfg["general"]["output_dir"], "diagnostic_ubuntu", info)
    print_human_and_json(f"Etat Ubuntu pour {host}", info)
    return ExitCode.OK
