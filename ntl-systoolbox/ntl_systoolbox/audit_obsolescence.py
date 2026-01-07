import csv
import ipaddress
import subprocess
from pathlib import Path
from .utils import now_iso, write_json, print_human_and_json, ExitCode

def scan_subnet(cfg: dict, subnet: str) -> int:
    net = ipaddress.ip_network(subnet, strict=False)
    results = []

    for ip in net.hosts():
        ip_str = str(ip)
        try:
            completed = subprocess.run(["ping", "-c", "1", "-W", "1", ip_str],
                                       capture_output=True, text=True)
            reachable = (completed.returncode == 0)
        except Exception:
            reachable = False

        # Détection OS simplifiée (placeholder)
        detected_os = None
        if reachable:
            # TODO: ajouter nmap ou autre, selon contraintes
            detected_os = "unknown"

        results.append({
            "ip": ip_str,
            "reachable": reachable,
            "os": detected_os,
        })

    data = {
        "timestamp": now_iso(),
        "type": "network_inventory",
        "subnet": subnet,
        "hosts": results,
    }
    write_json(cfg["general"]["output_dir"], "audit_inventory", data)
    print_human_and_json(f"Scan réseau {subnet} terminé.", data)
    return ExitCode.OK

def _load_eol_reference(path: str | Path) -> list[dict]:
    ref = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ref.append(row)
    return ref

def list_os_eol(cfg: dict, os_name: str) -> int:
    ref_file = cfg["audit"]["eol_reference_file"]
    ref = _load_eol_reference(ref_file)
    matches = [r for r in ref if r.get("os_name", "").lower() == os_name.lower()]

    data = {
        "timestamp": now_iso(),
        "type": "os_eol_list",
        "os_name": os_name,
        "results": matches,
    }
    write_json(cfg["general"]["output_dir"], "audit_os_eol", data)

    lines = [f"{r['os_name']} {r['version']} : fin de support {r['eol_date']}" for r in matches]
    human = "Versions connues pour cet OS:\n" + "\n".join(lines) if lines else "Aucune entrée trouvée."
    print_human_and_json(human, data)
    return ExitCode.OK

def audit_from_csv(cfg: dict, csv_path: str) -> int:
    ref_file = cfg["audit"]["eol_reference_file"]
    ref = _load_eol_reference(ref_file)

    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        components = list(reader)

    def find_eol(os_name, version):
        for r in ref:
            if r.get("os_name", "").lower() == os_name.lower() and r.get("version") == version:
                return r.get("eol_date")
        return None

    report = []
    for comp in components:
        os_name = comp.get("os_name")
        version = comp.get("version")
        eol = find_eol(os_name, version)
        status = "unknown"
        if eol:
            # TODO: comparer à la date du jour et classer: expired, soon, ok
            status = "known"
        report.append({
            "hostname": comp.get("hostname"),
            "ip": comp.get("ip"),
            "os_name": os_name,
            "version": version,
            "eol_date": eol,
            "status": status,
        })

    data = {
        "timestamp": now_iso(),
        "type": "obsolescence_audit",
        "components": report,
    }
    write_json(cfg["general"]["output_dir"], "audit_obsolescence", data)
    print_human_and_json("Audit d'obsolescence généré.", data)
    return ExitCode.OK
