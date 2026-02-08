#!/usr/bin/env python3
"""
module_diagnostic.py
Module 1 - Diagnostic NTL-SysToolbox
"""

import json
from datetime import datetime

# à adapter avec tes libs réelles
import socket
import platform


class DiagnosticModule:
    def __init__(self):
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "checks": [],
        }

    # ---------- helpers ----------

    def _add_check(self, name, target, status, details=None, error=None):
        self.results["checks"].append(
            {
                "name": name,
                "target": target,
                "status": status,
                "details": details or {},
                "error": error,
                "timestamp": datetime.now().isoformat(),
            }
        )

    def get_results_human(self) -> str:
        lines = ["=" * 70, "MODULE DIAGNOSTIC - RÉSULTATS", "=" * 70]
        lines.append(f"Horodatage: {self.results['timestamp']}\n")
        for i, check in enumerate(self.results["checks"], start=1):
            lines.append(f"[{i}] {check['name']} - Statut: {check['status']}")
            lines.append("-" * 70)
            lines.append(f"  Cible : {check['target']}")
            if check["error"]:
                lines.append(f"  ERREUR : {check['error']}")
            if check["details"]:
                for k, v in check["details"].items():
                    lines.append(f"  {k}: {v}")
            lines.append("")
        return "\n".join(lines)

    def get_results_json(self) -> str:
        return json.dumps(self.results, indent=2, ensure_ascii=False)

    # ---------- AD/DNS ----------

    def check_ad_dns_service(self, ip: str):
        # ici tu mets ta logique réelle (ports, DNS, LDAP, etc.)
        try:
            # simple ping/dns pour l'exemple
            socket.gethostbyaddr(ip)
            self._add_check(
                "AD_DNS",
                ip,
                "OK",
                details={"info": "Résolution DNS OK (exemple)"},
            )
        except Exception as e:
            self._add_check(
                "AD_DNS",
                ip,
                "ERROR",
                error=str(e),
            )

    # ---------- MySQL ----------

    def check_mysql_database(self, host, port=3306, database=None, user=None, password=None, use_ssl=False):
        # à adapter avec PyMySQL (tu l'as déjà)
        target = f"{user}@{host}:{port}"
        try:
            # placeholder : on simule une connexion OK
            details = {
                "database": database or "(none)",
                "ssl": use_ssl,
            }
            self._add_check("MySQL", target, "OK", details=details)
        except Exception as e:
            self._add_check("MySQL", target, "ERROR", error=str(e))

    # ---------- Windows Server ----------

    def check_windows_server(self, remote_ip=None, username=None, password=None):
        target = remote_ip or "local"
        try:
            # à remplacer par pypsrp / WinRM
            details = {
                "os": platform.platform(),
                "mode": "remote" if remote_ip else "local",
            }
            self._add_check("Windows_Server", target, "OK", details=details)
        except Exception as e:
            self._add_check("Windows_Server", target, "ERROR", error=str(e))

    # ---------- Ubuntu/Linux Server ----------

    def check_ubuntu_server(self, remote_ip=None, username=None, password=None):
        target = remote_ip or "local"
        try:
            # à remplacer par SSH Paramiko + commandes (free/df/etc.)
            details = {
                "os": platform.platform(),
                "mode": "remote" if remote_ip else "local",
            }
            self._add_check("Ubuntu_Server", target, "OK", details=details)
        except Exception as e:
            self._add_check("Ubuntu_Server", target, "ERROR", error=str(e))
