#!/usr/bin/env python3
"""
Module 1 - Diagnostic avec support à distance (AUTONOME)
Vérifie l'état des services critiques AD/DNS, MySQL et ressources système (local et distant)
"""

import subprocess
import platform
import json
import psutil
from datetime import datetime
import socket
import argparse
import sys
import os
from pathlib import Path

CONFIG_FILE = Path("ntl_config.json")

# ============================================================================
# CLASSE DIAGNOSTIC MODULE (Moteur)
# ============================================================================

class DiagnosticModule:
    def __init__(self):
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "module": "diagnostic",
            "checks": []
        }

    def check_ad_dns_service(self, server_ip):
        """Vérifie l'état des services AD/DNS sur un contrôleur de domaine"""
        check_result = {
            "type": "AD_DNS_Service",
            "server": server_ip,
            "timestamp": datetime.now().isoformat(),
            "status": "unknown",
            "details": {}
        }

        try:
            dns_test = self._test_dns(server_ip)
            check_result["details"]["dns"] = dns_test

            ldap_test = self._test_port(server_ip, 389, "LDAP")
            check_result["details"]["ldap"] = ldap_test

            kerberos_test = self._test_port(server_ip, 88, "Kerberos")
            check_result["details"]["kerberos"] = kerberos_test

            if all([dns_test["available"], ldap_test["available"], kerberos_test["available"]]):
                check_result["status"] = "OK"
            else:
                check_result["status"] = "DEGRADED"

        except Exception as e:
            check_result["status"] = "ERROR"
            check_result["error"] = str(e)

        self.results["checks"].append(check_result)
        return check_result

    def check_mysql_database(self, host, port=3306, database=None, user=None, password=None):
        """Teste le bon fonctionnement de la base de données MySQL"""
        check_result = {
            "type": "MySQL_Database",
            "host": host,
            "port": port,
            "timestamp": datetime.now().isoformat(),
            "status": "unknown",
            "details": {},
        }

        try:
            import pymysql

            connection_params = {
                "host": host,
                "port": port,
                "user": user if user else "root",
                "password": password if password else "",
                "connect_timeout": 5
            }

            if database:
                connection_params["database"] = database


            connection = pymysql.connect(**connection_params)
            cursor = connection.cursor()

            cursor.execute("SELECT VERSION()")
            version = cursor.fetchone()[0]
            check_result["details"]["version"] = version

            cursor.execute("SHOW GLOBAL STATUS LIKE 'Uptime'")
            uptime_result = cursor.fetchone()
            if uptime_result:
                uptime_seconds = int(uptime_result[1])
                check_result["details"]["uptime_seconds"] = uptime_seconds
                check_result["details"]["uptime_formatted"] = self._format_uptime(uptime_seconds)

            cursor.execute("SHOW GLOBAL STATUS LIKE 'Threads_connected'")
            connections_result = cursor.fetchone()
            if connections_result:
                connections = int(connections_result[1])
                check_result["details"]["active_connections"] = connections

            cursor.execute("SHOW GLOBAL STATUS LIKE 'Questions'")
            questions_result = cursor.fetchone()
            if questions_result:
                check_result["details"]["total_queries"] = int(questions_result[1])

            cursor.close()
            connection.close()

            check_result["status"] = "OK"

        except ImportError:
            check_result["status"] = "ERROR"
            check_result["error"] = "PyMySQL ou cryptography non installé"
        except Exception as e:
            check_result["status"] = "ERROR"
            check_result["error"] = str(e)

        self.results["checks"].append(check_result)
        return check_result

    def check_windows_server(self, hostname=None, remote_ip=None, username=None, password=None):
        """Vérifie les ressources d'un serveur Windows (local ou distant)"""
        check_result = {
            "type": "Windows_Server",
            "hostname": hostname if hostname else platform.node(),
            "remote_ip": remote_ip,
            "timestamp": datetime.now().isoformat(),
            "status": "unknown",
            "details": {}
        }

        if remote_ip and username and password:
            try:
                from pypsrp.client import Client

                check_result["details"]["mode"] = "remote"
                check_result["hostname"] = remote_ip

                client = Client(remote_ip, username=username, password=password, ssl=False)

                ps_script = """
                $os = Get-WmiObject Win32_OperatingSystem
                $cpu = Get-WmiObject Win32_Processor | Select-Object -First 1
                $memory = Get-WmiObject Win32_ComputerSystem
                $uptime = (Get-Date) - $os.ConvertToDateTime($os.LastBootUpTime)

                @{
                    OSVersion = $os.Caption
                    OSBuild = $os.Version
                    UptimeDays = [math]::Floor($uptime.TotalDays)
                    UptimeHours = $uptime.Hours
                    UptimeMinutes = $uptime.Minutes
                    CPUName = $cpu.Name
                    CPUCores = $cpu.NumberOfCores
                    CPULogicalProcessors = $cpu.NumberOfLogicalProcessors
                    TotalMemoryGB = [math]::Round($memory.TotalPhysicalMemory / 1GB, 2)
                    FreeMemoryGB = [math]::Round($os.FreePhysicalMemory / 1MB / 1024, 2)
                } | ConvertTo-Json
                """

                output, streams, had_errors = client.execute_ps(ps_script)

                if not had_errors and output:
                    import json as json_lib
                    data = json_lib.loads(output)

                    check_result["details"]["os_version"] = data.get("OSVersion", "Unknown")
                    check_result["details"]["os_build"] = data.get("OSBuild", "Unknown")

                    uptime_seconds = (data.get("UptimeDays", 0) * 86400 + 
                                    data.get("UptimeHours", 0) * 3600 + 
                                    data.get("UptimeMinutes", 0) * 60)
                    check_result["details"]["uptime_seconds"] = uptime_seconds
                    check_result["details"]["uptime_formatted"] = self._format_uptime(uptime_seconds)

                    check_result["details"]["cpu"] = {
                        "name": data.get("CPUName", "Unknown"),
                        "count": data.get("CPUCores", 0),
                        "count_logical": data.get("CPULogicalProcessors", 0)
                    }

                    total_mem = data.get("TotalMemoryGB", 0)
                    free_mem = data.get("FreeMemoryGB", 0)
                    used_mem = total_mem - free_mem

                    check_result["details"]["ram"] = {
                        "total_gb": total_mem,
                        "used_gb": round(used_mem, 2),
                        "available_gb": free_mem,
                        "usage_percent": round((used_mem / total_mem * 100), 2) if total_mem > 0 else 0
                    }

                    disk_script = """
                    Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" | 
                    Select-Object DeviceID, VolumeName, 
                        @{Name='SizeGB';Expression={[math]::Round($_.Size/1GB,2)}},
                        @{Name='FreeGB';Expression={[math]::Round($_.FreeSpace/1GB,2)}},
                        @{Name='UsedGB';Expression={[math]::Round(($_.Size - $_.FreeSpace)/1GB,2)}},
                        @{Name='UsedPercent';Expression={[math]::Round((($_.Size - $_.FreeSpace)/$_.Size)*100,2)}} |
                    ConvertTo-Json
                    """

                    disk_output, disk_streams, disk_errors = client.execute_ps(disk_script)

                    if not disk_errors and disk_output:
                        disk_data = json_lib.loads(disk_output)
                        if not isinstance(disk_data, list):
                            disk_data = [disk_data]

                        disks = []
                        for disk in disk_data:
                            disks.append({
                                "device": disk.get("DeviceID", ""),
                                "mountpoint": disk.get("DeviceID", ""),
                                "label": disk.get("VolumeName", ""),
                                "total_gb": disk.get("SizeGB", 0),
                                "used_gb": disk.get("UsedGB", 0),
                                "free_gb": disk.get("FreeGB", 0),
                                "usage_percent": disk.get("UsedPercent", 0)
                            })

                        check_result["details"]["disks"] = disks

                    check_result["status"] = "OK"
                else:
                    check_result["status"] = "ERROR"
                    check_result["error"] = "Erreur PowerShell: " + str(streams.error)

            except ImportError:
                check_result["status"] = "ERROR"
                check_result["error"] = "pypsrp non installé. Installer avec: pip install pypsrp"
            except Exception as e:
                check_result["status"] = "ERROR"
                check_result["error"] = f"Erreur connexion PowerShell: {str(e)}"

        else:
            if platform.system() != "Windows":
                check_result["status"] = "ERROR"
                check_result["error"] = "Cette fonction nécessite Windows (ou spécifier remote_ip)"
                self.results["checks"].append(check_result)
                return check_result

            try:
                check_result["details"]["mode"] = "local"
                check_result["details"]["os_version"] = f"{platform.system()} {platform.release()}"
                check_result["details"]["os_details"] = platform.version()

                uptime_seconds = psutil.boot_time()
                uptime = datetime.now().timestamp() - uptime_seconds
                check_result["details"]["uptime_seconds"] = int(uptime)
                check_result["details"]["uptime_formatted"] = self._format_uptime(int(uptime))

                cpu_percent = psutil.cpu_percent(interval=1)
                check_result["details"]["cpu"] = {
                    "usage_percent": cpu_percent,
                    "count": psutil.cpu_count(),
                    "count_logical": psutil.cpu_count(logical=True)
                }

                memory = psutil.virtual_memory()
                check_result["details"]["ram"] = {
                    "total_gb": round(memory.total / (1024**3), 2),
                    "used_gb": round(memory.used / (1024**3), 2),
                    "available_gb": round(memory.available / (1024**3), 2),
                    "usage_percent": memory.percent
                }

                disks = []
                for partition in psutil.disk_partitions():
                    try:
                        usage = psutil.disk_usage(partition.mountpoint)
                        disks.append({
                            "device": partition.device,
                            "mountpoint": partition.mountpoint,
                            "fstype": partition.fstype,
                            "total_gb": round(usage.total / (1024**3), 2),
                            "used_gb": round(usage.used / (1024**3), 2),
                            "free_gb": round(usage.free / (1024**3), 2),
                            "usage_percent": usage.percent
                        })
                    except PermissionError:
                        continue

                check_result["details"]["disks"] = disks
                check_result["status"] = "OK"

            except Exception as e:
                check_result["status"] = "ERROR"
                check_result["error"] = str(e)

        self.results["checks"].append(check_result)
        return check_result

    def check_ubuntu_server(self, hostname=None, remote_ip=None, username=None, password=None):
        """Vérifie les ressources d'un serveur Ubuntu (local ou distant)"""
        check_result = {
            "type": "Ubuntu_Server",
            "hostname": hostname if hostname else platform.node(),
            "remote_ip": remote_ip,
            "timestamp": datetime.now().isoformat(),
            "status": "unknown",
            "details": {}
        }

        if remote_ip and username and password:
            try:
                import paramiko

                check_result["details"]["mode"] = "remote"
                check_result["hostname"] = remote_ip

                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(remote_ip, username=username, password=password, timeout=10)

                stdin, stdout, stderr = ssh.exec_command('lsb_release -d')
                os_desc = stdout.read().decode().strip().replace('Description:\t', '')
                check_result["details"]["distribution"] = os_desc

                stdin, stdout, stderr = ssh.exec_command('uname -r')
                kernel = stdout.read().decode().strip()
                check_result["details"]["os_version"] = f"Linux {kernel}"

                stdin, stdout, stderr = ssh.exec_command('cat /proc/uptime')
                uptime_data = stdout.read().decode().strip().split()[0]
                uptime_seconds = int(float(uptime_data))
                check_result["details"]["uptime_seconds"] = uptime_seconds
                check_result["details"]["uptime_formatted"] = self._format_uptime(uptime_seconds)

                stdin, stdout, stderr = ssh.exec_command('nproc')
                cpu_count = int(stdout.read().decode().strip())

                stdin, stdout, stderr = ssh.exec_command("top -bn1 | grep 'Cpu(s)' | awk '{print $2}'")
                cpu_usage = stdout.read().decode().strip().replace('%us,', '')
                try:
                    cpu_percent = float(cpu_usage)
                except:
                    cpu_percent = 0

                check_result["details"]["cpu"] = {
                    "usage_percent": cpu_percent,
                    "count": cpu_count,
                    "count_logical": cpu_count
                }

                stdin, stdout, stderr = ssh.exec_command('free -m')
                ram_output = stdout.read().decode().strip().split('\n')[1].split()
                total_ram = int(ram_output[1])
                used_ram = int(ram_output[2])
                available_ram = int(ram_output[6])

                check_result["details"]["ram"] = {
                    "total_gb": round(total_ram / 1024, 2),
                    "used_gb": round(used_ram / 1024, 2),
                    "available_gb": round(available_ram / 1024, 2),
                    "usage_percent": round((used_ram / total_ram * 100), 2) if total_ram > 0 else 0
                }

                stdin, stdout, stderr = ssh.exec_command('df -h -x tmpfs -x devtmpfs')
                disk_output = stdout.read().decode().strip().split('\n')[1:]

                disks = []
                for line in disk_output:
                    parts = line.split()
                    if len(parts) >= 6:
                        try:
                            size_str = parts[1].replace('G', '').replace('M', '').replace('T', '')
                            used_str = parts[2].replace('G', '').replace('M', '').replace('T', '')
                            avail_str = parts[3].replace('G', '').replace('M', '').replace('T', '')
                            usage_str = parts[4].replace('%', '')

                            if 'T' in parts[1]:
                                total_gb = float(size_str) * 1024
                            elif 'M' in parts[1]:
                                total_gb = float(size_str) / 1024
                            else:
                                total_gb = float(size_str)

                            if 'T' in parts[2]:
                                used_gb = float(used_str) * 1024
                            elif 'M' in parts[2]:
                                used_gb = float(used_str) / 1024
                            else:
                                used_gb = float(used_str)

                            if 'T' in parts[3]:
                                free_gb = float(avail_str) * 1024
                            elif 'M' in parts[3]:
                                free_gb = float(avail_str) / 1024
                            else:
                                free_gb = float(avail_str)

                            disks.append({
                                "device": parts[0],
                                "mountpoint": parts[5],
                                "total_gb": round(total_gb, 2),
                                "used_gb": round(used_gb, 2),
                                "free_gb": round(free_gb, 2),
                                "usage_percent": float(usage_str)
                            })
                        except:
                            continue

                check_result["details"]["disks"] = disks

                ssh.close()
                check_result["status"] = "OK"

            except ImportError:
                check_result["status"] = "ERROR"
                check_result["error"] = "paramiko non installé. Installer avec: pip install paramiko"
            except Exception as e:
                check_result["status"] = "ERROR"
                check_result["error"] = f"Erreur connexion SSH: {str(e)}"

        else:
            if platform.system() != "Linux":
                check_result["status"] = "ERROR"
                check_result["error"] = "Cette fonction nécessite Linux (ou spécifier remote_ip)"
                self.results["checks"].append(check_result)
                return check_result

            try:
                check_result["details"]["mode"] = "local"
                check_result["details"]["os_version"] = f"{platform.system()} {platform.release()}"

                try:
                    with open('/etc/os-release', 'r') as f:
                        os_release = dict(line.strip().replace('"', '').split('=', 1) 
                                        for line in f if '=' in line)
                        check_result["details"]["distribution"] = os_release.get('PRETTY_NAME', 'Unknown')
                except:
                    check_result["details"]["distribution"] = "Unknown"

                uptime_seconds = psutil.boot_time()
                uptime = datetime.now().timestamp() - uptime_seconds
                check_result["details"]["uptime_seconds"] = int(uptime)
                check_result["details"]["uptime_formatted"] = self._format_uptime(int(uptime))

                cpu_percent = psutil.cpu_percent(interval=1)
                check_result["details"]["cpu"] = {
                    "usage_percent": cpu_percent,
                    "count": psutil.cpu_count(),
                    "count_logical": psutil.cpu_count(logical=True)
                }

                memory = psutil.virtual_memory()
                check_result["details"]["ram"] = {
                    "total_gb": round(memory.total / (1024**3), 2),
                    "used_gb": round(memory.used / (1024**3), 2),
                    "available_gb": round(memory.available / (1024**3), 2),
                    "usage_percent": memory.percent
                }

                disks = []
                for partition in psutil.disk_partitions():
                    try:
                        usage = psutil.disk_usage(partition.mountpoint)
                        disks.append({
                            "device": partition.device,
                            "mountpoint": partition.mountpoint,
                            "fstype": partition.fstype,
                            "total_gb": round(usage.total / (1024**3), 2),
                            "used_gb": round(usage.used / (1024**3), 2),
                            "free_gb": round(usage.free / (1024**3), 2),
                            "usage_percent": usage.percent
                        })
                    except PermissionError:
                        continue

                check_result["details"]["disks"] = disks
                check_result["status"] = "OK"

            except Exception as e:
                check_result["status"] = "ERROR"
                check_result["error"] = str(e)

        self.results["checks"].append(check_result)
        return check_result

    def _test_dns(self, dns_server):
        """Teste la résolution DNS"""
        try:
            return self._test_port(dns_server, 53, "DNS")
        except Exception as e:
            return {"available": False, "error": str(e)}

    def _test_port(self, host, port, service_name):
        """Teste la disponibilité d'un port"""
        result = {
            "service": service_name,
            "port": port,
            "available": False,
            "response_time_ms": None
        }

        try:
            start_time = datetime.now()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result_code = sock.connect_ex((host, port))
            end_time = datetime.now()
            sock.close()

            if result_code == 0:
                result["available"] = True
                result["response_time_ms"] = int((end_time - start_time).total_seconds() * 1000)

        except Exception as e:
            result["error"] = str(e)

        return result

    def _format_uptime(self, seconds):
        """Formate l'uptime en jours, heures, minutes"""
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        minutes = (seconds % 3600) // 60
        return f"{days}j {hours}h {minutes}min"

    def get_results_json(self):
        """Retourne les résultats au format JSON"""
        return json.dumps(self.results, indent=2, ensure_ascii=False)

    def get_results_human(self):
        """Retourne les résultats dans un format lisible"""
        output = []
        output.append("=" * 70)
        output.append("MODULE DIAGNOSTIC - RÉSULTATS")
        output.append("=" * 70)
        output.append(f"Horodatage: {self.results['timestamp']}")
        output.append("")

        for idx, check in enumerate(self.results['checks'], 1):
            output.append(f"[{idx}] {check['type']} - Statut: {check['status']}")
            output.append("-" * 70)

            if check['type'] == 'AD_DNS_Service':
                output.append(f"  Serveur: {check['server']}")
                if 'details' in check:
                    for service, info in check['details'].items():
                        if isinstance(info, dict) and 'available' in info:
                            status = "✓ OK" if info['available'] else "✗ ERREUR"
                            output.append(f"  {service.upper()}: {status}")
                            if info['available'] and 'response_time_ms' in info:
                                output.append(f"    Temps de réponse: {info['response_time_ms']} ms")

            elif check['type'] == 'MySQL_Database':
                output.append(f"  Hôte: {check['host']}:{check['port']}")
                if 'details' in check:
                    details = check['details']
                    if 'version' in details:
                        output.append(f"  Version: {details['version']}")
                    if 'uptime_formatted' in details:
                        output.append(f"  Uptime: {details['uptime_formatted']}")
                    if 'active_connections' in details:
                        output.append(f"  Connexions actives: {details['active_connections']}")
                    if 'ssl_enabled' in details:
                        ssl_status = "Activé" if details['ssl_enabled'] else "Désactivé"
                        output.append(f"  SSL configuré: {ssl_status}")
                    if 'ssl_active' in details:
                        ssl_active = "✓ Oui" if details['ssl_active'] else "✗ Non"
                        output.append(f"  SSL actif: {ssl_active}")
                        if details.get('ssl_cipher'):
                            output.append(f"  Chiffrement SSL: {details['ssl_cipher']}")
                    if 'total_queries' in details:
                        output.append(f"  Requêtes totales: {details['total_queries']}")

            elif check['type'] in ['Windows_Server', 'Ubuntu_Server']:
                output.append(f"  Hostname: {check['hostname']}")
                if check.get('remote_ip'):
                    output.append(f"  IP distante: {check['remote_ip']}")
                if 'details' in check:
                    details = check['details']
                    if 'mode' in details:
                        mode_text = "🌐 Distant" if details['mode'] == 'remote' else "💻 Local"
                        output.append(f"  Mode: {mode_text}")
                    if 'os_version' in details:
                        output.append(f"  OS: {details['os_version']}")
                    if 'distribution' in details:
                        output.append(f"  Distribution: {details['distribution']}")
                    if 'uptime_formatted' in details:
                        output.append(f"  Uptime: {details['uptime_formatted']}")

                    if 'cpu' in details:
                        cpu = details['cpu']
                        if 'usage_percent' in cpu:
                            output.append(f"  CPU: {cpu['usage_percent']}% utilisé ({cpu.get('count_logical', 'N/A')} cœurs)")
                        elif 'name' in cpu:
                            output.append(f"  CPU: {cpu['name']} ({cpu.get('count_logical', 'N/A')} cœurs)")

                    if 'ram' in details:
                        ram = details['ram']
                        output.append(f"  RAM: {ram['used_gb']} GB / {ram['total_gb']} GB ({ram['usage_percent']}%)")

                    if 'disks' in details:
                        output.append("  Disques:")
                        for disk in details['disks']:
                            label = f" [{disk.get('label')}]" if disk.get('label') else ""
                            output.append(f"    {disk['device']}{label} ({disk['mountpoint']}): "
                                        f"{disk['used_gb']} GB / {disk['total_gb']} GB ({disk['usage_percent']}%)")

            if 'error' in check:
                output.append(f"  ERREUR: {check['error']}")

            output.append("")

        output.append("=" * 70)
        return "\n".join(output)

    def get_exit_code(self):
        """Retourne un code de sortie basé sur les résultats"""
        statuses = [check.get('status') for check in self.results['checks']]

        if 'ERROR' in statuses:
            return 2
        elif 'DEGRADED' in statuses:
            return 1
        elif 'OK' in statuses:
            return 0
        else:
            return 3


# ============================================================================
# INTERFACE CLI (Menu interactif + argparse)
# ============================================================================

class DiagnosticCLI:
    """Interface CLI complète avec menu interactif"""
    
    def __init__(self):
        self.diag = DiagnosticModule()
        self.config = self._load_config()
        self.last_check_type = None
        self._setup_backup_folders()
    
    def _setup_backup_folders(self):
        """Crée l'arborescence de dossiers de sauvegarde"""
        self.backup_folders = {
            'ad_dns': Path("backups/ad_dns"),
            'mysql': Path("backups/mysql"),
            'windows': Path("backups/windows"),
            'ubuntu': Path("backups/ubuntu"),
            'global': Path("backups/global"),
        }
        for folder in self.backup_folders.values():
            folder.mkdir(parents=True, exist_ok=True)
    
    def _load_config(self):
        """Charge config JSON (partagée avec main.py)"""
        defaults = {
            "dc01_ip": "192.168.10.10",
            "dc02_ip": "192.168.10.11",
            "wms_db_host": "192.168.10.21",
            "wms_db_port": 3306,
            "wms_db_user": "ntlsystoolbox",
            "wms_db_pass": "",
            "wms_db_ssl": False,
            "windows_default_user": "Administrator",
            "ubuntu_default_user": "admin",
        }
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, 'r') as f:
                    data = json.load(f).get("infrastructure", {})
                defaults.update(data)
            except:
                pass
        return defaults
    
    def cli_menu(self):
        """Menu interactif principal"""
        while True:
            self._clear_screen()
            self._banner()
            print("MODULE 1 - DIAGNOSTIC SYSTÈME")
            print("-" * 70)
            print(f"  [1] AD/DNS DC01 ({self.config['dc01_ip']})")
            print(f"  [2] AD/DNS DC02 ({self.config['dc02_ip']})")
            print(f"  [3] MySQL WMS ({self.config['wms_db_host']}:{self.config['wms_db_port']})")
            print("  [4] Diagnostic Windows (local ou distant)")
            print("  [5] Diagnostic Ubuntu/Linux (local ou distant)")
            print("  [6] Diagnostic global NTL")
            print("  [S] Sauvegarder dernier résultat")
            print("  [0] Quitter")
            print("-" * 70)
            
            choice = input("Choix: ").strip().upper()
            
            if choice == "0":
                break
            elif choice == "1":
                self._check_ad_dns(self.config["dc01_ip"])
            elif choice == "2":
                self._check_ad_dns(self.config["dc02_ip"])
            elif choice == "3":
                self._check_mysql()
            elif choice == "4":
                self._check_windows()
            elif choice == "5":
                self._check_ubuntu()
            elif choice == "6":
                self._check_global()
            elif choice == "S":
                self._save_results()
            else:
                print("\n[!] Option invalide.")
                input("Entrée...")
    
    def _check_ad_dns(self, ip):
        """Vérification AD/DNS"""
        self._clear_screen()
        self._banner()
        print(f"VÉRIFICATION AD/DNS sur {ip}")
        print("-" * 70)
        print("\n[+] Analyse en cours...")

        self.diag = DiagnosticModule()
        self.diag.check_ad_dns_service(ip)
        self.last_check_type = "ad_dns"
        print(self.diag.get_results_human())
        input("\nEntrée...")
    
    def _check_mysql(self):
        """Test MySQL"""
        self._clear_screen()
        self._banner()
        print("TEST MYSQL WMS")
        print("-" * 70)
        print(f"Hôte: {self.config['wms_db_host']}:{self.config['wms_db_port']}")
        print(f"User: {self.config['wms_db_user']}")
        
        override_pass = input("Mot de passe (Entrée=config): ").strip()
        password = override_pass if override_pass else self.config.get("wms_db_pass", "")
        
        print("\n[+] Connexion...")
        self.diag = DiagnosticModule()
        self.diag.check_mysql_database(
            self.config['wms_db_host'],
            self.config['wms_db_port'],
            None,
            self.config['wms_db_user'],
            password,

        )
        self.last_check_type = "mysql"
        print(self.diag.get_results_human())
        input("\nEntrée...")
    
    def _check_windows(self):
        """Diagnostic Windows"""
        self._clear_screen()
        self._banner()
        print("DIAGNOSTIC WINDOWS")
        print("-" * 70)
        
        remote_ip = input("IP serveur (Entrée=local): ").strip()

        self.diag = DiagnosticModule()
        if remote_ip:
            user = input(f"User [{self.config['windows_default_user']}]: ").strip() or self.config['windows_default_user']
            password = input("Mot de passe: ").strip()
            print("\n[+] Connexion distante...")
            self.diag.check_windows_server(hostname=None, remote_ip=remote_ip, username=user, password=password)
        else:
            print("\n[+] Diagnostic local...")
            self.diag.check_windows_server()
        
        self.last_check_type = "windows"
        print(self.diag.get_results_human())
        input("\nEntrée...")
    
    def _check_ubuntu(self):
        """Diagnostic Ubuntu"""
        self._clear_screen()
        self._banner()
        print("DIAGNOSTIC UBUNTU/LINUX")
        print("-" * 70)
        
        remote_ip = input("IP serveur (Entrée=local): ").strip()

        self.diag = DiagnosticModule()
        if remote_ip:
            user = input(f"User SSH [{self.config['ubuntu_default_user']}]: ").strip() or self.config['ubuntu_default_user']
            password = input("Mot de passe SSH: ").strip()
            print("\n[+] Connexion SSH...")
            self.diag.check_ubuntu_server(hostname=None, remote_ip=remote_ip, username=user, password=password)
        else:
            print("\n[+] Diagnostic local...")
            self.diag.check_ubuntu_server()
        
        self.last_check_type = "ubuntu"
        print(self.diag.get_results_human())
        input("\nEntrée...")
    
    def _check_global(self):
        """Diagnostic global NTL"""
        self._clear_screen()
        self._banner()
        print("DIAGNOSTIC GLOBAL NTL")
        print("-" * 70)
        print(f"DC01: {self.config['dc01_ip']}")
        print(f"DC02: {self.config['dc02_ip']}")
        print(f"MySQL: {self.config['wms_db_host']}")
        print("Serveur local")
        
        if input("\nContinuer? (o/n) [o]: ").strip().lower() == "n":
            return
        
        print("\n[+] Diagnostic global...")
        self.diag = DiagnosticModule()
        self.diag.check_ad_dns_service(self.config["dc01_ip"])
        self.diag.check_ad_dns_service(self.config["dc02_ip"])
        self.diag.check_mysql_database(
            self.config["wms_db_host"],
            self.config["wms_db_port"],
            None,
            self.config["wms_db_user"],
            self.config["wms_db_pass"],
        )
        
        if platform.system() == "Windows":
            self.diag.check_windows_server()
        else:
            self.diag.check_ubuntu_server()
        
        self.last_check_type = "global"
        print(self.diag.get_results_human())
        input("\nEntrée...")
    
    def _save_results(self):
        """Sauvegarde les résultats du dernier diagnostic dans le dossier approprié"""
        
        if not self.diag.results.get("checks"):
            print("\n[!] Aucun résultat à sauvegarder.")
            print("    Effectuez d'abord un diagnostic (options 1-6).")
            input("\nEntrée...")
            return
        
        if not self.last_check_type:
            print("\n[!] Type de diagnostic inconnu.")
            print("    Effectuez d'abord un diagnostic avant de sauvegarder.")
            input("\nEntrée...")
            return
        
        backup_folder = self.backup_folders.get(self.last_check_type, Path("backups"))
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"{self.last_check_type}_{timestamp}"
        json_file = backup_folder / f"{base_filename}.json"
        txt_file = backup_folder / f"{base_filename}.txt"
        
        try:
            with open(json_file, "w", encoding="utf-8") as f:
                f.write(self.diag.get_results_json())
            
            with open(txt_file, "w", encoding="utf-8") as f:
                f.write(self.diag.get_results_human())
            
            print("\n" + "=" * 70)
            print("✓ SAUVEGARDE RÉUSSIE")
            print("=" * 70)
            print(f"Type de diagnostic : {self.last_check_type.upper()}")
            print(f"Dossier            : {backup_folder}/")
            print(f"Fichier JSON       : {json_file.name}")
            print(f"Fichier TXT        : {txt_file.name}")
            print("=" * 70)
            
        except Exception as e:
            print("\n" + "=" * 70)
            print("✗ ERREUR DE SAUVEGARDE")
            print("=" * 70)
            print(f"Erreur: {e}")
            print("=" * 70)
        
        input("\nAppuyez sur Entrée pour continuer...")
    
    def _clear_screen(self):
        os.system("cls" if os.name == "nt" else "clear")
    
    def _banner(self):
        print("=" * 70)
        print(" NTL-SysToolbox - MODULE 1 DIAGNOSTIC")
        print("=" * 70)
        print()


# ============================================================================
# CLI ARGPARSE (Usage direct en ligne de commande)
# ============================================================================

def create_parser():
    """Crée parser argparse pour CLI direct"""
    parser = argparse.ArgumentParser(
        prog="module_diagnostic.py",
        description="Module 1 - Diagnostic NTL (AD/DNS, MySQL, Windows/Ubuntu)"
    )
    
    parser.add_argument("--menu", action="store_true", help="Lance le menu interactif")
    parser.add_argument("--json", action="store_true", help="Sortie JSON (sinon humain)")
    
    subparsers = parser.add_subparsers(dest="command", help="Commandes disponibles")
    
    # AD/DNS
    dns_parser = subparsers.add_parser("ad-dns", help="Vérification AD/DNS")
    dns_parser.add_argument("server_ip", help="IP contrôleur domaine")
    
    # MySQL
    mysql_parser = subparsers.add_parser("mysql", help="Test MySQL")
    mysql_parser.add_argument("--host", default="127.0.0.1")
    mysql_parser.add_argument("--port", type=int, default=3306)
    mysql_parser.add_argument("--user", default="root")
    mysql_parser.add_argument("--password", default="")
    
    # Windows
    win_parser = subparsers.add_parser("windows", help="Serveur Windows")
    win_parser.add_argument("--ip", dest="remote_ip", help="IP distante (local si absent)")
    win_parser.add_argument("-u", "--user", default="Administrator")
    win_parser.add_argument("-p", "--password")
    
    # Ubuntu
    ubuntu_parser = subparsers.add_parser("ubuntu", help="Serveur Ubuntu")
    ubuntu_parser.add_argument("--ip", dest="remote_ip", help="IP distante (local si absent)")
    ubuntu_parser.add_argument("-u", "--user", default="admin")
    ubuntu_parser.add_argument("-p", "--password")
    
    return parser


def main():
    """Point d'entrée principal"""
    parser = create_parser()
    args = parser.parse_args()
    
    # Mode menu interactif
    if args.menu or not args.command:
        cli = DiagnosticCLI()
        cli.cli_menu()
        return
    
    # Mode CLI direct
    diag = DiagnosticModule()
    
    if args.command == "ad-dns":
        diag.check_ad_dns_service(args.server_ip)

    elif args.command == "mysql":
        diag.check_mysql_database(args.host, args.port, None, args.user, args.password)
    
    elif args.command == "windows":
        if args.remote_ip:
            diag.check_windows_server(hostname=None, remote_ip=args.remote_ip, username=args.user, password=args.password)
        else:
            diag.check_windows_server()
    
    elif args.command == "ubuntu":
        if args.remote_ip:
            diag.check_ubuntu_server(hostname=None, remote_ip=args.remote_ip, username=args.user, password=args.password)
        else:
            diag.check_ubuntu_server()
    
    # Affichage résultats
    if hasattr(args, 'json') and args.json:
        print(diag.get_results_json())
    else:
        print(diag.get_results_human())
    
    sys.exit(diag.get_exit_code())


if __name__ == "__main__":
    main()
