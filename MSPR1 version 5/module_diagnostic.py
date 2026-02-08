"""
Module 1 - Diagnostic avec support à distance
Vérifie l'état des services critiques AD/DNS, MySQL et ressources système (local et distant)
"""

import subprocess
import platform
import json
import psutil
from datetime import datetime
import socket

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
            # Test DNS
            dns_test = self._test_dns(server_ip)
            check_result["details"]["dns"] = dns_test

            # Test connectivité LDAP (port 389 pour AD)
            ldap_test = self._test_port(server_ip, 389, "LDAP")
            check_result["details"]["ldap"] = ldap_test

            # Test Kerberos (port 88)
            kerberos_test = self._test_port(server_ip, 88, "Kerberos")
            check_result["details"]["kerberos"] = kerberos_test

            # Déterminer le statut global
            if all([dns_test["available"], ldap_test["available"], kerberos_test["available"]]):
                check_result["status"] = "OK"
            else:
                check_result["status"] = "DEGRADED"

        except Exception as e:
            check_result["status"] = "ERROR"
            check_result["error"] = str(e)

        self.results["checks"].append(check_result)
        return check_result

    def check_mysql_database(self, host, port=3306, database=None, user=None, password=None, use_ssl=False):
        """Teste le bon fonctionnement de la base de données MySQL"""
        check_result = {
            "type": "MySQL_Database",
            "host": host,
            "port": port,
            "timestamp": datetime.now().isoformat(),
            "status": "unknown",
            "details": {
                "ssl_enabled": use_ssl
            }
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

            if use_ssl:
                connection_params["ssl"] = {"ssl_disabled": False}

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

            cursor.execute("SHOW STATUS LIKE 'Ssl_cipher'")
            ssl_result = cursor.fetchone()
            if ssl_result and ssl_result[1]:
                check_result["details"]["ssl_cipher"] = ssl_result[1]
                check_result["details"]["ssl_active"] = True
            else:
                check_result["details"]["ssl_active"] = False

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

        # Mode distant via PowerShell Remoting
        if remote_ip and username and password:
            try:
                from pypsrp.client import Client

                check_result["details"]["mode"] = "remote"
                check_result["hostname"] = remote_ip

                # Connexion PowerShell
                client = Client(remote_ip, username=username, password=password, ssl=False)

                # Récupérer infos OS
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

                    # Disques
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

        # Mode local avec psutil
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

        # Mode distant via SSH
        if remote_ip and username and password:
            try:
                import paramiko

                check_result["details"]["mode"] = "remote"
                check_result["hostname"] = remote_ip

                # Connexion SSH
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(remote_ip, username=username, password=password, timeout=10)

                # Version OS
                stdin, stdout, stderr = ssh.exec_command('lsb_release -d')
                os_desc = stdout.read().decode().strip().replace('Description:\t', '')
                check_result["details"]["distribution"] = os_desc

                stdin, stdout, stderr = ssh.exec_command('uname -r')
                kernel = stdout.read().decode().strip()
                check_result["details"]["os_version"] = f"Linux {kernel}"

                # Uptime
                stdin, stdout, stderr = ssh.exec_command('cat /proc/uptime')
                uptime_data = stdout.read().decode().strip().split()[0]
                uptime_seconds = int(float(uptime_data))
                check_result["details"]["uptime_seconds"] = uptime_seconds
                check_result["details"]["uptime_formatted"] = self._format_uptime(uptime_seconds)

                # CPU
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

                # RAM
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

                # Disques
                stdin, stdout, stderr = ssh.exec_command('df -h -x tmpfs -x devtmpfs')
                disk_output = stdout.read().decode().strip().split('\n')[1:]  # Skip header

                disks = []
                for line in disk_output:
                    parts = line.split()
                    if len(parts) >= 6:
                        try:
                            size_str = parts[1].replace('G', '').replace('M', '').replace('T', '')
                            used_str = parts[2].replace('G', '').replace('M', '').replace('T', '')
                            avail_str = parts[3].replace('G', '').replace('M', '').replace('T', '')
                            usage_str = parts[4].replace('%', '')

                            # Convertir en GB
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

        # Mode local avec psutil
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
