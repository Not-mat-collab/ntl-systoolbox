import sys
import os
import nmap
import ipaddress
import socket
import subprocess
import platform
import re
import pandas as pd
import csv
import json
import io
import traceback
from pathlib import Path
from datetime import date, datetime
from typing import List, Dict, Optional, Tuple
import requests
from requests.exceptions import RequestException


class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
    
    # ✅ MODIFIÉ: args nmap améliorés + -sV pour bannières de services
    def scan_range(self, ip_range: str, ports: str = "22,80,443,3389,135,139,445") -> List[Dict]:
        print(f"Scan de la plage réseau: {ip_range}")
        print("Cela peut prendre quelques minutes...")
        hosts = []
        try:
            # -sV détecte les versions de services (crucial pour déduire l'OS)
            # --osscan-guess systématique + T4 plus rapide
            self.nm.scan(hosts=ip_range, arguments=f'-sS -sV -O --osscan-guess -T4 --version-intensity 5 -p {ports}')
            for host in self.nm.all_hosts():
                host_info = {
                    'ip': host,
                    'hostname': self._get_hostname(host),
                    'state': self.nm[host].state(),
                    'mac': self._get_mac_address(host),
                    'vendor': self._get_vendor(host),
                    'open_ports': self._get_open_ports(host),
                    'os_info': self._get_os_info(host)
                }
                hosts.append(host_info)
                print(f"  Hôte détecté: {host} ({host_info['hostname']})")
        except Exception as e:
            print(f"Erreur lors du scan: {e}")
            hosts = self._simple_ping_scan(ip_range)
        return hosts
    
    # ✅ MODIFIÉ: Nmap hostname en priorité, puis DNS, puis IP (plus jamais "Unknown")
    def _get_hostname(self, ip: str) -> str:
        # 1) Hostname récupéré directement par Nmap (le plus fiable)
        try:
            hn = self.nm[ip].hostname()
            if hn:
                return hn
        except:
            pass
        # 2) Résolution DNS inverse
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname:
                return hostname
        except:
            pass
        # 3) Fallback: retourne l'IP (jamais "Unknown")
        return ip
    
    def _get_mac_address(self, ip: str) -> Optional[str]:
        try:
            if 'mac' in self.nm[ip]['addresses']:
                return self.nm[ip]['addresses']['mac']
        except:
            pass
        return None
    
    def _get_vendor(self, ip: str) -> Optional[str]:
        try:
            if 'vendor' in self.nm[ip]:
                vendors = self.nm[ip]['vendor']
                if vendors:
                    return list(vendors.values())[0]
        except:
            pass
        return None
    
    def _get_open_ports(self, ip: str) -> List[int]:
        open_ports = []
        try:
            for proto in self.nm[ip].all_protocols():
                ports = self.nm[ip][proto].keys()
                for port in ports:
                    if self.nm[ip][proto][port]['state'] == 'open':
                        open_ports.append(port)
        except:
            pass
        return sorted(open_ports)
    
    # ✅ MODIFIÉ: meilleure exploitation d'osclass + heuristique via services -sV
    def _get_os_info(self, ip: str) -> Dict:
        os_info = {
            'os_family': None,
            'os_gen': None,
            'os_details': None,
            'accuracy': None,
            'build_number': None
        }
        try:
            # --- osmatch (méthode principale) ---
            if 'osmatch' in self.nm[ip]:
                os_matches = self.nm[ip]['osmatch']
                if os_matches:
                    best_match = max(os_matches, key=lambda x: x.get('accuracy', 0))
                    os_info['os_details'] = best_match.get('name', 'Unknown')
                    os_info['accuracy'] = best_match.get('accuracy', 0)
                    name = best_match.get('name', '').lower()
                    build_match = re.search(r'build[\s_]?(\d+)', name)
                    if build_match:
                        os_info['build_number'] = int(build_match.group(1))
                    if 'windows' in name:
                        os_info['os_family'] = 'Windows'
                        os_info['os_gen'] = self._extract_windows_version(name)
                    elif any(kw in name for kw in ['linux', 'ubuntu', 'debian', 'centos',
                                                    'red hat', 'rhel', 'fedora', 'suse',
                                                    'kali', 'arch', 'mint', 'rocky', 'alma']):
                        os_info['os_family'] = 'Linux'
                        os_info['os_gen'] = self._extract_linux_version(name)
                    elif 'macos' in name or 'mac os' in name:
                        os_info['os_family'] = 'macOS'
                        os_info['os_gen'] = self._extract_macos_version(name)

            # --- osclass (complément si osmatch insuffisant) ---
            if 'osclass' in self.nm[ip]:
                os_classes = self.nm[ip]['osclass']
                if os_classes:
                    best_class = max(os_classes, key=lambda x: x.get('accuracy', 0))
                    class_accuracy = int(best_class.get('accuracy', 0))
                    current_accuracy = int(os_info.get('accuracy') or 0)

                    if class_accuracy >= current_accuracy:
                        os_type       = best_class.get('type', '').lower()
                        os_vendor_cls = best_class.get('vendor', '').lower()
                        os_family_cls = best_class.get('osfamily', '').lower()
                        os_gen_cls    = best_class.get('osgen', '')

                        if 'windows' in os_type or 'windows' in os_vendor_cls or 'windows' in os_family_cls:
                            if not os_info['os_family']:
                                os_info['os_family'] = 'Windows'
                            if not os_info['os_gen'] and os_gen_cls:
                                os_info['os_gen'] = self._extract_windows_version(os_gen_cls.lower())

                        elif any(kw in os_family_cls for kw in ['linux', 'ubuntu', 'debian', 'centos',
                                                                  'red hat', 'rhel', 'fedora']):
                            if not os_info['os_family']:
                                os_info['os_family'] = 'Linux'
                            if not os_info['os_gen'] and os_gen_cls:
                                os_info['os_gen'] = self._extract_linux_version(os_gen_cls.lower())

            # --- Heuristique via services détectés par -sV (nouveau) ---
            if not os_info['os_family']:
                os_info['os_family'] = self._guess_family_from_services(ip)

        except Exception as e:
            pass
        return os_info

    # ✅ NOUVEAU: heuristique OS via bannières de services (-sV)
    def _guess_family_from_services(self, ip: str) -> Optional[str]:
        """Déduit la famille OS depuis les services détectés par -sV."""
        try:
            for proto in self.nm[ip].all_protocols():
                for port in self.nm[ip][proto]:
                    svc = self.nm[ip][proto][port]
                    product = (svc.get('product', '') + ' ' + svc.get('version', '') +
                               ' ' + svc.get('extrainfo', '')).lower()
                    if any(kw in product for kw in ['windows', 'microsoft', 'iis', 'rdp']):
                        return 'Windows'
                    if any(kw in product for kw in ['linux', 'ubuntu', 'debian', 'centos',
                                                     'openssh', 'apache', 'nginx']):
                        return 'Linux'
        except:
            pass
        # Heuristique ports en dernier recours
        try:
            open_ports = set(self._get_open_ports(ip))
            if {445, 3389, 135, 139} & open_ports:
                return 'Windows'
            if {22} & open_ports:
                return 'Linux'
        except:
            pass
        return None
    
    def _extract_windows_version(self, name: str) -> Optional[str]:
        name_lower = name.lower()
        build_match = re.search(r'build[\s_]?(\d+)', name_lower)
        build_number = None
        if build_match:
            build_number = int(build_match.group(1))
        if build_number:
            if build_number >= 22000:
                return f"Windows 11 (Build {build_number})"
            elif build_number >= 10240:
                return f"Windows 10 (Build {build_number})"
        if 'windows 11' in name_lower or 'win11' in name_lower:
            return "Windows 11"
        elif 'windows 10' in name_lower or 'win10' in name_lower:
            if build_number and build_number < 22000:
                return f"Windows 10 (Build {build_number})"
            return "Windows 10"
        elif 'windows server' in name_lower:
            version_match = re.search(r'windows server[\s_]?(\d{4})', name_lower)
            if version_match:
                return f"Windows Server {version_match.group(1)}"
            if build_number:
                if build_number >= 20348:
                    return "Windows Server 2022"
                elif build_number >= 17763:
                    return "Windows Server 2019"
                elif build_number >= 14393:
                    return "Windows Server 2016"
            return "Windows Server"
        return None
    
    def _extract_linux_version(self, name: str) -> Optional[str]:
        name_lower = name.lower()
        ubuntu_match = re.search(r'ubuntu[\s_]?(\d+\.\d+)', name_lower)
        if ubuntu_match:
            return f"Ubuntu {ubuntu_match.group(1)}"
        debian_match = re.search(r'debian[\s_]?(\d+)', name_lower)
        if debian_match:
            return f"Debian {debian_match.group(1)}"
        centos_match = re.search(r'centos[\s_]?(\d+)', name_lower)
        if centos_match:
            return f"CentOS {centos_match.group(1)}"
        rhel_match = re.search(r'(?:rhel|red[\s_]?hat|redhat)[\s_]?(\d+)', name_lower)
        if rhel_match:
            return f"RHEL {rhel_match.group(1)}"
        return None
    
    def _extract_macos_version(self, name: str) -> Optional[str]:
        macos_match = re.search(r'mac os x (\d+\.\d+)', name.lower())
        if macos_match:
            return f"macOS {macos_match.group(1)}"
        return None
    
    def _simple_ping_scan(self, ip_range: str) -> List[Dict]:
        hosts = []
        try:
            if '/' in ip_range:
                network = ipaddress.ip_network(ip_range, strict=False)
                ips = [str(ip) for ip in network.hosts()]
            elif '-' in ip_range:
                start_ip, end_ip = ip_range.split('-')
                start = ipaddress.IPv4Address(start_ip.strip())
                end = ipaddress.IPv4Address(end_ip.strip())
                ips = [str(ipaddress.IPv4Address(i)) for i in range(int(start), int(end) + 1)]
            else:
                ips = [ip_range]
            self.nm.scan(hosts=' '.join(ips), arguments='-sn')
            for host in self.nm.all_hosts():
                hosts.append({
                    'ip': host,
                    'hostname': self._get_hostname(host),
                    'state': 'up',
                    'mac': None,
                    'vendor': None,
                    'open_ports': [],
                    'os_info': {'os_family': None, 'os_gen': None, 'os_details': None, 'accuracy': None}
                })
        except Exception as e:
            print(f"Erreur lors du scan ping: {e}")
        return hosts


class OSDetector:
    def __init__(self):
        self.detection_methods = [
            self._detect_via_smb,
            self._detect_via_banner,
            self._detect_via_http_header,
            self._detect_via_ssh_banner,
            self._detect_via_snmp
        ]
    
    def detect_os(self, ip: str, ports: Dict[int, str] = None) -> Dict:
        os_info = {
            'os_family': None,
            'os_version': None,
            'os_full_name': None,
            'detection_method': None,
            'confidence': 'low'
        }
        for method in self.detection_methods:
            try:
                result = method(ip, ports)
                if result and result.get('os_version'):
                    os_info.update(result)
                    os_info['confidence'] = 'high'
                    break
            except Exception as e:
                continue
        return os_info
    
    def _detect_via_ssh_banner(self, ip: str, ports: Dict = None) -> Optional[Dict]:
        ssh_port = 22
        if ports and 22 in ports:
            ssh_port = 22
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, ssh_port))
            if result == 0:
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                os_info = self._parse_ssh_banner(banner)
                if os_info:
                    os_info['detection_method'] = 'SSH Banner'
                    return os_info
        except:
            pass
        return None
    
    def _parse_ssh_banner(self, banner: str) -> Optional[Dict]:
        banner_lower = banner.lower()
        ubuntu_match = re.search(r'ubuntu[_-]?(\d+\.\d+)', banner_lower)
        if ubuntu_match:
            return {
                'os_family': 'Linux',
                'os_version': f"Ubuntu {ubuntu_match.group(1)}",
                'os_full_name': f"Ubuntu {ubuntu_match.group(1)}"
            }
        debian_match = re.search(r'debian[_-]?(\d+)', banner_lower)
        if debian_match:
            return {
                'os_family': 'Linux',
                'os_version': f"Debian {debian_match.group(1)}",
                'os_full_name': f"Debian {debian_match.group(1)}"
            }
        centos_match = re.search(r'(?:centos|rhel|redhat)[_-]?(\d+)', banner_lower)
        if centos_match:
            return {
                'os_family': 'Linux',
                'os_version': f"CentOS/RHEL {centos_match.group(1)}",
                'os_full_name': f"CentOS/RHEL {centos_match.group(1)}"
            }
        if 'openssh_for_windows' in banner_lower or 'microsoft' in banner_lower:
            return {
                'os_family': 'Windows',
                'os_version': 'Windows (via SSH)',
                'os_full_name': 'Windows (détecté via SSH)'
            }
        return None
    
    def _detect_via_banner(self, ip: str, ports: Dict = None) -> Optional[Dict]:
        common_ports = {
            22: 'ssh',
            80: 'http',
            443: 'https',
            3389: 'rdp',
            135: 'msrpc',
            139: 'netbios',
            445: 'smb'
        }
        if ports:
            common_ports.update(ports)
        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    if service == 'http' or service == 'https':
                        os_info = self._detect_via_http_header(ip, port)
                        if os_info:
                            return os_info
                    elif service == 'smb':
                        os_info = self._detect_via_smb(ip)
                        if os_info:
                            return os_info
                sock.close()
            except:
                continue
        return None
    
    def _detect_via_http_header(self, ip: str, port: int = 80) -> Optional[Dict]:
        try:
            protocol = 'https' if port == 443 else 'http'
            url = f"{protocol}://{ip}:{port}"
            response = requests.get(url, timeout=3, verify=False, allow_redirects=True)
            server_header = response.headers.get('Server', '').lower()
            if 'ubuntu' in server_header:
                match = re.search(r'ubuntu[_-]?(\d+\.\d+)', server_header)
                if match:
                    return {
                        'os_family': 'Linux',
                        'os_version': f"Ubuntu {match.group(1)}",
                        'os_full_name': f"Ubuntu {match.group(1)}",
                        'detection_method': 'HTTP Header'
                    }
            if 'microsoft-iis' in server_header or 'windows' in server_header:
                iis_match = re.search(r'iis[/\s](\d+\.\d+)', server_header)
                if iis_match:
                    iis_version = float(iis_match.group(1))
                    windows_version = self._iis_to_windows_version(iis_version)
                    return {
                        'os_family': 'Windows',
                        'os_version': windows_version,
                        'os_full_name': f"Windows Server ({windows_version})",
                        'detection_method': 'HTTP Header'
                    }
        except:
            pass
        return None
    
    def _iis_to_windows_version(self, iis_version: float) -> str:
        if iis_version >= 10.0:
            return "Windows Server 2016/2019/2022"
        elif iis_version >= 8.5:
            return "Windows Server 2012 R2"
        elif iis_version >= 8.0:
            return "Windows Server 2012"
        elif iis_version >= 7.5:
            return "Windows Server 2008 R2"
        else:
            return "Windows Server (ancien)"
    
    def _detect_via_smb(self, ip: str) -> Optional[Dict]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, 445))
            if result == 0:
                smb_negotiate = b'\x00\x00\x00\x54\xfeSMB@\x00'
                sock.send(smb_negotiate)
                response = sock.recv(1024)
                sock.close()
                if response:
                    response_str = response.decode('utf-8', errors='ignore')
                    if 'Windows' in response_str:
                        win_match = re.search(r'Windows[\s_]?(\d+\.\d+)', response_str)
                        if win_match:
                            version = win_match.group(1)
                            if version.startswith('10.'):
                                return {
                                    'os_family': 'Windows',
                                    'os_version': 'Windows 10/11 (détecté via SMB)',
                                    'os_full_name': 'Windows (détecté via SMB)',
                                    'detection_method': 'SMB'
                                }
        except Exception:
            pass
        return None
    
    def _detect_via_snmp(self, ip: str, ports: Dict = None) -> Optional[Dict]:
        return None
    
    def normalize_os_version(self, os_family: str, raw_version: str) -> str:
        if not raw_version:
            return "Unknown"
        raw_lower = raw_version.lower()
        if os_family == 'Windows':
            if 'windows 11' in raw_lower or 'win11' in raw_lower:
                return "Windows 11"
            elif 'windows 10' in raw_lower or 'win10' in raw_lower:
                return "Windows 10"
            elif 'windows server' in raw_lower or 'server' in raw_lower:
                server_match = re.search(r'server[\s_]?(\d{4})', raw_lower)
                if server_match:
                    year = server_match.group(1)
                    return f"Windows Server {year}"
                return "Windows Server"
            else:
                return "Windows"
        elif os_family == 'Linux':
            ubuntu_match = re.search(r'ubuntu[\s_]?(\d+\.\d+)', raw_lower)
            if ubuntu_match:
                return f"Ubuntu {ubuntu_match.group(1)}"
            debian_match = re.search(r'debian[\s_]?(\d+)', raw_lower)
            if debian_match:
                return f"Debian {debian_match.group(1)}"
            centos_match = re.search(r'centos[\s_]?(\d+)', raw_lower)
            if centos_match:
                return f"CentOS {centos_match.group(1)}"
            rhel_match = re.search(r'(?:rhel|red[\s_]?hat|redhat)[\s_]?(\d+)', raw_lower)
            if rhel_match:
                return f"RHEL {rhel_match.group(1)}"
            if 'linux' in raw_lower and raw_lower != 'linux':
                return raw_version
            return "Linux"
        elif os_family == 'macOS':
            macos_match = re.search(r'mac[\s_]?os[\s_]?x?[\s_]?(\d+\.\d+)', raw_lower)
            if macos_match:
                return f"macOS {macos_match.group(1)}"
            return "macOS"
        return raw_version


class EOLDatabase:
    def __init__(self):
        self.eol_data = self._load_eol_data()
    
    def _load_eol_data(self) -> Dict:
        return {
            'Windows': {
                'Windows 11': {
                    'release_date': date(2021, 10, 5),
                    'eol_date': None,
                    'eol_extended_date': None,
                    'status': 'supported'
                },
                'Windows 10': {
                    'release_date': date(2015, 7, 29),
                    'eol_date': date(2025, 10, 14),
                    'eol_extended_date': date(2026, 10, 13),
                    'status': 'soon_eol'
                },
                'Windows Server 2022': {
                    'release_date': date(2021, 8, 18),
                    'eol_date': date(2026, 10, 13),
                    'eol_extended_date': date(2031, 10, 14),
                    'status': 'supported'
                },
                'Windows Server 2019': {
                    'release_date': date(2018, 10, 2),
                    'eol_date': date(2024, 1, 9),
                    'eol_extended_date': date(2029, 1, 9),
                    'status': 'extended_support'
                },
                'Windows Server 2016': {
                    'release_date': date(2016, 10, 12),
                    'eol_date': date(2022, 1, 11),
                    'eol_extended_date': date(2027, 1, 12),
                    'status': 'extended_support'
                },
                'Windows Server 2012': {
                    'release_date': date(2012, 9, 4),
                    'eol_date': date(2018, 10, 9),
                    'eol_extended_date': date(2023, 10, 10),
                    'status': 'eol'
                },
                'Windows Server 2012 R2': {
                    'release_date': date(2013, 10, 18),
                    'eol_date': date(2018, 10, 9),
                    'eol_extended_date': date(2023, 10, 10),
                    'status': 'eol'
                },
                'Windows Server 2008 R2': {
                    'release_date': date(2009, 10, 22),
                    'eol_date': date(2015, 1, 13),
                    'eol_extended_date': date(2020, 1, 14),
                    'status': 'eol'
                }
            },
            'Linux': {
                'Ubuntu 24.04': {
                    'release_date': date(2024, 4, 25),
                    'eol_date': date(2029, 4, 25),
                    'eol_extended_date': None,
                    'status': 'supported'
                },
                'Ubuntu 22.04': {
                    'release_date': date(2022, 4, 21),
                    'eol_date': date(2027, 4, 21),
                    'eol_extended_date': None,
                    'status': 'supported'
                },
                'Ubuntu 20.04': {
                    'release_date': date(2020, 4, 23),
                    'eol_date': date(2025, 4, 23),
                    'eol_extended_date': None,
                    'status': 'soon_eol'
                },
                'Ubuntu 18.04': {
                    'release_date': date(2018, 4, 26),
                    'eol_date': date(2023, 4, 26),
                    'eol_extended_date': date(2028, 4, 26),
                    'status': 'extended_support'
                },
                'Ubuntu 16.04': {
                    'release_date': date(2016, 4, 21),
                    'eol_date': date(2021, 4, 21),
                    'eol_extended_date': date(2026, 4, 21),
                    'status': 'extended_support'
                },
                'Ubuntu 14.04': {
                    'release_date': date(2014, 4, 17),
                    'eol_date': date(2019, 4, 25),
                    'eol_extended_date': date(2024, 4, 25),
                    'status': 'eol'
                },
                'Debian 12': {
                    'release_date': date(2023, 6, 10),
                    'eol_date': date(2028, 6, 10),
                    'eol_extended_date': None,
                    'status': 'supported'
                },
                'Debian 11': {
                    'release_date': date(2021, 8, 14),
                    'eol_date': date(2026, 7, 31),
                    'eol_extended_date': None,
                    'status': 'supported'
                },
                'Debian 10': {
                    'release_date': date(2019, 7, 6),
                    'eol_date': date(2024, 6, 30),
                    'eol_extended_date': date(2027, 6, 30),
                    'status': 'extended_support'
                },
                'Debian 9': {
                    'release_date': date(2017, 6, 17),
                    'eol_date': date(2022, 6, 30),
                    'eol_extended_date': date(2024, 6, 30),
                    'status': 'eol'
                },
                'CentOS 9': {
                    'release_date': date(2021, 12, 3),
                    'eol_date': date(2027, 5, 31),
                    'eol_extended_date': None,
                    'status': 'supported'
                },
                'CentOS 8': {
                    'release_date': date(2019, 9, 24),
                    'eol_date': date(2021, 12, 31),
                    'eol_extended_date': None,
                    'status': 'eol'
                },
                'CentOS 7': {
                    'release_date': date(2014, 7, 7),
                    'eol_date': date(2024, 6, 30),
                    'eol_extended_date': date(2027, 6, 30),
                    'status': 'extended_support'
                },
                'RHEL 9': {
                    'release_date': date(2022, 5, 17),
                    'eol_date': date(2027, 5, 31),
                    'eol_extended_date': date(2032, 5, 31),
                    'status': 'supported'
                },
                'RHEL 8': {
                    'release_date': date(2019, 5, 7),
                    'eol_date': date(2024, 5, 31),
                    'eol_extended_date': date(2029, 5, 31),
                    'status': 'supported'
                },
                'RHEL 7': {
                    'release_date': date(2014, 6, 10),
                    'eol_date': date(2019, 8, 6),
                    'eol_extended_date': date(2024, 6, 30),
                    'status': 'eol'
                }
            },
            'macOS': {
                'macOS 14 (Sonoma)': {
                    'release_date': date(2023, 9, 26),
                    'eol_date': date(2026, 9, 26),
                    'eol_extended_date': None,
                    'status': 'supported'
                },
                'macOS 13 (Ventura)': {
                    'release_date': date(2022, 10, 24),
                    'eol_date': date(2025, 10, 24),
                    'eol_extended_date': None,
                    'status': 'supported'
                },
                'macOS 12 (Monterey)': {
                    'release_date': date(2021, 10, 25),
                    'eol_date': date(2024, 10, 25),
                    'eol_extended_date': None,
                    'status': 'soon_eol'
                },
                'macOS 11 (Big Sur)': {
                    'release_date': date(2020, 11, 12),
                    'eol_date': date(2023, 11, 12),
                    'eol_extended_date': None,
                    'status': 'eol'
                }
            }
        }
    
    def get_eol_info(self, os_family: str, os_version: str) -> Optional[Dict]:
        if os_family not in self.eol_data:
            return None
        if os_version in self.eol_data[os_family]:
            return self.eol_data[os_family][os_version].copy()
        for key, value in self.eol_data[os_family].items():
            if os_version.lower() in key.lower() or key.lower() in os_version.lower():
                result = value.copy()
                result['matched_version'] = key
                return result
        return None
    
    def list_all_versions(self, os_family: str) -> List[Dict]:
        if os_family not in self.eol_data:
            return []
        versions = []
        for version, info in self.eol_data[os_family].items():
            version_info = info.copy()
            version_info['version'] = version
            versions.append(version_info)
        versions.sort(key=lambda x: x['release_date'], reverse=True)
        return versions
    
    def get_status(self, eol_info: Dict) -> str:
        if not eol_info:
            return 'unknown'
        today = date.today()
        eol_date = eol_info.get('eol_date')
        eol_extended_date = eol_info.get('eol_extended_date')
        if not eol_date and not eol_extended_date:
            return 'supported'
        if eol_extended_date:
            if today > eol_extended_date:
                return 'eol'
            elif eol_date and today > eol_date:
                return 'extended_support'
        if eol_date:
            days_until_eol = (eol_date - today).days
            if days_until_eol < 0:
                return 'eol'
            elif days_until_eol < 90:
                return 'soon_eol'
            elif days_until_eol < 365:
                return 'warning'
        return eol_info.get('status', 'supported')
    
    def get_days_until_eol(self, eol_info: Dict) -> Optional[int]:
        if not eol_info:
            return None
        today = date.today()
        eol_date = eol_info.get('eol_date')
        if eol_date:
            return (eol_date - today).days
        return None


class CSVProcessor:
    def __init__(self):
        self.required_columns = ['ip', 'hostname', 'os_family', 'os_version']
    
    def read_csv(self, csv_path: str) -> pd.DataFrame:
        try:
            for sep in [',', ';', '\t']:
                try:
                    df = pd.read_csv(csv_path, sep=sep, encoding='utf-8')
                    if len(df.columns) > 1:
                        break
                except:
                    continue
            df.columns = df.columns.str.lower().str.strip().str.replace(' ', '_')
            missing_cols = [col for col in self.required_columns if col not in df.columns]
            if missing_cols:
                raise ValueError(f"Colonnes manquantes: {', '.join(missing_cols)}")
            return df
        except Exception as e:
            raise Exception(f"Erreur lors de la lecture du CSV: {e}")
    
    def validate_data(self, df: pd.DataFrame) -> List[str]:
        errors = []
        for col in self.required_columns:
            if col not in df.columns:
                errors.append(f"Colonne '{col}' manquante")
        if errors:
            return errors
        for col in ['ip', 'os_family', 'os_version']:
            missing = df[col].isna().sum()
            if missing > 0:
                errors.append(f"{missing} valeur(s) manquante(s) dans la colonne '{col}'")
        invalid_ips = []
        for idx, ip in enumerate(df['ip']):
            if pd.notna(ip):
                if not self._is_valid_ip(str(ip)):
                    invalid_ips.append(f"Ligne {idx + 2}: IP invalide '{ip}'")
        if invalid_ips:
            errors.extend(invalid_ips[:10])
        return errors
    
    def _is_valid_ip(self, ip: str) -> bool:
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except:
            return False
    
    def process_components(self, df: pd.DataFrame) -> List[Dict]:
        components = []
        for _, row in df.iterrows():
            component = {
                'ip': str(row.get('ip', 'Unknown')),
                'hostname': str(row.get('hostname', 'Unknown')),
                'os_family': str(row.get('os_family', 'Unknown')),
                'os_version': str(row.get('os_version', 'Unknown')),
                'additional_info': {}
            }
            for col in df.columns:
                if col not in self.required_columns:
                    component['additional_info'][col] = row.get(col)
            components.append(component)
        return components
    
    def export_to_csv(self, data: List[Dict], output_path: str):
        if not data:
            raise ValueError("Aucune donnée à exporter")
        df = pd.DataFrame(data)
        df.to_csv(output_path, index=False, encoding='utf-8-sig')
    
    def create_template(self, output_path: str):
        template_data = {
            'ip': ['192.168.1.1', '192.168.1.2', '10.0.0.1'],
            'hostname': ['server01', 'server02', 'workstation01'],
            'os_family': ['Linux', 'Windows', 'Linux'],
            'os_version': ['Ubuntu 22.04', 'Windows Server 2019', 'Ubuntu 20.04']
        }
        df = pd.DataFrame(template_data)
        df.to_csv(output_path, index=False, encoding='utf-8-sig')
        print(f"Template créé: {output_path}")


class ReportGenerator:
    def __init__(self):
        self.status_labels = {
            'supported': 'Supporté',
            'soon_eol': 'EOL proche (< 3 mois)',
            'warning': "EOL dans moins d'un an",
            'extended_support': 'Support étendu uniquement',
            'eol': 'EOL (non supporté)',
            'unknown': 'Inconnu'
        }
    
    def generate_report(self, components: List[Dict], eol_database, output_path: str = None, format: str = 'txt'):
        analysis = self._analyze_components(components, eol_database)
        if format == 'csv':
            report = self._generate_csv_report(analysis, components)
        elif format == 'json':
            report = self._generate_json_report(analysis, components)
        else:
            report = self._generate_text_report(analysis, components)
        if output_path:
            self._save_report(report, output_path, format)
        return report
    
    def _analyze_components(self, components: List[Dict], eol_database) -> Dict:
        stats = {
            'total': len(components),
            'supported': 0,
            'soon_eol': 0,
            'warning': 0,
            'extended_support': 0,
            'eol': 0,
            'unknown': 0,
            'by_os_family': {},
            'critical': []
        }
        for component in components:
            os_family = component.get('os_family', 'Unknown')
            os_version = component.get('os_version', 'Unknown')
            eol_info = component.get('eol_info') or {}
            status = component.get('status', 'unknown')
            stats[status] = stats.get(status, 0) + 1
            if os_family not in stats['by_os_family']:
                stats['by_os_family'][os_family] = {
                    'total': 0,
                    'supported': 0,
                    'eol': 0,
                    'soon_eol': 0
                }
            stats['by_os_family'][os_family]['total'] += 1
            stats['by_os_family'][os_family][status] = stats['by_os_family'][os_family].get(status, 0) + 1
            if status in ['eol', 'soon_eol']:
                eol_date = eol_info.get('eol_date') if eol_info else None
                stats['critical'].append({
                    'ip': component.get('ip'),
                    'hostname': component.get('hostname'),
                    'os_version': os_version,
                    'status': status,
                    'eol_date': eol_date,
                    'days_until_eol': component.get('days_until_eol')
                })
        return stats
    
    def _generate_csv_report(self, analysis: Dict, components: List[Dict]) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['IP', 'Hostname', 'Famille OS', 'Version OS', 'Statut', 'Date EOL', 'Jours restants'])
        for comp in components:
            eol_info = comp.get('eol_info') or {}
            eol_date = eol_info.get('eol_date') if eol_info else None
            eol_date_str = eol_date.strftime('%Y-%m-%d') if eol_date else 'N/A'
            writer.writerow([
                comp.get('ip', 'N/A'),
                comp.get('hostname', 'N/A'),
                comp.get('os_family', 'Unknown'),
                comp.get('os_version', 'Unknown'),
                self.status_labels.get(comp.get('status', 'unknown'), comp.get('status', 'unknown')),
                eol_date_str,
                comp.get('days_until_eol', 'N/A')
            ])
        return output.getvalue()
    
    def _generate_json_report(self, analysis: Dict, components: List[Dict]) -> str:
        report_data = {
            'generation_date': datetime.now().isoformat(),
            'statistics': analysis,
            'components': []
        }
        for comp in components:
            comp_data = comp.copy()
            eol_info = comp_data.get('eol_info')
            if eol_info:
                eol_info_copy = eol_info.copy()
                if 'release_date' in eol_info_copy and eol_info_copy['release_date']:
                    eol_info_copy['release_date'] = eol_info_copy['release_date'].isoformat()
                if 'eol_date' in eol_info_copy and eol_info_copy['eol_date']:
                    eol_info_copy['eol_date'] = eol_info_copy['eol_date'].isoformat()
                if 'eol_extended_date' in eol_info_copy and eol_info_copy['eol_extended_date']:
                    eol_info_copy['eol_extended_date'] = eol_info_copy['eol_extended_date'].isoformat()
                comp_data['eol_info'] = eol_info_copy
            else:
                comp_data['eol_info'] = None
            report_data['components'].append(comp_data)
        return json.dumps(report_data, indent=2, ensure_ascii=False)
    
    def _generate_text_report(self, analysis: Dict, components: List[Dict]) -> str:
        report = f"""
{'='*80}
RAPPORT D'AUDIT D'OBSOLESCENCE
{'='*80}
Date de génération: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}

STATISTIQUES GLOBALES
{'-'*80}
Total de composants: {analysis['total']}
  Supportés: {analysis['supported']}
  EOL proche (< 3 mois): {analysis['soon_eol']}
  EOL dans moins d'un an: {analysis['warning']}
  Support étendu uniquement: {analysis['extended_support']}
  EOL (non supporté): {analysis['eol']}
  Inconnu: {analysis['unknown']}

"""
        if analysis['critical']:
            report += "COMPOSANTS NÉCESSITANT UNE ATTENTION IMMÉDIATE\n"
            report += "-"*80 + "\n"
            for comp in analysis['critical']:
                eol_date = comp.get('eol_date')
                eol_date_str = eol_date.strftime('%d/%m/%Y') if eol_date else 'N/A'
                days = comp.get('days_until_eol', 'N/A')
                report += f"  {comp.get('ip', 'N/A')} ({comp.get('hostname', 'N/A')}) - {comp.get('os_version', 'Unknown')}\n"
                report += f"    Statut: {self.status_labels.get(comp.get('status', 'unknown'), comp.get('status', 'unknown'))}\n"
                report += f"    Date EOL: {eol_date_str} (Jours restants: {days})\n\n"
        report += "\nDÉTAIL DES COMPOSANTS\n"
        report += "-"*80 + "\n"
        for comp in components:
            eol_info = comp.get('eol_info') or {}
            eol_date = eol_info.get('eol_date') if eol_info else None
            eol_date_str = eol_date.strftime('%d/%m/%Y') if eol_date else 'N/A'
            report += f"{comp.get('ip', 'N/A')} | {comp.get('hostname', 'N/A')} | "
            report += f"{comp.get('os_family', 'Unknown')} | {comp.get('os_version', 'Unknown')} | "
            report += f"{self.status_labels.get(comp.get('status', 'unknown'), comp.get('status', 'unknown'))} | "
            report += f"EOL: {eol_date_str} | Jours: {comp.get('days_until_eol', 'N/A')}\n"
        return report
    
    def _save_report(self, content: str, output_path: str, format: str):
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if format == 'csv':
            path = path.with_suffix('.csv')
        elif format == 'json':
            path = path.with_suffix('.json')
        else:
            path = path.with_suffix('.txt')
        encoding = 'utf-8' if format == 'json' else 'utf-8-sig'
        with open(path, 'w', encoding=encoding) as f:
            f.write(content)
        print(f"Rapport sauvegardé: {path}")


# ✅ MODIFIÉ: heuristique ports en fallback final si OS toujours Unknown
def scan_network(ip_range: str, output_csv: str = None):
    print("="*80)
    print("SCAN RÉSEAU")
    print("="*80)
    scanner = NetworkScanner()
    detector = OSDetector()
    eol_db = EOLDatabase()
    hosts = scanner.scan_range(ip_range)
    if not hosts:
        print("Aucun hôte détecté.")
        return
    print(f"\n{len(hosts)} hôte(s) détecté(s).")
    print("\nAnalyse des OS et versions...")
    components = []
    for host in hosts:
        ip = host['ip']
        os_info_nmap = host.get('os_info', {})
        ports_dict = {port: 'open' for port in host.get('open_ports', [])}
        os_info_detected = detector.detect_os(ip, ports_dict)
        os_family = os_info_detected.get('os_family') or os_info_nmap.get('os_family') or 'Unknown'
        os_version_raw = os_info_detected.get('os_version') or os_info_nmap.get('os_gen') or os_info_nmap.get('os_details') or 'Unknown'
        build_number = os_info_nmap.get('build_number')
        if build_number and os_family == 'Windows':
            if build_number >= 22000:
                os_version_raw = f"Windows 11 (Build {build_number})"
            elif build_number >= 10240:
                os_version_raw = f"Windows 10 (Build {build_number})"
        if os_family == 'Linux' and (os_version_raw == 'Unknown' or os_version_raw.lower() == 'linux'):
            linux_version = os_info_nmap.get('os_gen')
            if linux_version and linux_version.lower() != 'linux':
                os_version_raw = linux_version

        # ✅ NOUVEAU: si family toujours Unknown, heuristique ports ouverts
        if os_family == 'Unknown':
            open_ports = set(host.get('open_ports', []))
            if {445, 3389, 135, 139} & open_ports:
                os_family = 'Windows'
                if os_version_raw == 'Unknown':
                    os_version_raw = 'Windows (ports)'
            elif 22 in open_ports:
                os_family = 'Linux'
                if os_version_raw == 'Unknown':
                    os_version_raw = 'Linux (SSH)'

        os_version = detector.normalize_os_version(os_family, os_version_raw)
        if os_version == 'Linux' and os_version_raw != 'Unknown' and os_version_raw.lower() != 'linux':
            if any(kw in os_version_raw.lower() for kw in ['ubuntu', 'debian', 'centos', 'rhel', 'red hat']):
                os_version = os_version_raw
        eol_info = eol_db.get_eol_info(os_family, os_version)
        status = eol_db.get_status(eol_info) if eol_info else 'unknown'
        days_until_eol = eol_db.get_days_until_eol(eol_info) if eol_info else None
        component = {
            'ip': ip,
            'hostname': host.get('hostname', ip),
            'os_family': os_family,
            'os_version': os_version,
            'eol_info': eol_info,
            'status': status,
            'days_until_eol': days_until_eol,
            'mac': host.get('mac'),
            'vendor': host.get('vendor'),
            'open_ports': host.get('open_ports', [])
        }
        components.append(component)
        status_label = {
            'supported': '[OK]',
            'soon_eol': '[WARN]',
            'warning': '[WARN]',
            'extended_support': '[EXT]',
            'eol': '[EOL]',
            'unknown': '[?]'
        }.get(status, '[?]')
        display_os = os_version if os_version != 'Unknown' else os_family
        print(f"  {status_label} {ip} ({host.get('hostname', ip)}) - {display_os}")
    if output_csv:
        processor = CSVProcessor()
        processor.export_to_csv(components, output_csv)
        print(f"\nRésultats exportés vers: {output_csv}")
    print("\n" + "="*80)
    print("RÉSUMÉ DU SCAN")
    print("="*80)
    stats = {
        'total': len(components),
        'supported': sum(1 for c in components if c.get('status') == 'supported'),
        'soon_eol': sum(1 for c in components if c.get('status') == 'soon_eol'),
        'eol': sum(1 for c in components if c.get('status') == 'eol'),
        'extended_support': sum(1 for c in components if c.get('status') == 'extended_support'),
        'unknown': sum(1 for c in components if c.get('status') == 'unknown')
    }
    print(f"Total: {stats['total']}")
    print(f"Supportés: {stats['supported']}")
    print(f"EOL proche: {stats['soon_eol']}")
    print(f"Support étendu: {stats['extended_support']}")
    print(f"EOL: {stats['eol']}")
    print(f"Inconnu: {stats['unknown']}")
    return components


def list_os_versions(os_family: str):
    print("="*80)
    print(f"VERSIONS ET DATES EOL POUR {os_family.upper()}")
    print("="*80)
    eol_db = EOLDatabase()
    versions = eol_db.list_all_versions(os_family)
    if not versions:
        print(f"Aucune version trouvée pour {os_family}.")
        return
    print(f"\n{len(versions)} version(s) trouvée(s):\n")
    for version_info in versions:
        version = version_info['version']
        release_date = version_info['release_date']
        eol_date = version_info.get('eol_date')
        eol_extended_date = version_info.get('eol_extended_date')
        print(f"{version}")
        print(f"  Date de release: {release_date.strftime('%d/%m/%Y')}")
        if eol_date:
            print(f"  Date EOL (Mainstream): {eol_date.strftime('%d/%m/%Y')}")
        else:
            print(f"  Date EOL (Mainstream): Non définie / Support continu")
        if eol_extended_date:
            print(f"  Date EOL (Extended): {eol_extended_date.strftime('%d/%m/%Y')}")
        elif eol_date:
            print(f"  Date EOL (Extended): Non disponible")
        print()


def process_csv(csv_path: str, output_report: str = None, format: str = 'txt'):
    print("="*80)
    print("TRAITEMENT DU FICHIER CSV")
    print("="*80)
    processor = CSVProcessor()
    eol_db = EOLDatabase()
    detector = OSDetector()
    try:
        df = processor.read_csv(csv_path)
        print(f"Fichier CSV lu: {len(df)} composant(s)")
    except Exception as e:
        print(f"Erreur lors de la lecture du CSV: {e}")
        return
    errors = processor.validate_data(df)
    if errors:
        print("Erreurs de validation:")
        for error in errors[:10]:
            print(f"  - {error}")
        if len(errors) > 10:
            print(f"  ... et {len(errors) - 10} autre(s) erreur(s)")
        return
    components_raw = processor.process_components(df)
    print("\nAnalyse des dates EOL...")
    components = []
    for comp in components_raw:
        os_family = comp['os_family']
        os_version = comp['os_version']
        os_version_normalized = detector.normalize_os_version(os_family, os_version)
        eol_info = eol_db.get_eol_info(os_family, os_version_normalized)
        status = eol_db.get_status(eol_info) if eol_info else 'unknown'
        days_until_eol = eol_db.get_days_until_eol(eol_info) if eol_info else None
        component = comp.copy()
        component['os_version'] = os_version_normalized
        component['eol_info'] = eol_info
        component['status'] = status
        component['days_until_eol'] = days_until_eol
        components.append(component)
    generator = ReportGenerator()
    report_path = output_report or csv_path.replace('.csv', '_report.txt')
    generator.generate_report(components, eol_db, report_path, format)
    print(f"\nRapport généré: {report_path}")
    stats = {
        'total': len(components),
        'supported': sum(1 for c in components if c.get('status') == 'supported'),
        'soon_eol': sum(1 for c in components if c.get('status') == 'soon_eol'),
        'eol': sum(1 for c in components if c.get('status') == 'eol'),
        'extended_support': sum(1 for c in components if c.get('status') == 'extended_support'),
        'unknown': sum(1 for c in components if c.get('status') == 'unknown')
    }
    print("\nRésumé:")
    print(f"  Total: {stats['total']}")
    print(f"  Supportés: {stats['supported']}")
    print(f"  EOL proche: {stats['soon_eol']}")
    print(f"  Support étendu: {stats['extended_support']}")
    print(f"  EOL: {stats['eol']}")
    print(f"  Inconnu: {stats['unknown']}")


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def display_menu():
    print("\n" + "="*80)
    print(" " * 25 + "MODULE D'AUDIT D'OBSOLESCENCE RÉSEAU")
    print("="*80)
    print()
    print("  [1] Scanner une plage réseau")
    print("  [2] Lister les versions d'un OS et leurs dates EOL")
    print("  [3] Analyser un fichier CSV")
    print("  [4] Quitter")
    print()
    print("="*80)


def menu_scan_network():
    clear_screen()
    print("\n" + "="*80)
    print("SCAN RÉSEAU")
    print("="*80)
    print()
    print("Entrez la plage IP à scanner.")
    print("Exemples:")
    print("  - 192.168.1.0/24 (plage CIDR)")
    print("  - 192.168.1.1-192.168.1.100 (plage IP)")
    print("  - 192.168.1.10 (une seule IP)")
    print()
    ip_range = input("Plage IP: ").strip()
    if not ip_range:
        print("\nErreur: Plage IP vide. Retour au menu principal.")
        input("\nAppuyez sur Entrée pour continuer...")
        return
    print()
    export_csv = input("Exporter les résultats en CSV? (o/n) [n]: ").strip().lower()
    output_csv = None
    if export_csv == 'o' or export_csv == 'oui' or export_csv == 'y' or export_csv == 'yes':
        output_csv = input("Nom du fichier CSV [scan_results.csv]: ").strip()
        if not output_csv:
            output_csv = "scan_results.csv"
    print("\nDémarrage du scan...")
    print("(Cela peut prendre plusieurs minutes selon la taille du réseau)\n")
    try:
        scan_network(ip_range, output_csv)
    except KeyboardInterrupt:
        print("\n\nScan interrompu par l'utilisateur.")
    except Exception as e:
        print(f"\nErreur lors du scan: {e}")
        traceback.print_exc()
    input("\nAppuyez sur Entrée pour continuer...")


def menu_list_os():
    clear_screen()
    print("\n" + "="*80)
    print("LISTER LES VERSIONS D'UN OS")
    print("="*80)
    print()
    print("Sélectionnez la famille d'OS:")
    print("  [1] Windows")
    print("  [2] Linux")
    print("  [3] macOS")
    print("  [4] Retour au menu principal")
    print()
    choice = input("Votre choix [1-4]: ").strip()
    os_families = {
        '1': 'Windows',
        '2': 'Linux',
        '3': 'macOS'
    }
    if choice in os_families:
        os_family = os_families[choice]
        clear_screen()
        try:
            list_os_versions(os_family)
        except Exception as e:
            print(f"\nErreur: {e}")
    elif choice == '4':
        return
    else:
        print("\nChoix invalide.")
    input("\nAppuyez sur Entrée pour continuer...")


def menu_process_csv():
    clear_screen()
    print("\n" + "="*80)
    print("ANALYSER UN FICHIER CSV")
    print("="*80)
    print()
    csv_path = input("Chemin vers le fichier CSV: ").strip()
    if not csv_path:
        print("\nErreur: Chemin vide. Retour au menu principal.")
        input("\nAppuyez sur Entrée pour continuer...")
        return
    if not Path(csv_path).exists():
        print(f"\nErreur: Le fichier '{csv_path}' n'existe pas.")
        input("\nAppuyez sur Entrée pour continuer...")
        return
    print()
    print("Sélectionnez le format du rapport:")
    print("  [1] TXT (recommandé)")
    print("  [2] CSV")
    print("  [3] JSON")
    print()
    format_choice = input("Format [1]: ").strip() or '1'
    formats = {
        '1': 'txt',
        '2': 'csv',
        '3': 'json'
    }
    report_format = formats.get(format_choice, 'txt')
    print()
    custom_output = input("Nom personnalisé pour le rapport (laisser vide pour auto): ").strip()
    output_report = custom_output if custom_output else None
    print("\nTraitement en cours...\n")
    try:
        process_csv(csv_path, output_report, report_format)
    except Exception as e:
        print(f"\nErreur lors du traitement: {e}")
        traceback.print_exc()
    input("\nAppuyez sur Entrée pour continuer...")


def main():
    while True:
        clear_screen()
        display_menu()
        choice = input("Votre choix [1-4]: ").strip()
        if choice == '1':
            menu_scan_network()
        elif choice == '2':
            menu_list_os()
        elif choice == '3':
            menu_process_csv()
        elif choice == '4':
            clear_screen()
            print("\n" + "="*80)
            print("Au revoir!")
            print("="*80)
            print()
            break
        else:
            print("\nChoix invalide. Veuillez entrer un nombre entre 1 et 4.")
            input("\nAppuyez sur Entrée pour continuer...")


if __name__ == '__main__':
    main()
