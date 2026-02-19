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
import logging

# Configuration logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
    
    def scan_range(self, ip_range: str, ports: str = "22,80,443,3389,135,139,445", debug: bool = False) -> List[Dict]:
        logger.info(f"Scan de la plage réseau: {ip_range}")
        logger.info("Cela peut prendre quelques minutes...")
        hosts = []
        try:
            # Arguments Nmap améliorés: T4 pour plus rapide, version-all pour bannières, osscan-guess systématique
            args = f'-sS -O --osscan-guess -T4 --version-all -p {ports}'
            self.nm.scan(hosts=ip_range, arguments=args)
            logger.info(f"Nmap a trouvé {len(self.nm.all_hosts())} hôtes")
            
            for host in self.nm.all_hosts():
                host_info = {
                    'ip': host,
                    'hostname': self._get_hostname(host),
                    'state': self.nm[host].state(),
                    'mac': self._get_mac_address(host),
                    'vendor': self._get_vendor(host),
                    'open_ports': self._get_open_ports(host),
                    'os_info': self._get_os_info(host, debug)
                }
                hosts.append(host_info)
                display_name = host_info['hostname'] if host_info['hostname'] != host else host
                logger.info(f"  Hôte détecté: {host} ({display_name})")
                
        except Exception as e:
            logger.error(f"Erreur lors du scan: {e}")
            hosts = self._simple_ping_scan(ip_range)
        return hosts
    
    def _get_hostname(self, ip: str) -> str:
        """Amélioré: Nmap d'abord, puis DNS, fallback IP"""
        try:
            # Nmap essaie déjà les hostnames
            if 'hostname' in self.nm[ip]:
                hostnames = self.nm[ip]['hostname']
                if hostnames:
                    return hostnames[0]
        except:
            pass
        
        # Fallback DNS
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            pass
        
        # Dernier recours: l'IP
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
                        open_ports.append(int(port))
        except:
            pass
        return sorted(open_ports)
    
    def _get_os_info(self, ip: str, debug: bool = False) -> Dict:
        os_info = {
            'os_family': None,
            'os_gen': None,
            'os_details': None,
            'accuracy': None,
            'build_number': None,
            'nmap_raw': None  # Pour debug
        }
        try:
            if debug:
                logger.debug(f"OS Nmap raw pour {ip}: {self.nm[ip]}")
            
            if 'osmatch' in self.nm[ip]:
                os_matches = self.nm[ip]['osmatch']
                if os_matches:
                    best_match = max(os_matches, key=lambda x: x.get('accuracy', 0))
                    os_info['os_details'] = best_match.get('name', 'Unknown')
                    os_info['accuracy'] = best_match.get('accuracy', 0)
                    name = best_match.get('name', '').lower()
                    os_info['nmap_raw'] = name
                    
                    build_match = re.search(r'build[_\\s]?(\\d+)', name)
                    if build_match:
                        os_info['build_number'] = int(build_match.group(1))
                    
                    if 'windows' in name:
                        os_info['os_family'] = 'Windows'
                        os_info['os_gen'] = self._extract_windows_version(name)
                    elif any(word in name for word in ['linux', 'ubuntu', 'debian', 'centos', 'red hat', 'rhel', 'fedora']):
                        os_info['os_family'] = 'Linux'
                        os_info['os_gen'] = self._extract_linux_version(name)
                    elif 'macos' in name or 'mac os' in name:
                        os_info['os_family'] = 'macOS'
                        os_info['os_gen'] = self._extract_macos_version(name)
            
            if 'osclass' in self.nm[ip]:
                os_classes = self.nm[ip]['osclass']
                if os_classes:
                    best_class = max(os_classes, key=lambda x: x.get('accuracy', 0))
                    if best_class.get('accuracy', 0) > os_info.get('accuracy', 0):
                        os_type = best_class.get('type', '').lower()
                        if 'windows' in os_type:
                            if not os_info['os_family']:
                                os_info['os_family'] = 'Windows'
                        
        except Exception as e:
            if debug:
                logger.debug(f"Erreur _get_os_info {ip}: {e}")
        return os_info
    
    def _extract_windows_version(self, name: str) -> Optional[str]:
        name_lower = name.lower()
        build_match = re.search(r'build[_\\s]?(\\d+)', name_lower)
        build_number = int(build_match.group(1)) if build_match else None
        
        if build_number:
            if build_number >= 22000:
                return f"Windows 11 (Build {build_number})"
            elif build_number >= 10240:
                return f"Windows 10 (Build {build_number})"
        
        if 'windows 11' in name_lower or 'win11' in name_lower:
            return "Windows 11"
        elif 'windows 10' in name_lower:
            return "Windows 10"
        elif 'windows server' in name_lower:
            version_match = re.search(r'windows server[_\\s]?(\\d{4})', name_lower)
            if version_match:
                return f"Windows Server {version_match.group(1)}"
            if build_number:
                if build_number >= 20348: return "Windows Server 2022"
                elif build_number >= 17763: return "Windows Server 2019"
                elif build_number >= 14393: return "Windows Server 2016"
        return None
    
    def _extract_linux_version(self, name: str) -> Optional[str]:
        name_lower = name.lower()
        ubuntu_match = re.search(r'ubuntu[_\\s]?(\\d+\\.\\d+)', name_lower)
        if ubuntu_match: return f"Ubuntu {ubuntu_match.group(1)}"
        debian_match = re.search(r'debian[_\\s]?(\\d+)', name_lower)
        if debian_match: return f"Debian {debian_match.group(1)}"
        centos_match = re.search(r'centos[_\\s]?(\\d+)', name_lower)
        if centos_match: return f"CentOS {centos_match.group(1)}"
        rhel_match = re.search(r'(?:rhel|red[_\\s]?hat|redhat)[_\\s]?(\\d+)', name_lower)
        if rhel_match: return f"RHEL {rhel_match.group(1)}"
        return None
    
    def _extract_macos_version(self, name: str) -> Optional[str]:
        macos_match = re.search(r'mac os x (\\d+\\.\\d+)', name.lower())
        if macos_match: return f"macOS {macos_match.group(1)}"
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
            logger.error(f"Erreur lors du scan ping: {e}")
        return hosts

class OSDetector:
    def __init__(self):
        self.detection_methods = [
            self._detect_via_ssh_banner,
            self._detect_via_http_header,
            self._detect_via_smb,
            self._detect_via_banner_heuristic  # Nouvelle méthode heuristique
        ]
    
    def detect_os(self, ip: str, ports: Dict[int, str] = None, debug: bool = False) -> Dict:
        """Fusionne toutes les méthodes au lieu d'arrêter à la première"""
        all_results = []
        for method in self.detection_methods:
            try:
                result = method(ip, ports)
                if result:
                    all_results.append(result)
                    if debug:
                        logger.debug(f"OS détecté via {result.get('detection_method', 'unknown')}: {result}")
            except Exception as e:
                if debug:
                    logger.debug(f"Échec méthode {method.__name__}: {e}")
        
        # Fusionne les résultats
        if all_results:
            # Prend le plus précis, fallback sur le premier
            best = max(all_results, key=lambda x: x.get('confidence_score', 0))
            return best
        
        return {'os_family': None, 'os_version': None, 'detection_method': 'none'}
    
    def _detect_via_ssh_banner(self, ip: str, ports: Dict = None) -> Optional[Dict]:
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
                    os_info['confidence_score'] = 80
                    return os_info
        except:
            pass
        return None
    
    def _parse_ssh_banner(self, banner: str) -> Optional[Dict]:
        banner_lower = banner.lower()
        # Plus de patterns
        ubuntu_match = re.search(r'ubuntu[_-]?(\\d+\\.\\d+)', banner_lower)
        if ubuntu_match:
            return {'os_family': 'Linux', 'os_version': f"Ubuntu {ubuntu_match.group(1)}"}
        debian_match = re.search(r'debian[_-]?(\\d+)', banner_lower)
        if debian_match:
            return {'os_family': 'Linux', 'os_version': f"Debian {debian_match.group(1)}"}
        centos_match = re.search(r'(?:centos|rhel|redhat)[_-]?(\\d+)', banner_lower)
        if centos_match:
            return {'os_family': 'Linux', 'os_version': f"CentOS/RHEL {centos_match.group(1)}"}
        if 'openssh_for_windows' in banner_lower or 'microsoft' in banner_lower:
            return {'os_family': 'Windows', 'os_version': 'Windows (SSH)'}
        # Au moins détecter Linux/Windows si mots-clés
        if 'linux' in banner_lower:
            return {'os_family': 'Linux'}
        if 'windows' in banner_lower:
            return {'os_family': 'Windows'}
        return None
    
    def _detect_via_http_header(self, ip: str, port: int = 80) -> Optional[Dict]:
        try:
            protocol = 'https' if port == 443 else 'http'
            url = f"{protocol}://{ip}:{port}"
            response = requests.get(url, timeout=3, verify=False, allow_redirects=True)
            server_header = response.headers.get('Server', '').lower()
            
            ubuntu_match = re.search(r'ubuntu[_-]?(\\d+\\.\\d+)', server_header)
            if ubuntu_match:
                return {
                    'os_family': 'Linux',
                    'os_version': f"Ubuntu {ubuntu_match.group(1)}",
                    'detection_method': 'HTTP Header',
                    'confidence_score': 70
                }
            
            if 'microsoft-iis' in server_header or 'windows' in server_header:
                return {
                    'os_family': 'Windows',
                    'os_version': 'Windows Server (IIS)',
                    'detection_method': 'HTTP Header',
                    'confidence_score': 70
                }
        except:
            pass
        return None
    
    def _detect_via_smb(self, ip: str) -> Optional[Dict]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, 445))
            if result == 0:
                smb_negotiate = b'\x00\x00\x00\x54\xffSMB@ \x00'
                sock.send(smb_negotiate)
                response = sock.recv(1024)
                sock.close()
                if response and b'Windows' in response:
                    return {
                        'os_family': 'Windows',
                        'os_version': 'Windows (SMB)',
                        'detection_method': 'SMB',
                        'confidence_score': 90
                    }
        except:
            pass
        return None
    
    def _detect_via_banner_heuristic(self, ip: str, ports: Dict = None) -> Optional[Dict]:
        """Nouvelle: heuristique sur ports ouverts"""
        if not ports:
            return None
        
        open_ports = list(ports.keys())
        if 445 in open_ports or 3389 in open_ports:
            return {'os_family': 'Windows', 'os_version': 'Windows (ports)', 'detection_method': 'Ports', 'confidence_score': 40}
        elif 22 in open_ports:
            return {'os_family': 'Linux', 'os_version': 'Linux/Unix (SSH)', 'detection_method': 'Ports', 'confidence_score': 40}
        return None

# [EOLDatabase, CSVProcessor, ReportGenerator restent identiques]
# Pour gagner de la place, je ne les recopie pas ici mais garde-les du code original

class EOLDatabase:
    def __init__(self):
        self.eol_data = self._load_eol_data()
    
    def _load_eol_data(self) -> Dict:
        # [Même code que dans ton original]
        return {
            'Windows': {
                'Windows 11': {'release_date': date(2021, 10, 5), 'eol_date': None, 'status': 'supported'},
                'Windows 10': {'release_date': date(2015, 7, 29), 'eol_date': date(2025, 10, 14), 'status': 'soon_eol'},
                # ... (reste identique)
            },
            # Linux, macOS identiques
        }
    
    def get_eol_info(self, os_family: str, os_version: str) -> Optional[Dict]:
        # [Identique]
        pass
    
    def get_status(self, eol_info: Dict) -> str:
        # [Identique]
        pass
    
    def get_days_until_eol(self, eol_info: Dict) -> Optional[int]:
        # [Identique]
        pass

# [CSVProcessor et ReportGenerator identiques à l'original]

def scan_network(ip_range: str, output_csv: str = None, debug: bool = False):
    logger.info("="*80)
    logger.info("SCAN RÉSEAU AMÉLIORÉ")
    logger.info("="*80)
    
    scanner = NetworkScanner()
    detector = OSDetector()
    eol_db = EOLDatabase()
    
    hosts = scanner.scan_range(ip_range, debug=debug)
    if not hosts:
        logger.warning("Aucun hôte détecté.")
        return []
    
    logger.info(f"{len(hosts)} hôte(s) détecté(s).")
    logger.info("Analyse des OS et versions...")
    
    components = []
    for host in hosts:
        ip = host['ip']
        os_info_nmap = host.get('os_info', {})
        ports_dict = {port: 'open' for port in host.get('open_ports', [])}
        
        os_info_detected = detector.detect_os(ip, ports_dict, debug=debug)
        
        # Fusion améliorée
        os_family = (os_info_detected.get('os_family') or 
                    os_info_nmap.get('os_family') or 
                    self._guess_os_family_from_ports(host.get('open_ports', [])))
        
        os_version_raw = (os_info_detected.get('os_version') or 
                         os_info_nmap.get('os_gen') or 
                         os_info_nmap.get('os_details') or 'Unknown')
        
        # Build Windows
        build_number = os_info_nmap.get('build_number')
        if build_number and os_family == 'Windows':
            if build_number >= 22000:
                os_version_raw = f"Windows 11 (Build {build_number})"
            elif build_number >= 10240:
                os_version_raw = f"Windows 10 (Build {build_number})"
        
        # Heuristique finale si toujours Unknown
        if os_family == 'Unknown' and os_version_raw == 'Unknown':
            os_family = self._guess_os_family_from_ports(host.get('open_ports', []))
        
        detection_method = os_info_detected.get('detection_method', 'Nmap')
        
        eol_info = eol_db.get_eol_info(os_family, os_version_raw)
        status = eol_db.get_status(eol_info) if eol_info else 'unknown'
        days_until_eol = eol_db.get_days_until_eol(eol_info) if eol_info else None
        
        component = {
            'ip': ip,
            'hostname': host['hostname'],
            'os_family': os_family,
            'os_version': os_version_raw,
            'detection_method': detection_method,
            'eol_info': eol_info,
            'status': status,
            'days_until_eol': days_until_eol,
            'mac': host.get('mac'),
            'vendor': host.get('vendor'),
            'open_ports': host.get('open_ports', []),
            'nmap_accuracy': os_info_nmap.get('accuracy')
        }
        components.append(component)
        
        status_label = {'supported': 'OK', 'soon_eol': 'WARN', 'warning': 'WARN', 
                       'extended_support': 'EXT', 'eol': 'EOL', 'unknown': '?'}.get(status, '?')
        display_os = os_version_raw if os_version_raw != 'Unknown' else os_family
        logger.info(f"  [{status_label}] {ip} ({host['hostname']}) - {display_os} [{detection_method}]")
    
    if output_csv:
        processor = CSVProcessor()
        processor.export_to_csv(components, output_csv)
        logger.info(f"Résultats exportés vers {output_csv}")
    
    return components

def _guess_os_family_from_ports(open_ports: List[int]) -> str:
    """Heuristique simple sur ports"""
    ports = set(open_ports)
    if 445 in ports or 3389 in ports:
        return 'Windows'
    elif 22 in ports:
        return 'Linux'
    elif 161 in ports:  # SNMP
        return 'Network Device'
    return 'Unknown'

# [Reste du code: CSVProcessor, ReportGenerator, menu CLI identiques]
# Pour ne pas allonger, utilise ceux de ton original

# Menu principal avec debug
def main():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("="*80)
        print(" "*25 + "MODULE D'AUDIT D'OBSOLESCENCE RÉSEAU")
        print("="*80)
        print()
        print("1. Scanner une plage réseau")
        print("2. Lister les versions d'un OS et leurs dates EOL")
        print("3. Analyser un fichier CSV")
        print("4. Quitter")
        print("="*80)
        
        choice = input("Votre choix (1-4): ").strip()
        if choice == '1':
            print("\nExemples:")
            print(" - 192.168.1.0/24 (plage CIDR)")
            print(" - 192.168.1.1-192.168.1.100 (plage IP)")
            print(" - 192.168.1.10 (une seule IP)")
            ip_range = input("Plage IP: ").strip()
            if not ip_range:
                input("\nPlage IP vide. Appuyez sur Entrée...")
                continue
            
            debug_choice = input("Mode debug pour OS? (o/n): ").strip().lower()
            debug = debug_choice in ['o', 'oui', 'y', 'yes']
            
            output_csv = None
            if input("Exporter en CSV? (o/n): ").strip().lower() in ['o', 'oui', 'y', 'yes']:
                output_csv = input("Nom du fichier (scanresults.csv): ").strip() or "scanresults.csv"
            
            print("\nDémarrage du scan...")
            try:
                scan_network(ip_range, output_csv, debug)
                input("\nAppuyez sur Entrée pour continuer...")
            except KeyboardInterrupt:
                print("\nInterrompu par l'utilisateur.")
            except Exception as e:
                logger.error(f"Erreur scan: {e}")
                traceback.print_exc()
                input("Appuyez sur Entrée...")
        # [Autres menus identiques]
        elif choice == '4':
            break

if __name__ == '__main__':
    main()
