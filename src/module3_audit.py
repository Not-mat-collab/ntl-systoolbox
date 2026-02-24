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
    
    def scan_range(self, ip_range: str, ports: str = "22,80,443,3389,135,139,445") -> List[Dict]:
        print(f"Scan de la plage réseau: {ip_range}")
        print("Cela peut prendre quelques minutes...")
        hosts = []
        try:
            try:
                self.nm.scan(hosts=ip_range, arguments=f'--privileged -sS -O --osscan-limit -p {ports}')
            except:
                self.nm.scan(hosts=ip_range, arguments=f'--privileged -sS -O --osscan-guess -p {ports}')
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
    
    def _get_hostname(self, ip: str) -> str:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Unknown"
    
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
    
    def _extract_os(self, os_string: str) -> Tuple[str, str]:
        """Extrait OS et version à partir de la chaîne Nmap (approche audit_os_V4)."""
        os_lower = os_string.lower()
        if 'debian' in os_lower:
            numbers = re.findall(r'\d+', os_string)
            if numbers:
                return ('Debian', numbers[0])
            return ('Debian', 'Unknown')
        if 'ubuntu' in os_lower:
            match = re.search(r'(\d+\.\d+)', os_string)
            if match:
                return ('Ubuntu', match.group(1))
            return ('Ubuntu', 'Unknown')
        if 'windows server' in os_lower:
            match = re.search(r'(2003|2008|2012|2016|2019|2022|2025)', os_string)
            version = 'Unknown'
            if match:
                version = match.group(1)
                if 'r2' in os_lower:
                    version += ' R2'
            return ('Windows Server', version)
        if 'windows' in os_lower or 'microsoft' in os_lower:
            for v in ['11', '10', '8.1', '8', '7']:
                if v in os_lower:
                    return ('Windows', v)
            return ('Windows', 'Unknown')
        if 'linux' in os_lower:
            return ('Linux', 'Unknown')
        return (os_string, 'Unknown')

    def _get_os_info(self, ip: str) -> Dict:
        os_info = {
            'os_family': None,
            'os_gen': None,
            'os_details': None,
            'accuracy': None,
            'build_number': None,
            'is_server': False
        }
        try:
            os_matches = self.nm[ip].get('osmatch', [])
            if not os_matches:
                for osc in self.nm[ip].get('osclass', []):
                    vendor = osc.get('vendor', '').lower()
                    osfamily = osc.get('osfamily', '').lower()
                    if 'microsoft' in vendor or 'windows' in osfamily:
                        os_info['os_family'] = 'Windows'
                    elif 'linux' in vendor or 'linux' in osfamily:
                        os_info['os_family'] = 'Linux'
                    if osc.get('type', '').lower() == 'server':
                        os_info['is_server'] = True
                return os_info
            best_match = max(os_matches, key=lambda x: int(x.get('accuracy', 0)))
            os_info['os_details'] = best_match.get('name', 'Unknown')
            os_info['accuracy'] = int(best_match.get('accuracy', 0))

            for match in os_matches:
                name = match.get('name', '').lower()
                bm = re.search(r'build[_\s]?(\d+)', name)
                if bm and not os_info['build_number']:
                    os_info['build_number'] = int(bm.group(1))

            for osc in best_match.get('osclass', []):
                if osc.get('type', '').lower() == 'server':
                    os_info['is_server'] = True
                for cpe in osc.get('cpe', []):
                    if 'windows_server' in cpe.lower():
                        os_info['is_server'] = True
            for osc in self.nm[ip].get('osclass', []):
                if osc.get('type', '').lower() == 'server':
                    os_info['is_server'] = True
            for match in os_matches:
                os_raw = match.get('name', '')
                os_name, version = self._extract_os(os_raw)
                if os_name in ('Ubuntu', 'Debian') and version != 'Unknown':
                    os_info['os_family'] = 'Linux'
                    os_info['os_gen'] = f"{os_name} {version}"
                    break
                if os_name == 'Windows Server' and version != 'Unknown':
                    os_info['os_family'] = 'Windows'
                    os_info['os_gen'] = f"Windows Server {version}"
                    os_info['is_server'] = True
                    break
                if os_name == 'Windows' and version != 'Unknown':
                    os_info['os_family'] = 'Windows'
                    os_info['os_gen'] = f"Windows {version}"
                    break
            if not os_info['os_gen']:
                for match in os_matches:
                    os_raw = match.get('name', '')
                    os_name, version = self._extract_os(os_raw)
                    if os_name in ('Ubuntu', 'Debian'):
                        os_info['os_family'] = 'Linux'
                        break
                    if os_name == 'Windows Server':
                        os_info['os_family'] = 'Windows'
                        os_info['is_server'] = True
                        break
                    if os_name == 'Windows':
                        os_info['os_family'] = 'Windows'
                        break
                    if os_name == 'Linux':
                        os_info['os_family'] = 'Linux'
                        break
            if not os_info['os_gen'] and os_info['os_family'] == 'Linux':
                for match in os_matches:
                    for osc in match.get('osclass', []):
                        for cpe in osc.get('cpe', []):
                            cpe_lower = cpe.lower()
                            m = re.search(r'debian[_:].*?:(\d+)', cpe_lower)
                            if m:
                                os_info['os_gen'] = f"Debian {m.group(1)}"
                                break
                            m = re.search(r'ubuntu[_:].*?:(\d+\.\d+)', cpe_lower)
                            if m:
                                os_info['os_gen'] = f"Ubuntu {m.group(1)}"
                                break
                        if os_info['os_gen']:
                            break
                    if os_info['os_gen']:
                        break
            if os_info['os_family'] == 'Windows' and not os_info['os_gen']:
                for match in os_matches:
                    for osc in match.get('osclass', []):
                        osgen = osc.get('osgen', '').strip()
                        if osgen:
                            gen_result = self._extract_os(f"windows {'server ' if os_info['is_server'] else ''}{osgen}")
                            if gen_result[1] != 'Unknown':
                                if gen_result[0] == 'Windows Server':
                                    os_info['os_gen'] = f"Windows Server {gen_result[1]}"
                                else:
                                    os_info['os_gen'] = f"Windows {gen_result[1]}"
                                break
                        for cpe in osc.get('cpe', []):
                            cpe_lower = cpe.lower()
                            m = re.search(r'windows_server[_:](\d{4})', cpe_lower)
                            if m:
                                os_info['os_gen'] = f"Windows Server {m.group(1)}"
                                os_info['is_server'] = True
                                break
                            m = re.search(r'windows[_:](\d+)', cpe_lower)
                            if m and not os_info['os_gen']:
                                ver = m.group(1)
                                if ver in ('11', '10', '7', '8'):
                                    os_info['os_gen'] = f"Windows {ver}"
                                    break
                        if os_info['os_gen']:
                            break
                    if os_info['os_gen']:
                        break
            if os_info['os_family'] == 'Windows' and not os_info['os_gen']:
                bn = os_info['build_number']
                if bn:
                    if os_info['is_server']:
                        if bn >= 26100:
                            os_info['os_gen'] = "Windows Server 2025"
                        elif bn >= 20348:
                            os_info['os_gen'] = "Windows Server 2022"
                        elif bn >= 17763:
                            os_info['os_gen'] = "Windows Server 2019"
                        elif bn >= 14393:
                            os_info['os_gen'] = "Windows Server 2016"
                    else:
                        if bn >= 22000:
                            os_info['os_gen'] = "Windows 11"
                        elif bn >= 10240:
                            os_info['os_gen'] = "Windows 10"
        except Exception:
            pass
        return os_info
    
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
            self._detect_via_msrpc,
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
            'build_number': None,
            'confidence': 'low'
        }
        for method in self.detection_methods:
            try:
                result = method(ip, ports)
                if result and result.get('os_version'):
                    os_info.update(result)
                    os_info['confidence'] = 'high'
                    if os_info.get('build_number'):
                        break
            except Exception:
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
    
    def _detect_via_smb(self, ip: str, ports: Dict = None) -> Optional[Dict]:
        """Detect exact Windows version via SMB2 + NTLM negotiation.

        The NTLMSSP CHALLENGE message always contains the OS build number in
        its Version field (bytes 48-55), regardless of authentication.
        No credentials are required.
        """
        import struct

        def _asn1_len(n: int) -> bytes:
            if n < 0x80:
                return bytes([n])
            if n < 0x100:
                return bytes([0x81, n])
            return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            if sock.connect_ex((ip, 445)) != 0:
                sock.close()
                return None

            smb2_hdr = bytearray(64)
            smb2_hdr[0:4] = b'\xfeSMB'
            smb2_hdr[4:6] = b'\x40\x00'
            neg_body = (
                b'\x24\x00'
                b'\x01\x00'
                b'\x00\x00'
                b'\x00\x00'
                b'\x00\x00\x00\x00'
                + b'\x00' * 16
                + b'\x00' * 8
                + b'\x02\x02'
            )
            payload1 = bytes(smb2_hdr) + neg_body
            sock.send(struct.pack('>I', len(payload1)) + payload1)

            buf = b''
            while len(buf) < 4:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
            if len(buf) < 4:
                sock.close()
                return None
            nb_len = struct.unpack('>I', buf[:4])[0]
            while len(buf) < 4 + nb_len:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
            if buf[4:8] != b'\xfeSMB':
                sock.close()
                return None

            ntlmssp_flags = 0xE2088297
            ntlmssp_neg = (
                b'NTLMSSP\x00'
                b'\x01\x00\x00\x00'
                + struct.pack('<I', ntlmssp_flags)
                + b'\x00\x00\x00\x00\x28\x00\x00\x00'
                + b'\x00\x00\x00\x00\x28\x00\x00\x00'
                + b'\x06\x01\x00\x00\x00\x00\x00\x0f'
            )

            mech_ntlm       = b'\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a'
            mech_tok_inner  = b'\x04' + _asn1_len(len(ntlmssp_neg)) + ntlmssp_neg
            mech_tok_ctx    = b'\xa2' + _asn1_len(len(mech_tok_inner)) + mech_tok_inner
            mech_list_inner = b'\x06' + bytes([len(mech_ntlm)]) + mech_ntlm
            mech_list_seq   = b'\x30' + _asn1_len(len(mech_list_inner)) + mech_list_inner
            mech_list_ctx   = b'\xa0' + _asn1_len(len(mech_list_seq)) + mech_list_seq
            neg_tok_seq     = mech_list_ctx + mech_tok_ctx
            neg_tok         = b'\x30' + _asn1_len(len(neg_tok_seq)) + neg_tok_seq
            neg_tok_init    = b'\xa0' + _asn1_len(len(neg_tok)) + neg_tok
            spnego_oid      = b'\x06\x06\x2b\x06\x01\x05\x05\x02'
            spnego_seq      = spnego_oid + neg_tok_init
            sec_blob        = b'\x60' + _asn1_len(len(spnego_seq)) + spnego_seq

            sec_offset = 64 + 25
            ss_body = (
                b'\x19\x00'
                b'\x00'
                b'\x00'
                b'\x00\x00\x00\x00'
                b'\x00\x00\x00\x00'
                + struct.pack('<H', sec_offset)
                + struct.pack('<H', len(sec_blob))
                + b'\x00' * 8
                + sec_blob
            )
            smb2_hdr2 = bytearray(64)
            smb2_hdr2[0:4]   = b'\xfeSMB'
            smb2_hdr2[4:6]   = b'\x40\x00'
            smb2_hdr2[12:14] = b'\x01\x00'
            smb2_hdr2[14:16] = b'\x01\x00'
            smb2_hdr2[28:36] = b'\x01\x00\x00\x00\x00\x00\x00\x00'

            payload2 = bytes(smb2_hdr2) + ss_body
            sock.send(struct.pack('>I', len(payload2)) + payload2)

            buf2 = b''
            while len(buf2) < 4:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf2 += chunk
            if len(buf2) < 4:
                sock.close()
                return None
            nb_len2 = struct.unpack('>I', buf2[:4])[0]
            while len(buf2) < 4 + nb_len2:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf2 += chunk
            sock.close()

            idx = buf2.find(b'NTLMSSP\x00\x02\x00\x00\x00')
            if idx < 0:
                return None
            chal = buf2[idx:]
            if len(chal) < 56:
                return None

            flags = struct.unpack('<I', chal[20:24])[0]
            if not (flags & 0x02000000):
                return None

            build = struct.unpack('<H', chal[50:52])[0]
            if build < 6000:
                return None

            return {
                'os_family': 'Windows',
                'os_version': 'Windows',
                'build_number': build,
                'detection_method': 'SMB/NTLM'
            }
        except Exception:
            pass
        return None
    
    def _detect_via_snmp(self, ip: str, ports: Dict = None) -> Optional[Dict]:
        return None

    def _detect_via_msrpc(self, ip: str, ports: Dict = None) -> Optional[Dict]:
        """Detect Windows via MSRPC endpoint mapper (port 135).
        Port 135 is exclusive to Windows. A successful TCP connection is enough
        to confirm the OS family; we return a generic 'Windows' os_version so
        the build-number logic in scan_network can still refine it.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            if sock.connect_ex((ip, 135)) == 0:
                sock.close()
                return {
                    'os_family': 'Windows',
                    'os_version': 'Windows',
                    'detection_method': 'MSRPC'
                }
            sock.close()
        except Exception:
            pass
        return None
    
    def normalize_os_version(
        self,
        os_family: str,
        raw_version: str,
        build_number: Optional[int] = None,
        is_server: bool = False
    ) -> str:
        if not raw_version:
            return "Unknown"
        raw_lower = raw_version.lower()
        if os_family == 'Windows':
            is_server_hint = is_server or ('server' in raw_lower and 'windows' in raw_lower)

            if is_server_hint:
                year_match = re.search(r'server[_\s]?(\d{4})', raw_lower)
                if year_match:
                    year = int(year_match.group(1))
                    return "Windows Server 2025" if year >= 2025 else "Windows Server 2022"
                if '2025' in raw_lower:
                    return "Windows Server 2025"
                if '2022' in raw_lower or '2019' in raw_lower or '2016' in raw_lower:
                    return "Windows Server 2022"
            else:
                if 'windows 11' in raw_lower or 'win11' in raw_lower:
                    return "Windows 11"
                if 'windows 10' in raw_lower or 'win10' in raw_lower:
                    return "Windows 10"

            bn = build_number
            if bn is None:
                build_match = re.search(r'build[_\s]?(\d+)', raw_lower)
                if build_match:
                    bn = int(build_match.group(1))
            if bn is not None:
                if 22000 <= bn < 26100:
                    return "Windows 11"
                if 20348 <= bn < 22000:
                    return "Windows Server 2022"
                if 19041 <= bn < 20348:
                    return "Windows 10"
                if bn >= 26100:
                    return "Windows Server 2025" if is_server_hint else "Windows 11"
                if bn >= 17763:
                    return "Windows Server 2019" if is_server_hint else "Windows 10"
                if bn >= 14393:
                    return "Windows Server 2016" if is_server_hint else "Windows 10"
                return "Windows 10"

            if is_server_hint:
                return "Windows Server 2022"
            if '11' in raw_lower:
                return "Windows 11"
            return "Windows 10"
        elif os_family == 'Linux':
            ubuntu_match = re.search(r'ubuntu[_\s]?(\d+\.\d+)', raw_lower)
            if ubuntu_match:
                return f"Ubuntu {ubuntu_match.group(1)}"
            debian_match = re.search(r'debian[_\s]?(\d+)', raw_lower)
            if debian_match:
                return f"Debian {debian_match.group(1)}"
            centos_match = re.search(r'centos[_\s]?(\d+)', raw_lower)
            if centos_match:
                return f"CentOS {centos_match.group(1)}"
            rhel_match = re.search(r'(?:rhel|red[_\s]?hat|redhat)[_\s]?(\d+)', raw_lower)
            if rhel_match:
                return f"RHEL {rhel_match.group(1)}"
            if 'linux' in raw_lower and raw_lower != 'linux':
                return raw_version
            return "Linux"
        elif os_family == 'macOS':
            macos_match = re.search(r'mac[_\s]?os[_\s]?x?[_\s]?(\d+\.\d+)', raw_lower)
            if macos_match:
                return f"macOS {macos_match.group(1)}"
            return "macOS"
        return raw_version


class EOLDatabase:
    API_BASE_URL = "https://endoflife.date/api"
    PRODUCTS = [
        {'os_family': 'Windows', 'api_product': 'windows', 'type': 'windows_client',
         'eol_field': 'eol', 'extended_field': 'extendedSupport'},
        {'os_family': 'Windows', 'api_product': 'windowsserver', 'type': 'windows_server',
         'eol_field': 'support', 'extended_field': 'eol'},
        {'os_family': 'Linux', 'api_product': 'ubuntu', 'type': 'standard', 'prefix': 'Ubuntu',
         'eol_field': 'eol', 'extended_field': 'extendedSupport', 'max_versions': 4},
        {'os_family': 'Linux', 'api_product': 'debian', 'type': 'standard', 'prefix': 'Debian',
         'eol_field': 'eol', 'extended_field': 'extendedSupport', 'max_versions': 4},
    ]

    def __init__(self):
        self.eol_data = self._load_eol_data()

    def _load_eol_data(self) -> Dict:
        print("Récupération des données EOL depuis endoflife.date...")
        data = {'Windows': {}, 'Linux': {}}
        for product in self.PRODUCTS:
            try:
                cycles = self._fetch_api(product['api_product'])
                entries = self._parse_product(cycles, product)
                data[product['os_family']].update(entries)
            except Exception as e:
                print(f"  Avertissement ({product['api_product']}): {e}")
        total = sum(len(v) for v in data.values())
        print(f"  {total} version(s) chargée(s) depuis l'API.")
        return data

    def _fetch_api(self, product: str) -> list:
        url = f"{self.API_BASE_URL}/{product}.json"
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def _parse_date(value) -> Optional[date]:
        if isinstance(value, str):
            try:
                return datetime.strptime(value, '%Y-%m-%d').date()
            except ValueError:
                return None
        return None

    @staticmethod
    def _parse_eol_value(value) -> Optional[date]:
        """Parse an EOL field that can be False (supported), True (EOL, no date), or a date string."""
        if value is False:
            return None
        if value is True:
            return date.today()
        if isinstance(value, str):
            try:
                return datetime.strptime(value, '%Y-%m-%d').date()
            except ValueError:
                return None
        return None

    def _parse_product(self, cycles: list, config: dict) -> Dict:
        ptype = config['type']
        if ptype == 'windows_client':
            return self._parse_windows_client(cycles, config)
        elif ptype == 'windows_server':
            return self._parse_windows_server(cycles, config)
        return self._parse_standard(cycles, config)

    def _parse_windows_client(self, cycles: list, config: dict) -> Dict:
        """Consolidate Windows client cycles by major version (10, 11, etc.).
        Uses earliest release date and latest EOL date per major version."""
        groups = {}
        for c in cycles:
            cid = c.get('cycle', '')
            if 'lts' in cid or 'iot' in cid:
                continue
            if cid.startswith('11-'):
                major = '11'
            elif cid.startswith('10-'):
                major = '10'
            else:
                continue
            rd = self._parse_date(c.get('releaseDate'))
            eol = self._parse_eol_value(c.get(config['eol_field']))
            ext = self._parse_eol_value(c.get(config['extended_field'])) if config.get('extended_field') else None
            if major not in groups:
                groups[major] = {'release_date': rd, 'eol_date': eol, 'eol_extended_date': ext}
            else:
                g = groups[major]
                if rd and (not g['release_date'] or rd < g['release_date']):
                    g['release_date'] = rd
                if eol and (not g['eol_date'] or eol > g['eol_date']):
                    g['eol_date'] = eol
                if ext and (not g['eol_extended_date'] or ext > g['eol_extended_date']):
                    g['eol_extended_date'] = ext
        return {f"Windows {m}": info for m, info in groups.items()}

    def _parse_windows_server(self, cycles: list, config: dict) -> Dict:
        """Parse Windows Server cycles, keeping only LTSC (long-term) editions."""
        result = {}
        for c in cycles:
            if not c.get('lts', False):
                continue
            cid = c.get('cycle', '')
            year_match = re.search(r'(\d{4})', cid)
            if not year_match:
                continue
            year = year_match.group(1)
            if year not in ('2016', '2019', '2022', '2025'):
                continue
            name = f"Windows Server {year}"
            rd = self._parse_date(c.get('releaseDate'))
            eol = self._parse_eol_value(c.get(config['eol_field']))
            ext = self._parse_eol_value(c.get(config['extended_field']))
            if name not in result or (eol and (not result[name]['eol_date'] or eol > result[name]['eol_date'])):
                result[name] = {'release_date': rd, 'eol_date': eol, 'eol_extended_date': ext}
        return result

    def _parse_standard(self, cycles: list, config: dict) -> Dict:
        prefix = config['prefix']
        eol_field = config['eol_field']
        ext_field = config.get('extended_field')
        max_versions = config.get('max_versions')
        entries = []
        for c in cycles:
            name = f"{prefix} {c.get('cycle', '')}"
            rd = self._parse_date(c.get('releaseDate'))
            eol = self._parse_eol_value(c.get(eol_field))
            ext = self._parse_eol_value(c.get(ext_field)) if ext_field else None
            entries.append((name, {'release_date': rd, 'eol_date': eol, 'eol_extended_date': ext}))
        if max_versions:
            entries.sort(key=lambda x: x[1].get('release_date') or date.min, reverse=True)
            entries = entries[:max_versions]
        return dict(entries)

    def get_eol_info(self, os_family: str, os_version: str) -> Optional[Dict]:
        if os_family not in self.eol_data:
            return None
        family_data = self.eol_data[os_family]
        if os_version in family_data:
            return family_data[os_version].copy()
        for key, value in family_data.items():
            if os_version.lower() in key.lower() or key.lower() in os_version.lower():
                result = value.copy()
                result['matched_version'] = key
                return result
        if os_version.startswith('CentOS ') and not os_version.startswith('CentOS Stream'):
            stream_key = os_version.replace('CentOS ', 'CentOS Stream ', 1)
            if stream_key in family_data:
                result = family_data[stream_key].copy()
                result['matched_version'] = stream_key
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
        versions.sort(key=lambda x: x.get('release_date') or date.min, reverse=True)
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
        return 'supported'

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
            'warning': 'EOL dans moins d\'un an',
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

        if os_family == 'Unknown':
            win_ports = {135, 139, 445, 3389}
            if win_ports.intersection(set(host.get('open_ports', []))):
                os_family = 'Windows'

        is_server = os_info_nmap.get('is_server', False)

        build_number = os_info_detected.get('build_number') or os_info_nmap.get('build_number')

        os_version_raw = os_info_detected.get('os_version') or os_info_nmap.get('os_gen') or 'Unknown'

        if os_version_raw in ('Unknown', 'Windows', None) and os_info_nmap.get('os_details'):
            os_name, ver = scanner._extract_os(os_info_nmap['os_details'])
            if ver != 'Unknown':
                if os_name == 'Windows Server':
                    os_version_raw = f"Windows Server {ver}"
                    is_server = True
                elif os_name in ('Windows', 'Ubuntu', 'Debian'):
                    os_version_raw = f"{os_name} {ver}"
            elif os_name in ('Windows', 'Windows Server', 'Linux', 'Ubuntu', 'Debian'):
                os_version_raw = os_info_nmap['os_details']

        if build_number and os_family == 'Windows':
            is_srv = is_server or 'server' in (os_version_raw or '').lower() or \
                     'server' in (os_info_nmap.get('os_details') or '').lower()
            if 22000 <= build_number < 26100:
                os_version_raw = "Windows 11"
                is_server = False
            elif 20348 <= build_number < 22000:
                os_version_raw = "Windows Server 2022"
                is_server = True
            elif 19041 <= build_number < 20348:
                os_version_raw = "Windows 10"
                is_server = False
            elif build_number >= 26100:
                os_version_raw = "Windows Server 2025" if is_srv else "Windows 11"
                is_server = is_srv
            elif build_number >= 17763:
                os_version_raw = "Windows Server 2019" if is_srv else "Windows 10"
                is_server = is_srv
            elif build_number >= 14393:
                os_version_raw = "Windows Server 2016" if is_srv else "Windows 10"
                is_server = is_srv
            else:
                os_version_raw = "Windows 10"

        if os_family == 'Linux' and (os_version_raw == 'Unknown' or os_version_raw.lower() == 'linux'):
            linux_version = os_info_nmap.get('os_gen')
            if linux_version and linux_version.lower() != 'linux':
                os_version_raw = linux_version

        os_version = detector.normalize_os_version(
            os_family,
            os_version_raw,
            build_number=build_number,
            is_server=is_server
        )
        if os_version == 'Linux' and os_version_raw != 'Unknown' and os_version_raw.lower() != 'linux':
            if 'ubuntu' in os_version_raw.lower() or 'debian' in os_version_raw.lower() or \
               'centos' in os_version_raw.lower() or 'rhel' in os_version_raw.lower() or \
               'red hat' in os_version_raw.lower():
                os_version = os_version_raw
        eol_info = eol_db.get_eol_info(os_family, os_version)
        status = eol_db.get_status(eol_info) if eol_info else 'unknown'
        days_until_eol = eol_db.get_days_until_eol(eol_info) if eol_info else None
        component = {
            'ip': ip,
            'hostname': host.get('hostname', 'Unknown'),
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
        print(f"  {status_label} {ip} ({host.get('hostname', 'Unknown')}) - {display_os}")
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
    print("  [3] Retour au menu principal")
    print()
    choice = input("Votre choix [1-3]: ").strip()
    os_families = {
        '1': 'Windows',
        '2': 'Linux'
    }
    if choice in os_families:
        os_family = os_families[choice]
        clear_screen()
        try:
            list_os_versions(os_family)
        except Exception as e:
            print(f"\nErreur: {e}")
    elif choice == '3':
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
            break
        else:
            print("\nChoix invalide. Veuillez entrer un nombre entre 1 et 4.")
            input("\nAppuyez sur Entrée pour continuer...")


if __name__ == '__main__':
    main()
