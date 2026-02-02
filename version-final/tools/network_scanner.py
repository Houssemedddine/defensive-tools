#!/usr/bin/env python3
"""
Network Scanner Module
Scans network ranges to discover active hosts
"""

import socket
import ipaddress
import threading
import time
import subprocess
import platform
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# Common OUI Prefixes for Vendor Lookup (Offline Fallback)
OUI_VENDORS = {
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "00:1C:14": "VMware",
    "08:00:27": "Oracle (VirtualBox)",
    "0A:00:27": "Oracle (VirtualBox)",
    "00:15:5D": "Microsoft (Hyper-V)",
    "00:03:FF": "Microsoft (Hyper-V)",
    "DC:A6:32": "Raspberry Pi",
    "B8:27:EB": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "D8:3A:DD": "Raspberry Pi",
    "28:CD:C1": "Raspberry Pi",
    "AC:DE:48": "Private/Local",
    "00:1A:11": "Google",
    "F4:F5:D4": "Google",
    "80:2A:A8": "Ubiquiti",
    "F0:9F:C2": "Ubiquiti",
    "74:83:C2": "Ubiquiti",
    "18:E8:29": "Ubiquiti",
    "44:D9:E7": "Ubiquiti",
    "B4:FB:E4": "Ubiquiti",
    "00:11:32": "Synology",
    "00:11:11": "Intel",
    "00:19:D1": "Intel",
    "3C:D9:2B": "Hewlett Packard",
    "9C:8E:99": "Hewlett Packard",
    "10:65:30": "Cisco",
    "00:04:9F": "Cisco",
    "BC:5F:F4": "ASRock",
    "70:85:C2": "ASRock",
    "D8:BB:C1": "Logitech",
    "00:1F:29": "Hewlett Packard",
    "A4:2B:B0": "Espressif (IoT)",
    "24:62:AB": "Espressif (IoT)",
    "84:CC:A8": "Espressif (IoT)",
    "3C:71:BF": "Espressif (IoT)",
    "AC:D0:74": "Espressif (IoT)",
    "B4:E6:2D": "Espressif (IoT)",
    "CC:50:E3": "Espressif (IoT)",
    "EC:FA:BC": "Espressif (IoT)",
    "F0:9E:9E": "Espressif (IoT)",
    "5C:CF:7F": "Espressif (IoT)",
    "60:01:94": "Espressif (IoT)",
    "00:24:D2": "ASUS (Router)",
    "04:D9:F5": "ASUS (Router)",
    "F0:79:59": "ASUS (Router)",
    "78:24:AF": "ASUS (Router)",
    "C0:3F:0E": "Netgear",
    "A0:04:60": "Netgear",
    "00:14:6C": "Netgear",
    "C4:A8:1D": "D-Link",
    "B0:C5:54": "D-Link",
    "00:18:E7": "D-Link",
    "50:C7:BF": "TP-Link",
    "18:A6:F7": "TP-Link",
    "98:48:27": "TP-Link",
    "F4:F2:6D": "TP-Link",
    "00:1B:44": "SanDisk",
    "00:26:82": "Gemtek (Router)",
    "00:1D:AA": "HUAWEI",
    "F8:3D:FF": "HUAWEI",
    "E8:39:35": "HUAWEI",
    "00:25:9E": "HUAWEI",
    "80:B6:55": "ZTE",
    "F4:12:FA": "ZTE",
    "08:18:1A": "ZTE",
    "2C:AB:25": "Xiaomi",
    "64:CC:2E": "Xiaomi",
    "00:25:00": "Apple",
    "00:17:F2": "Apple",
    "DC:2B:2A": "Apple",
    "A8:20:66": "Apple",
    "F0:18:98": "Apple",
    "AC:87:A3": "Apple",
    "48:D7:05": "Apple",
    "FC:FC:48": "Apple",
    "00:1E:52": "Apple",
    "00:1B:63": "Apple",
    "28:CF:E9": "Apple",
    "7C:D1:C3": "Apple",
    "34:36:3B": "Apple",
    "18:AF:61": "Apple",
    "34:12:98": "Apple",
}


class NetworkScanner:
    def __init__(self, timeout=1, max_threads=100):
        self.timeout = timeout
        self.max_threads = max_threads
        self.active_hosts = []
        self.lock = threading.Lock()

    # ---------- Low-level host check helpers ----------

    def _ping_host_tcp(self, ip):
        """
        Check if a host is reachable using TCP connection to common ports.

        This is the original behaviour: try a small list of ports
        (80, 443, 22, ...) and consider the host "up" if any of them
        responds to a TCP connect() within the timeout.
        """
        try:
            # Try common ports for host detection
            test_ports = [80, 443, 22, 21, 25, 53, 135, 139, 445]
            
            for port in test_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    result = sock.connect_ex((str(ip), port))
                    sock.close()
                    
                    if result == 0:
                        with self.lock:
                            # Get MAC first, so we can use it for Vendor lookup if hostname fails
                            mac_addr = self.get_mac_address(str(ip))
                            host_info = self.get_host_info(str(ip), mac_addr)
                            self.active_hosts.append((str(ip), port, host_info, mac_addr))
                        return True
                except:
                    continue
            
        except Exception:
            pass
        return False

    def _ping_host_icmp(self, ip):
        """
        Check if a host is reachable using an ICMP ping.

        We call the system 'ping' command to avoid raw socket
        privileges. This is slower than TCP connect checks but
        works even when common TCP ports are closed.
        """
        ip_str = str(ip)

        # Build platform-specific ping command
        if platform.system().lower().startswith("win"):
            # Windows: -n 1 (one echo), -w timeout_ms
            timeout_ms = int(self.timeout * 1000)
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip_str]
        else:
            # Unix/macOS: -c 1 (one echo), -W timeout_sec (Linux)
            timeout_sec = max(1, int(self.timeout))
            cmd = ["ping", "-c", "1", "-W", str(timeout_sec), ip_str]

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if result.returncode == 0:
                # Host responded to ICMP
                with self.lock:
                    mac_addr = self.get_mac_address(ip_str)
                    host_info = self.get_host_info(ip_str, mac_addr)
                    # Port is "ICMP" to indicate method used
                    self.active_hosts.append((ip_str, "ICMP", host_info, mac_addr))
                return True
        except Exception:
            pass
        return False
    
    def get_host_info(self, ip, mac=None):
        """Get additional information about the host with better resolution
        
        Args:
            ip (str): IP address to resolve
            mac (str, optional): MAC address for vendor lookup fallback
        """
        try:
            # Try standard DNS resolution first
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                if hostname and hostname != ip:
                    return hostname
            except Exception:
                pass
            
            # Try FQDN
            try:
                hostname = socket.getfqdn(ip)
                if hostname and hostname != ip:
                    return hostname
            except Exception:
                pass

            # On Windows, try NetBIOS name using nbtstat
            if platform.system().lower() == "windows":
                try:
                    cmd = ["nbtstat", "-A", ip]
                    # Use subprocess to run nbtstat, suppress window on Windows
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        startupinfo=startupinfo,
                        timeout=2
                    )
                    
                    if result.returncode == 0:
                        # Parse output for the NetBIOS name
                        # Look for line with <00> UNIQUE
                        # LAN-ComputerName   <00>  UNIQUE
                        lines = result.stdout.splitlines()
                        for line in lines:
                            if "<00>" in line and "UNIQUE" in line:
                                parts = line.split()
                                if parts:
                                    return parts[0]
                except Exception:
                    pass

                except Exception:
                    pass
            
            # Fallback: OUI Vendor Lookup if MAC is provided and hostname is still unknown/IP
            if mac and mac != "Unknown":
                try:
                    # Clean MAC and take first 3 bytes (6 chars)
                    clean_mac = mac.replace(":", "").replace("-", "").upper()
                    if len(clean_mac) >= 6:
                        prefix = ":".join([clean_mac[i:i+2] for i in range(0, 6, 2)])
                        
                        # Check OUI map
                        if prefix in OUI_VENDORS:
                            return f"{OUI_VENDORS[prefix]}"
                except Exception:
                    pass

            return "Unknown"
        except Exception:
            return "Error"
    
    def get_mac_address(self, ip):
        """Get the MAC address of the host using ARP with multiple fallbacks"""
        try:
            ip_str = str(ip)
            
            # Check if this is the local machine
            try:
                # Get all local IPs
                local_ips = [info[4][0] for info in socket.getaddrinfo(socket.gethostname(), None) if info[0] == socket.AF_INET]
                if ip_str in local_ips or ip_str == "127.0.0.1":
                    # For local machine, we might not get it via ARP. 
                    # On Windows 'getmac' is an option, or uuid
                    if platform.system().lower() == "windows":
                         # Try getmac for local interface
                         try:
                             # This is a bit slow but accurate for local
                             # getmac /FO CSV /NH /V
                             cmd = ["getmac", "/FO", "CSV", "/NH"]
                             res = subprocess.run(cmd, capture_output=True, text=True)
                             if res.returncode == 0:
                                 # We can't easily map IP to MAC with getmac alone without parsing ipconfig too.
                                 # But often UUID is sufficient fallback for "Self"
                                 pass
                         except:
                             pass
                    
                    # Generic Python fallback for "own" MAC (hardware address of first interface)
                    import uuid
                    mac_num = uuid.getnode()
                    mac = ':'.join(('%012X' % mac_num)[i:i+2] for i in range(0, 12, 2))
                    return mac
            except:
                pass

            # Standard ARP lookup
            cmd = ["arp", "-a", ip_str] if platform.system().lower() == "windows" else ["arp", "-a", ip_str]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            output = result.stdout
            
            # Pattern for MAC address (Windows 00-11..., Linux/Mac 00:11...)
            mac_pattern = r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"
            match = re.search(mac_pattern, output)
            
            if match:
                return match.group(0).upper().replace("-", ":")
            
            # Fallback: Read FULL ARP table (sometimes specific IP lookup fails on some Windows versions)
            cmd_full = ["arp", "-a"]
            result_full = subprocess.run(
                cmd_full,
                capture_output=True,
                text=True
            )
            
            # Look for line containing the IP
            for line in result_full.stdout.splitlines():
                if ip_str in line:
                    match = re.search(mac_pattern, line)
                    if match:
                        return match.group(0).upper().replace("-", ":")

            return "Unknown"
        except Exception:
            return "Unknown"
    
    # ---------- High-level API ----------

    def scan(self, network_range, method="tcp"):
        """
        Scan a network range for active hosts.

        Parameters
        ----------
        network_range : str
            CIDR notation (e.g. "192.168.1.0/24") or a single IP.
        method : str
            "tcp"  -> TCP port-based discovery (with ICMP fallback if nothing found)
            "icmp" -> ICMP ping discovery only.
        """
        self.active_hosts = []
        start_time = time.time()
        
        try:
            # Parse network range
            network = ipaddress.ip_network(network_range, strict=False)
            hosts = list(network.hosts())
            
            if len(hosts) == 0:
                # Single host
                hosts = [network.network_address]
            
            results = f"Network Scan Results for {network_range}\n"
            results += f"{'='*50}\n\n"
            results += f"Scanning {len(hosts)} hosts...\n"
            results += f"Method: {'TCP (ports)' if method == 'tcp' else 'ICMP ping'}\n\n"

            def _scan_with(func):
                with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                    future_to_ip = {executor.submit(func, ip): ip for ip in hosts}
                    completed = 0
                    for _future in as_completed(future_to_ip):
                        completed += 1
                        if completed % 50 == 0:  # Progress update every 50 hosts
                            nonlocal results
                            results += f"Scanned {completed}/{len(hosts)} hosts...\n"

            # Primary scan
            if method == "icmp":
                _scan_with(self._ping_host_icmp)
            else:
                _scan_with(self._ping_host_tcp)

            # If user chose TCP and we found nothing, try ICMP fallback
            icmp_fallback_used = False
            if method == "tcp" and not self.active_hosts:
                icmp_fallback_used = True
                results += "\nNo hosts responded to common TCP ports.\n"
                results += "Attempting ICMP ping fallback...\n\n"
                _scan_with(self._ping_host_icmp)

            # Sort results by IP
            self.active_hosts.sort(key=lambda x: ipaddress.ip_address(x[0]))
            
            end_time = time.time()
            scan_duration = end_time - start_time
            
            results += f"\nScan Summary:\n"
            results += f"Duration: {scan_duration:.2f} seconds\n"
            results += f"Active hosts found: {len(self.active_hosts)}\n\n"
            
            if self.active_hosts:
                results += f"Active Hosts:\n"
                results += f"{'-'*80}\n"
                results += f"{'IP Address':<15} {'Open Port':<10} {'MAC Address':<20} {'Hostname':<30}\n"
                results += f"{'-'*80}\n"
                
                for ip, port, hostname, mac in self.active_hosts:
                    results += f"{ip:<15} {str(port):<10} {mac:<20} {hostname:<30}\n"
            else:
                results += "No active hosts found in the specified range.\n"
            
            results += f"\nNote: This scan uses basic connectivity checks.\n"
            if method == "icmp" or icmp_fallback_used:
                results += (
                    "Hosts may appear via ICMP ping even when no common TCP ports are open.\n"
                )
            results += f"Some hosts may not respond due to firewalls or security policies.\n"
            
        except ValueError as e:
            results = f"Error: Invalid network range format.\n"
            results += f"Please use CIDR notation (e.g., 192.168.1.0/24) or single IP.\n"
            results += f"Error details: {str(e)}"
        except Exception as e:
            results = f"Error during network scan: {str(e)}"
        
        return results