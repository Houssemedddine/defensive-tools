#!/usr/bin/env python3
"""
Network Scanner Module
Scans network ranges to discover active hosts
"""

import socket
import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

class NetworkScanner:
    def __init__(self, timeout=1, max_threads=100):
        self.timeout = timeout
        self.max_threads = max_threads
        self.active_hosts = []
        self.lock = threading.Lock()
    
    def ping_host(self, ip):
        """Check if a host is reachable using socket connection"""
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
                            host_info = self.get_host_info(str(ip))
                            self.active_hosts.append((str(ip), port, host_info))
                        return True
                except:
                    continue
            
            # If no common ports are open, try ping-like approach
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((str(ip), 80))
                sock.close()
                
                if result != 0:  # Even if connection fails, host might be up
                    # Try to resolve hostname
                    try:
                        hostname = socket.gethostbyaddr(str(ip))
                        with self.lock:
                            self.active_hosts.append((str(ip), "N/A", hostname[0]))
                        return True
                    except:
                        pass
            except:
                pass
                
        except Exception:
            pass
        return False
    
    def get_host_info(self, ip):
        """Get additional information about the host"""
        try:
            hostname = socket.gethostbyaddr(ip)
            return hostname[0]
        except socket.herror:
            return "Unknown"
        except Exception:
            return "Error"
    
    def scan(self, network_range):
        """Scan a network range for active hosts"""
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
            results += f"Scanning {len(hosts)} hosts...\n\n"
            
            # Use ThreadPoolExecutor for concurrent scanning
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_ip = {executor.submit(self.ping_host, ip): ip for ip in hosts}
                
                completed = 0
                for future in as_completed(future_to_ip):
                    completed += 1
                    if completed % 50 == 0:  # Progress update every 50 hosts
                        results += f"Scanned {completed}/{len(hosts)} hosts...\n"
            
            # Sort results by IP
            self.active_hosts.sort(key=lambda x: ipaddress.ip_address(x[0]))
            
            end_time = time.time()
            scan_duration = end_time - start_time
            
            results += f"\nScan Summary:\n"
            results += f"Duration: {scan_duration:.2f} seconds\n"
            results += f"Active hosts found: {len(self.active_hosts)}\n\n"
            
            if self.active_hosts:
                results += f"Active Hosts:\n"
                results += f"{'-'*60}\n"
                results += f"{'IP Address':<15} {'Open Port':<10} {'Hostname':<30}\n"
                results += f"{'-'*60}\n"
                
                for ip, port, hostname in self.active_hosts:
                    results += f"{ip:<15} {str(port):<10} {hostname:<30}\n"
            else:
                results += "No active hosts found in the specified range.\n"
            
            results += f"\nNote: This scan uses basic connectivity checks.\n"
            results += f"Some hosts may not respond due to firewalls or security policies.\n"
            
        except ValueError as e:
            results = f"Error: Invalid network range format.\n"
            results += f"Please use CIDR notation (e.g., 192.168.1.0/24) or single IP.\n"
            results += f"Error details: {str(e)}"
        except Exception as e:
            results = f"Error during network scan: {str(e)}"
        
        return results