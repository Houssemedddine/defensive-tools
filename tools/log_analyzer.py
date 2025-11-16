#!/usr/bin/env python3
"""
Log Analyzer Module
Analyzes log files for security threats and anomalies
"""

import re
import os
import time
from datetime import datetime, timedelta
from collections import Counter, defaultdict

class LogAnalyzer:
    def __init__(self):
        # Common attack patterns
        self.attack_patterns = {
            'sql_injection': [
                r"(\bunion\b.*\bselect\b)|(\bselect\b.*\bfrom\b.*\bwhere\b)",
                r"(\'\s*or\s*\'1\'\s*=\s*\'1)|(\'\s*or\s*1\s*=\s*1)",
                r"(\bdrop\s+table\b)|(\bdelete\s+from\b)",
                r"(\binsert\s+into\b)|(\bupdate\s+.*\bset\b)"
            ],
            'xss_attack': [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"vbscript:",
                r"onload\s*=|onclick\s*=|onerror\s*="
            ],
            'directory_traversal': [
                r"\.\./|\.\.\%5c",
                r"\.\.\\",
                r"%2e%2e%2f|%2e%2e%5c"
            ],
            'brute_force': [
                r"failed\s+login|authentication\s+failed",
                r"invalid\s+(user|password|login)",
                r"login\s+failed|logon\s+failure"
            ],
            'malware_indicators': [
                r"\.exe\s+(download|fetch)",
                r"powershell.*-enc|-encoded",
                r"cmd\.exe.*&|;|&&|\|\|"
            ]
        }
        
        # Suspicious IP patterns
        self.suspicious_patterns = {
            'known_malicious': [
                r"10\.0\.0\.",  # Example pattern
                r"192\.168\.1\.1"  # Example pattern
            ],
            'port_scan': [
                r"connect.*refused",
                r"connection.*timeout"
            ]
        }
    
    def parse_log_line(self, line):
        """Parse a log line to extract timestamp, IP, and other components"""
        # Common log formats (Apache, Nginx, IIS, etc.)
        patterns = [
            # Apache Common Log Format
            r'^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]+)" (\d+) (\d+)',
            # Nginx default format
            r'^(\S+) - - \[([^\]]+)\] "([^"]+)" (\d+) (\d+) "([^"]*)" "([^"]*)"',
            # Windows Event Log style
            r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?(\d+\.\d+\.\d+\.\d+)',
            # Generic timestamp and IP
            r'(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}).*?(\d+\.\d+\.\d+\.\d+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                groups = match.groups()
                return {
                    'ip': groups[0] if self.is_valid_ip(groups[0]) else (groups[1] if len(groups) > 1 and self.is_valid_ip(groups[1]) else None),
                    'timestamp': groups[1] if len(groups) > 1 else groups[0],
                    'request': groups[2] if len(groups) > 2 else line,
                    'status': groups[3] if len(groups) > 3 else None,
                    'line': line.strip()
                }
        
        # Fallback - extract IP if present
        ip_match = re.search(r'\b(\d+\.\d+\.\d+\.\d+)\b', line)
        timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2})', line)
        
        return {
            'ip': ip_match.group(1) if ip_match else None,
            'timestamp': timestamp_match.group(1) if timestamp_match else None,
            'request': line.strip(),
            'status': None,
            'line': line.strip()
        }
    
    def is_valid_ip(self, ip_string):
        """Check if string is a valid IP address"""
        try:
            parts = ip_string.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except:
            return False
    
    def detect_attacks(self, log_entry):
        """Detect attack patterns in log entry"""
        attacks = []
        line = log_entry['line'].lower()
        
        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    attacks.append(attack_type)
                    break
        
        return attacks
    
    def analyze_ip_behavior(self, ip_entries):
        """Analyze behavior patterns for IP addresses"""
        ip_analysis = {}
        
        for ip, entries in ip_entries.items():
            if not ip or not self.is_valid_ip(ip):
                continue
                
            request_count = len(entries)
            status_codes = [e.get('status') for e in entries if e.get('status')]
            error_count = sum(1 for code in status_codes if code and int(code) >= 400)
            
            # Check for rapid requests (potential DDoS)
            if len(entries) > 1:
                timestamps = [e.get('timestamp') for e in entries if e.get('timestamp')]
                if len(timestamps) > 1:
                    # Simple time analysis
                    rapid_requests = request_count > 100  # Threshold
                else:
                    rapid_requests = False
            else:
                rapid_requests = False
            
            # Check for attack patterns
            attack_types = set()
            for entry in entries:
                attacks = self.detect_attacks(entry)
                attack_types.update(attacks)
            
            ip_analysis[ip] = {
                'request_count': request_count,
                'error_count': error_count,
                'error_rate': (error_count / request_count * 100) if request_count > 0 else 0,
                'rapid_requests': rapid_requests,
                'attack_types': list(attack_types),
                'risk_level': self.calculate_risk_level(request_count, error_count, rapid_requests, attack_types)
            }
        
        return ip_analysis
    
    def calculate_risk_level(self, request_count, error_count, rapid_requests, attack_types):
        """Calculate risk level for an IP"""
        score = 0
        
        if request_count > 1000:
            score += 3
        elif request_count > 100:
            score += 1
        
        if error_count > 50:
            score += 2
        elif error_count > 10:
            score += 1
        
        if rapid_requests:
            score += 2
        
        if attack_types:
            score += len(attack_types) * 2
        
        if score >= 6:
            return "HIGH"
        elif score >= 3:
            return "MEDIUM"
        elif score >= 1:
            return "LOW"
        else:
            return "NORMAL"
    
    def analyze(self, log_file_path):
        """Analyze log file for security threats"""
        if not os.path.exists(log_file_path):
            return f"❌ Error: Log file '{log_file_path}' not found."
        
        try:
            start_time = time.time()
            results = f"📊 Log Analysis Results for {os.path.basename(log_file_path)}\n"
            results += f"{'='*60}\n\n"
            
            # Read and parse log file
            log_entries = []
            ip_entries = defaultdict(list)
            attack_summary = Counter()
            status_codes = Counter()
            
            with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                line_count = 0
                for line in f:
                    if line.strip():
                        line_count += 1
                        entry = self.parse_log_line(line)
                        log_entries.append(entry)
                        
                        if entry['ip']:
                            ip_entries[entry['ip']].append(entry)
                        
                        if entry['status']:
                            status_codes[entry['status']] += 1
                        
                        # Detect attacks in this entry
                        attacks = self.detect_attacks(entry)
                        for attack in attacks:
                            attack_summary[attack] += 1
            
            processing_time = time.time() - start_time
            
            results += f"📈 General Statistics:\n"
            results += f"Total log entries: {line_count:,}\n"
            results += f"Unique IP addresses: {len(ip_entries)}\n"
            results += f"Processing time: {processing_time:.2f} seconds\n\n"
            
            # Status code analysis
            if status_codes:
                results += f"🌐 HTTP Status Code Distribution:\n"
                for status, count in status_codes.most_common(10):
                    percentage = (count / line_count * 100) if line_count > 0 else 0
                    results += f"  {status}: {count:,} ({percentage:.1f}%)\n"
                results += "\n"
            
            # Attack summary
            if attack_summary:
                results += f"🚨 Security Threats Detected:\n"
                total_attacks = sum(attack_summary.values())
                for attack_type, count in attack_summary.most_common():
                    percentage = (count / total_attacks * 100) if total_attacks > 0 else 0
                    results += f"  {attack_type.replace('_', ' ').title()}: {count:,} ({percentage:.1f}%)\n"
                results += f"\nTotal attack attempts: {total_attacks:,}\n\n"
            else:
                results += f"✅ No obvious attack patterns detected.\n\n"
            
            # IP analysis
            ip_analysis = self.analyze_ip_behavior(ip_entries)
            high_risk_ips = {ip: data for ip, data in ip_analysis.items() if data['risk_level'] == 'HIGH'}
            medium_risk_ips = {ip: data for ip, data in ip_analysis.items() if data['risk_level'] == 'MEDIUM'}
            
            if high_risk_ips:
                results += f"🔴 HIGH RISK IP Addresses:\n"
                results += f"{'-'*70}\n"
                for ip, data in sorted(high_risk_ips.items(), key=lambda x: x[1]['request_count'], reverse=True)[:10]:
                    results += f"IP: {ip}\n"
                    results += f"  Requests: {data['request_count']:,} | Errors: {data['error_count']:,} ({data['error_rate']:.1f}%)\n"
                    if data['attack_types']:
                        results += f"  Attack types: {', '.join(data['attack_types'])}\n"
                    results += f"  {'Rapid requests detected' if data['rapid_requests'] else 'Normal request rate'}\n\n"
            
            if medium_risk_ips:
                results += f"🟡 MEDIUM RISK IP Addresses:\n"
                results += f"{'-'*70}\n"
                for ip, data in sorted(medium_risk_ips.items(), key=lambda x: x[1]['request_count'], reverse=True)[:5]:
                    results += f"IP: {ip} - {data['request_count']:,} requests, {data['error_count']:,} errors\n"
                results += "\n"
            
            # Top requesters
            top_ips = sorted(ip_entries.items(), key=lambda x: len(x[1]), reverse=True)[:10]
            if top_ips:
                results += f"📊 Top IP Addresses by Request Count:\n"
                results += f"{'-'*50}\n"
                for ip, entries in top_ips:
                    if ip and self.is_valid_ip(ip):
                        risk_level = ip_analysis.get(ip, {}).get('risk_level', 'UNKNOWN')
                        results += f"{ip:<15} {len(entries):>8,} requests [{risk_level}]\n"
                results += "\n"
            
            # Recommendations
            results += f"💡 Security Recommendations:\n"
            if high_risk_ips:
                results += f"• Consider blocking HIGH RISK IP addresses\n"
                results += f"• Implement rate limiting to prevent abuse\n"
            if attack_summary:
                results += f"• Review and strengthen input validation\n"
                results += f"• Consider implementing a Web Application Firewall (WAF)\n"
            if any(data['rapid_requests'] for data in ip_analysis.values()):
                results += f"• Implement DDoS protection measures\n"
            
            results += f"• Regular log monitoring and analysis\n"
            results += f"• Set up automated alerts for suspicious activities\n"
            
        except Exception as e:
            results = f"❌ Error analyzing log file: {str(e)}"
        
        return results