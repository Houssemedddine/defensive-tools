# 🛡️ Defensive Cybersecurity Multi-Tool

A comprehensive GUI-based cybersecurity toolkit designed for defensive security operations. This tool provides four essential security utilities in a single, easy-to-use interface.

## 🌟 Features

### 🌐 Network Scanner
- **Network Discovery**: Scan IP ranges to identify active hosts
- **Service Detection**: Identify running services and open ports
- **Hostname Resolution**: Resolve hostnames for discovered devices
- **CIDR Support**: Supports CIDR notation (e.g., 192.168.1.0/24)

### 🔍 Port Scanner
- **Comprehensive Scanning**: Scan individual ports or port ranges
- **Service Identification**: Identify common services running on open ports
- **Banner Grabbing**: Capture service banners for additional information
- **Security Analysis**: Highlight potentially risky open ports
- **Multiple Formats**: Support for single ports, ranges (1-1000), or comma-separated lists

### 📊 Log Analyzer
- **Security Threat Detection**: Identify SQL injection, XSS, directory traversal attacks
- **Brute Force Detection**: Detect failed login attempts and authentication failures
- **IP Risk Analysis**: Analyze IP behavior patterns and assign risk levels
- **Traffic Analysis**: HTTP status code distribution and request patterns
- **Automated Recommendations**: Provide security recommendations based on findings

### 🔐 Hash Verifier
- **Multiple Algorithms**: Support for MD5, SHA1, SHA256, and SHA512
- **File Integrity**: Verify file integrity by comparing calculated vs expected hashes
- **Performance Metrics**: Display calculation speed and processing time
- **Security Warnings**: Alert on hash mismatches indicating potential corruption
- **File Information**: Display detailed file metadata and permissions

## 🚀 Installation

### Prerequisites
- Python 3.6 or higher
- tkinter (usually included with Python)

### Setup
1. Clone or download the project files
2. Ensure all files are in the same directory structure:
   ```
   cybersecurity-tool/
   ├── main.py
   ├── tools/
   │   ├── __init__.py
   │   ├── network_scanner.py
   │   ├── port_scanner.py
   │   ├── log_analyzer.py
   │   └── hash_verifier.py
   ├── requirements.txt
   └── README.md
   ```

### Running the Tool
```bash
python main.py
```

## 🎯 Usage Guide

### Network Scanner
1. Enter network range in CIDR notation (e.g., `192.168.1.0/24`)
2. Click "Scan Network"
3. View results showing active hosts, open ports, and hostnames

### Port Scanner
1. Enter target IP address
2. Specify port range (e.g., `1-1000`, `80,443,8080`, or single port `80`)
3. Click "Scan Ports"
4. Review open ports, services, and security analysis

### Log Analyzer
1. Click "Browse" to select a log file
2. Click "Analyze Logs"
3. Review security threats, IP risk analysis, and recommendations

### Hash Verifier
1. Click "Browse" to select a file
2. Optionally enter expected hash for verification
3. Choose hash algorithm (MD5, SHA1, SHA256, SHA512)
4. Review hash results and integrity status

## 🔒 Security Features

### Attack Detection
- **SQL Injection**: Detects common SQL injection patterns
- **Cross-Site Scripting (XSS)**: Identifies XSS attack attempts
- **Directory Traversal**: Finds path traversal attack attempts
- **Brute Force**: Detects authentication brute force attempts
- **Malware Indicators**: Identifies suspicious executable downloads and commands

### Risk Assessment
- **Automated Risk Scoring**: IP addresses are automatically assigned risk levels
- **Behavioral Analysis**: Analyzes request patterns and error rates
- **Security Recommendations**: Provides actionable security advice

### File Integrity
- **Multi-Algorithm Support**: Multiple hash algorithms for comprehensive verification
- **Performance Monitoring**: Tracks calculation speed and efficiency
- **Security Alerts**: Clear warnings for integrity violations

## 🛠️ Technical Details

### Architecture
- **Modular Design**: Each tool is implemented as a separate module
- **Threaded Operations**: Network operations run in background threads
- **Memory Efficient**: File processing uses chunked reading for large files
- **Cross-Platform**: Compatible with Windows, macOS, and Linux

### Performance
- **Concurrent Scanning**: Network and port scans use thread pools for speed
- **Optimized Parsing**: Log analysis uses efficient regex patterns
- **Chunked Processing**: Hash calculations process files in memory-efficient chunks

## ⚠️ Important Notes

### Network Scanning
- Only scan networks you own or have permission to test
- Some hosts may not respond due to firewalls or security policies
- Results may vary based on network configuration

### Port Scanning
- Only scan hosts you own or have explicit permission to test
- Unauthorized port scanning may violate terms of service or laws
- Use responsibly for defensive security purposes only

### Log Analysis
- Works with common log formats (Apache, Nginx, IIS)
- Large log files may take time to process
- Results depend on log format and content quality

### Hash Verification
- Always verify hashes from trusted sources
- Hash mismatches may indicate file corruption or tampering
- Use appropriate hash algorithms for your security requirements

## 🆘 Troubleshooting

### Common Issues
1. **Permission Errors**: Run with appropriate permissions for network operations
2. **File Access**: Ensure read permissions for log files and hash verification files
3. **Network Timeouts**: Adjust timeout settings for slow networks
4. **Large Files**: Be patient with large log files or files for hash verification

### Performance Tips
- Use smaller port ranges for faster scanning
- Process log files in smaller chunks if memory is limited
- Close other network applications during intensive scanning

## 🤝 Contributing

This tool is designed for educational and defensive security purposes. Contributions welcome for:
- Additional attack pattern detection
- New log format support
- Performance improvements
- Security enhancements

## 📄 License

This tool is provided for educational and defensive cybersecurity purposes. Use responsibly and in accordance with applicable laws and regulations.

## 🔍 Disclaimer

This tool is intended for legitimate cybersecurity defense activities only. Users are responsible for ensuring compliance with applicable laws and regulations. The authors are not responsible for any misuse of this software.