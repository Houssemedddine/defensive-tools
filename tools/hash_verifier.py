#!/usr/bin/env python3
"""
Hash Verifier Module
Generates and verifies file hashes for integrity checking
"""

import hashlib
import os
import time

class HashVerifier:
    def __init__(self):
        self.chunk_size = 64 * 1024  # 64KB chunks for memory efficiency
    
    def calculate_hash(self, file_path, hash_type):
        """Calculate hash of a file"""
        hash_algorithms = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
            'sha512': hashlib.sha512()
        }
        
        if hash_type.lower() not in hash_algorithms:
            raise ValueError(f"Unsupported hash type: {hash_type}")
        
        hash_obj = hash_algorithms[hash_type.lower()]
        
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
    
    def get_file_info(self, file_path):
        """Get detailed file information"""
        try:
            stat = os.stat(file_path)
            return {
                'size': stat.st_size,
                'size_mb': stat.st_size / (1024 * 1024),
                'modified': time.ctime(stat.st_mtime),
                'created': time.ctime(stat.st_ctime),
                'permissions': oct(stat.st_mode)[-3:]
            }
        except Exception as e:
            return {'error': str(e)}
    
    def format_file_size(self, size_bytes):
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"
    
    def verify(self, file_path, hash_type, expected_hash=None):
        """Verify file integrity using hash"""
        if not os.path.exists(file_path):
            return f"❌ Error: File '{file_path}' not found."
        
        if not os.path.isfile(file_path):
            return f"❌ Error: '{file_path}' is not a regular file."
        
        try:
            start_time = time.time()
            
            results = f"🔐 File Hash Verification Results\n"
            results += f"{'='*50}\n\n"
            
            # File information
            file_info = self.get_file_info(file_path)
            if 'error' in file_info:
                return f"❌ Error getting file info: {file_info['error']}"
            
            results += f"📁 File Information:\n"
            results += f"Path: {file_path}\n"
            results += f"Size: {self.format_file_size(file_info['size'])} ({file_info['size']:,} bytes)\n"
            results += f"Modified: {file_info['modified']}\n"
            results += f"Permissions: {file_info['permissions']}\n\n"
            
            # Calculate hash
            results += f"🔢 Hash Calculation:\n"
            results += f"Algorithm: {hash_type.upper()}\n"
            results += f"Calculating hash...\n\n"
            
            calculated_hash = self.calculate_hash(file_path, hash_type)
            calculation_time = time.time() - start_time
            
            results += f"✅ Hash calculated successfully!\n"
            results += f"Calculation time: {calculation_time:.2f} seconds\n"
            if calculation_time > 0:
                results += f"Processing rate: {file_info['size_mb']/calculation_time:.2f} MB/s\n\n"
            else:
                results += f"Processing rate: Very fast (< 0.01s)\n\n"
            
            results += f"📋 Hash Results:\n"
            results += f"{hash_type.upper()} Hash: {calculated_hash}\n\n"
            
            # Verification if expected hash provided
            if expected_hash:
                expected_hash = expected_hash.strip().lower()
                calculated_hash_lower = calculated_hash.lower()
                
                results += f"🔍 Hash Verification:\n"
                results += f"Expected:   {expected_hash}\n"
                results += f"Calculated: {calculated_hash_lower}\n\n"
                
                if expected_hash == calculated_hash_lower:
                    results += f"✅ VERIFICATION PASSED\n"
                    results += f"File integrity confirmed - hashes match!\n\n"
                    
                    results += f"🛡️ Security Status:\n"
                    results += f"• File has NOT been modified\n"
                    results += f"• File integrity is INTACT\n"
                    results += f"• Safe to use this file\n"
                else:
                    results += f"❌ VERIFICATION FAILED\n"
                    results += f"File integrity compromised - hashes do NOT match!\n\n"
                    
                    results += f"🚨 Security Alert:\n"
                    results += f"• File may have been MODIFIED\n"
                    results += f"• Possible file CORRUPTION\n"
                    results += f"• Potential security THREAT\n"
                    results += f"• DO NOT use this file until verified\n\n"
                    
                    results += f"🔧 Recommended Actions:\n"
                    results += f"• Re-download the original file\n"
                    results += f"• Scan for malware\n"
                    results += f"• Verify the source\n"
                    results += f"• Check file permissions\n"
            else:
                results += f"ℹ️ Hash Generation Complete\n"
                results += f"Use this hash to verify file integrity later.\n\n"
                
                results += f"📝 Hash Usage Examples:\n"
                results += f"• Compare with vendor-provided hash\n"
                results += f"• Store for future verification\n"
                results += f"• Share for integrity validation\n"
                results += f"• Use in security audits\n\n"
            
            # Additional hash types for comprehensive verification
            if hash_type.lower() != 'sha256':
                results += f"🔄 Additional Hash (SHA256):\n"
                try:
                    additional_start = time.time()
                    sha256_hash = self.calculate_hash(file_path, 'sha256')
                    additional_time = time.time() - additional_start
                    results += f"SHA256: {sha256_hash}\n"
                    results += f"Time: {additional_time:.2f}s\n\n"
                except:
                    results += f"Failed to calculate SHA256 hash\n\n"
            
            # Security recommendations
            results += f"🔒 Security Best Practices:\n"
            results += f"• Always verify file hashes from trusted sources\n"
            results += f"• Use multiple hash algorithms for critical files\n"
            results += f"• Store hashes securely and separately\n"
            results += f"• Regularly verify important files\n"
            results += f"• Be suspicious of hash mismatches\n"
            
            # Hash algorithm information
            results += f"\n📚 Hash Algorithm Info ({hash_type.upper()}):\n"
            hash_info = {
                'md5': {
                    'length': '128-bit (32 hex chars)',
                    'security': 'Legacy - Not recommended for security',
                    'use_case': 'Quick integrity checks, legacy systems'
                },
                'sha1': {
                    'length': '160-bit (40 hex chars)',
                    'security': 'Deprecated - Vulnerable to attacks',
                    'use_case': 'Legacy systems, Git (being phased out)'
                },
                'sha256': {
                    'length': '256-bit (64 hex chars)',
                    'security': 'Secure - Current standard',
                    'use_case': 'Security applications, digital signatures'
                },
                'sha512': {
                    'length': '512-bit (128 hex chars)',
                    'security': 'Very secure - Higher security',
                    'use_case': 'High-security applications'
                }
            }
            
            if hash_type.lower() in hash_info:
                info = hash_info[hash_type.lower()]
                results += f"Length: {info['length']}\n"
                results += f"Security: {info['security']}\n"
                results += f"Use case: {info['use_case']}\n"
            
        except PermissionError:
            results = f"❌ Error: Permission denied accessing '{file_path}'"
        except ValueError as e:
            results = f"❌ Error: {str(e)}"
        except Exception as e:
            results = f"❌ Error during hash calculation: {str(e)}"
        
        return results