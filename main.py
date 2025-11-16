#!/usr/bin/env python3
"""
Defensive Cybersecurity Multi-Tool
A comprehensive GUI-based security toolkit for defensive operations
Author: Security Team
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
from tools.network_scanner import NetworkScanner
from tools.port_scanner import PortScanner
from tools.log_analyzer import LogAnalyzer
from tools.hash_verifier import HashVerifier

class CyberSecurityTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Defensive Cybersecurity Multi-Tool")
        self.root.geometry("800x600")
        self.root.configure(bg='#2b2b2b')
        
        # Initialize tool modules
        self.network_scanner = NetworkScanner()
        self.port_scanner = PortScanner()
        self.log_analyzer = LogAnalyzer()
        self.hash_verifier = HashVerifier()
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the main user interface"""
        # Main title
        title_frame = tk.Frame(self.root, bg='#2b2b2b')
        title_frame.pack(pady=10)
        
        title_label = tk.Label(
            title_frame, 
            text="🛡️ Defensive Cybersecurity Multi-Tool", 
            font=("Arial", 18, "bold"),
            fg='#00ff00',
            bg='#2b2b2b'
        )
        title_label.pack()
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill='both', padx=10, pady=5)
        
        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook.Tab', padding=[20, 10])
        
        # Create tabs for each tool
        self.create_network_scanner_tab()
        self.create_port_scanner_tab()
        self.create_log_analyzer_tab()
        self.create_hash_verifier_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = tk.Label(
            self.root, 
            textvariable=self.status_var, 
            relief=tk.SUNKEN, 
            anchor=tk.W,
            bg='#3b3b3b',
            fg='white'
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def create_network_scanner_tab(self):
        """Create the network scanner tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="🌐 Network Scanner")
        
        # Input frame
        input_frame = ttk.LabelFrame(frame, text="Network Range", padding=10)
        input_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(input_frame, text="Network (e.g., 192.168.1.0/24):").pack(anchor='w')
        self.network_entry = ttk.Entry(input_frame, width=30)
        self.network_entry.pack(fill='x', pady=2)
        self.network_entry.insert(0, "192.168.1.0/24")
        
        scan_btn = ttk.Button(
            input_frame, 
            text="Scan Network", 
            command=self.run_network_scan
        )
        scan_btn.pack(pady=5)
        
        # Results frame
        results_frame = ttk.LabelFrame(frame, text="Scan Results", padding=10)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.network_results = scrolledtext.ScrolledText(
            results_frame, 
            height=15, 
            wrap=tk.WORD
        )
        self.network_results.pack(fill='both', expand=True)
    
    def create_port_scanner_tab(self):
        """Create the port scanner tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="🔍 Port Scanner")
        
        # Input frame
        input_frame = ttk.LabelFrame(frame, text="Target Configuration", padding=10)
        input_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(input_frame, text="Target IP:").pack(anchor='w')
        self.target_entry = ttk.Entry(input_frame, width=30)
        self.target_entry.pack(fill='x', pady=2)
        self.target_entry.insert(0, "127.0.0.1")
        
        ttk.Label(input_frame, text="Port Range (e.g., 1-1000):").pack(anchor='w', pady=(5,0))
        self.port_range_entry = ttk.Entry(input_frame, width=30)
        self.port_range_entry.pack(fill='x', pady=2)
        self.port_range_entry.insert(0, "1-1000")
        
        scan_btn = ttk.Button(
            input_frame, 
            text="Scan Ports", 
            command=self.run_port_scan
        )
        scan_btn.pack(pady=5)
        
        # Results frame
        results_frame = ttk.LabelFrame(frame, text="Open Ports", padding=10)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.port_results = scrolledtext.ScrolledText(
            results_frame, 
            height=15, 
            wrap=tk.WORD
        )
        self.port_results.pack(fill='both', expand=True)
    
    def create_log_analyzer_tab(self):
        """Create the log analyzer tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="📊 Log Analyzer")
        
        # Input frame
        input_frame = ttk.LabelFrame(frame, text="Log Analysis", padding=10)
        input_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(input_frame, text="Log File Path:").pack(anchor='w')
        
        path_frame = ttk.Frame(input_frame)
        path_frame.pack(fill='x', pady=2)
        
        self.log_path_entry = ttk.Entry(path_frame, width=50)
        self.log_path_entry.pack(side='left', fill='x', expand=True)
        
        browse_btn = ttk.Button(
            path_frame, 
            text="Browse", 
            command=self.browse_log_file
        )
        browse_btn.pack(side='right', padx=(5,0))
        
        analyze_btn = ttk.Button(
            input_frame, 
            text="Analyze Logs", 
            command=self.run_log_analysis
        )
        analyze_btn.pack(pady=5)
        
        # Results frame
        results_frame = ttk.LabelFrame(frame, text="Analysis Results", padding=10)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.log_results = scrolledtext.ScrolledText(
            results_frame, 
            height=15, 
            wrap=tk.WORD
        )
        self.log_results.pack(fill='both', expand=True)
    
    def create_hash_verifier_tab(self):
        """Create the hash verifier tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="🔐 Hash Verifier")
        
        # Input frame
        input_frame = ttk.LabelFrame(frame, text="File Integrity Check", padding=10)
        input_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(input_frame, text="File Path:").pack(anchor='w')
        
        file_frame = ttk.Frame(input_frame)
        file_frame.pack(fill='x', pady=2)
        
        self.file_path_entry = ttk.Entry(file_frame, width=50)
        self.file_path_entry.pack(side='left', fill='x', expand=True)
        
        browse_file_btn = ttk.Button(
            file_frame, 
            text="Browse", 
            command=self.browse_hash_file
        )
        browse_file_btn.pack(side='right', padx=(5,0))
        
        ttk.Label(input_frame, text="Expected Hash (optional):").pack(anchor='w', pady=(5,0))
        self.expected_hash_entry = ttk.Entry(input_frame, width=70)
        self.expected_hash_entry.pack(fill='x', pady=2)
        
        hash_frame = ttk.Frame(input_frame)
        hash_frame.pack(pady=5)
        
        ttk.Button(
            hash_frame, 
            text="Generate MD5", 
            command=lambda: self.run_hash_verification('md5')
        ).pack(side='left', padx=2)
        
        ttk.Button(
            hash_frame, 
            text="Generate SHA1", 
            command=lambda: self.run_hash_verification('sha1')
        ).pack(side='left', padx=2)
        
        ttk.Button(
            hash_frame, 
            text="Generate SHA256", 
            command=lambda: self.run_hash_verification('sha256')
        ).pack(side='left', padx=2)
        
        # Results frame
        results_frame = ttk.LabelFrame(frame, text="Hash Results", padding=10)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.hash_results = scrolledtext.ScrolledText(
            results_frame, 
            height=15, 
            wrap=tk.WORD
        )
        self.hash_results.pack(fill='both', expand=True)
    
    def browse_log_file(self):
        """Browse for log file"""
        from tkinter import filedialog
        filename = filedialog.askopenfilename(
            title="Select Log File",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            self.log_path_entry.delete(0, tk.END)
            self.log_path_entry.insert(0, filename)
    
    def browse_hash_file(self):
        """Browse for file to hash"""
        from tkinter import filedialog
        filename = filedialog.askopenfilename(
            title="Select File to Verify",
            filetypes=[("All files", "*.*")]
        )
        if filename:
            self.file_path_entry.delete(0, tk.END)
            self.file_path_entry.insert(0, filename)
    
    def update_status(self, message):
        """Update status bar"""
        self.status_var.set(message)
        self.root.update_idletasks()
    
    def run_network_scan(self):
        """Run network scan in background thread"""
        network = self.network_entry.get().strip()
        if not network:
            messagebox.showerror("Error", "Please enter a network range")
            return
        
        self.network_results.delete(1.0, tk.END)
        self.update_status("Scanning network...")
        
        def scan_thread():
            try:
                results = self.network_scanner.scan(network)
                self.root.after(0, lambda: self.display_network_results(results))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
            finally:
                self.root.after(0, lambda: self.update_status("Ready"))
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def run_port_scan(self):
        """Run port scan in background thread"""
        target = self.target_entry.get().strip()
        port_range = self.port_range_entry.get().strip()
        
        if not target or not port_range:
            messagebox.showerror("Error", "Please enter target IP and port range")
            return
        
        self.port_results.delete(1.0, tk.END)
        self.update_status("Scanning ports...")
        
        def scan_thread():
            try:
                results = self.port_scanner.scan(target, port_range)
                self.root.after(0, lambda: self.display_port_results(results))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
            finally:
                self.root.after(0, lambda: self.update_status("Ready"))
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def run_log_analysis(self):
        """Run log analysis in background thread"""
        log_path = self.log_path_entry.get().strip()
        if not log_path:
            messagebox.showerror("Error", "Please select a log file")
            return
        
        self.log_results.delete(1.0, tk.END)
        self.update_status("Analyzing logs...")
        
        def analyze_thread():
            try:
                results = self.log_analyzer.analyze(log_path)
                self.root.after(0, lambda: self.display_log_results(results))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
            finally:
                self.root.after(0, lambda: self.update_status("Ready"))
        
        threading.Thread(target=analyze_thread, daemon=True).start()
    
    def run_hash_verification(self, hash_type):
        """Run hash verification"""
        file_path = self.file_path_entry.get().strip()
        if not file_path:
            messagebox.showerror("Error", "Please select a file")
            return
        
        expected_hash = self.expected_hash_entry.get().strip()
        self.hash_results.delete(1.0, tk.END)
        self.update_status(f"Generating {hash_type.upper()} hash...")
        
        def hash_thread():
            try:
                results = self.hash_verifier.verify(file_path, hash_type, expected_hash)
                self.root.after(0, lambda: self.display_hash_results(results))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
            finally:
                self.root.after(0, lambda: self.update_status("Ready"))
        
        threading.Thread(target=hash_thread, daemon=True).start()
    
    def display_network_results(self, results):
        """Display network scan results"""
        self.network_results.insert(tk.END, results)
    
    def display_port_results(self, results):
        """Display port scan results"""
        self.port_results.insert(tk.END, results)
    
    def display_log_results(self, results):
        """Display log analysis results"""
        self.log_results.insert(tk.END, results)
    
    def display_hash_results(self, results):
        """Display hash verification results"""
        self.hash_results.insert(tk.END, results)

def main():
    root = tk.Tk()
    app = CyberSecurityTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()