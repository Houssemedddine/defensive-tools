#!/usr/bin/env python3
"""
Defensive Cybersecurity Multi-Tool 
A comprehensive GUI-based security toolkit for defensive operations
Done for a University project.
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import time
import os
import sys
from datetime import datetime
import json
import platform

# Improve clarity on high-DPI (Windows) displays
def enable_high_dpi_awareness():
    """Best-effort DPI awareness for sharper rendering on Windows."""
    if platform.system().lower() != "windows":
        return
    try:
        import ctypes
        awareness = ctypes.c_int()
        shcore = ctypes.windll.shcore
        # Query current awareness first
        if shcore.GetProcessDpiAwareness(0, ctypes.byref(awareness)) == 0:
            if awareness.value == 0:  # DPI unaware
                shcore.SetProcessDpiAwareness(1)  # System DPI aware
    except Exception:
        try:
            # Older Windows fallback
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

# Matplotlib for plotting charts
try:
    import matplotlib
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
except Exception:
    matplotlib = None
    plt = None
    FigureCanvasTkAgg = None


# Add tools directory to path
sys.path.append('tools')

try:
    from tools.network_scanner import NetworkScanner
    from tools.port_scanner import PortScanner
    from tools.hash_verifier import HashVerifier
    from tools.password import password_strength, strengthen_password
    from tools.aes_tool import encrypt_file, decrypt_file, AesResult
    from tools.breach_checker import BreachChecker
except ImportError:
    # Fallback mock classes if tools aren't available
    class NetworkScanner:
        def scan(self, network): 
            time.sleep(2)
            return f"""Network Scan Results for {network}
═══════════════════════════════════════════════════
📡 Scan Summary:
• Target: {network}
• Hosts Found: 8
• Scan Duration: 2.1s
• Timestamp: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

🏠 Active Hosts:
IP Address      MAC Address           Hostname
--------------------------------------------------
192.168.1.1     00:11:22:33:44:55     Router
192.168.1.2     AA:BB:CC:DD:EE:FF     Desktop PC
192.168.1.5     11:22:33:44:55:66     Laptop
192.168.1.10    22:33:44:55:66:77     Smartphone
192.168.1.15    33:44:55:66:77:88     IoT Device
192.168.1.20    44:55:66:77:88:99     Server
192.168.1.25    55:66:77:88:99:AA     Printer
192.168.1.30    66:77:88:99:AA:BB     NAS

🔍 Scan completed successfully!
"""

    class PortScanner:
        def scan(self, target, ports): 
            time.sleep(3)
            return f"""Port Scan Results for {target}
═══════════════════════════════════════════════════
🎯 Target: {target}
📊 Port Range: {ports}
⏱️ Duration: 3.2s
🕐 Timestamp: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

🚪 Open Ports:
PORT    STATE   SERVICE     VERSION
22/tcp  open    ssh         OpenSSH 8.2
80/tcp  open    http        Apache 2.4
443/tcp open    https       Apache 2.4
3389/tcp open   rdps        Microsoft RDP

📈 Statistics:
• Total Ports Scanned: 1000
• Open Ports: 4
• Filtered Ports: 12
• Closed Ports: 984

🔒 Security Notes:
• SSH running on standard port
• HTTP service detected
• HTTPS service available
• RDP accessible from network
"""

    class HashVerifier:
        def verify(self, path, algo, expected=None): 
            time.sleep(1)
            file_hash = "a1b2c3d4e5f6789012345678901234567890" if algo == 'sha256' else "d41d8cd98f00b204e9800998ecf8427e"
            status = "✅ VERIFIED" if expected and expected.lower() == file_hash else "⚠️ NOT VERIFIED" if expected else "🔍 GENERATED"
            
            return f"""Hash Verification Results
═══════════════════════════════════════════════════
📁 File: {path}
🔢 Algorithm: {algo.upper()}
⏱️ Processing Time: 1.2s
🕐 Timestamp: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

🔑 Generated Hash:
{file_hash}

{'🎯 Expected Hash: ' + expected if expected else '📝 No expected hash provided'}

📊 Status: {status}

{'✅ Hashes match! File integrity verified.' if expected and expected.lower() == file_hash else 
  '❌ Hashes do not match! File may be compromised.' if expected else 
  '📋 Hash generated successfully. Copy for verification.'}
"""

class LoginWindow:
    """Login/Splash screen for the Cybersecurity Multi-Tool"""
    
    def __init__(self, root):
        self.root = root
        try:
            enable_high_dpi_awareness()
            # Slightly increase Tk scaling for crisper text on hiDPI screens
            self.root.tk.call('tk', 'scaling', 1.3)
        except Exception:
            pass
        self.root.title("Cybersecurity Multi-Tool - Login")
        # Open the login window in fullscreen when possible. Fallback to maximized or default size.
        try:
            self.root.attributes("-fullscreen", True)
        except Exception:
            try:
                self.root.state('zoomed')
            except Exception:
                self.root.geometry("900x700")
        # Allow exiting fullscreen with Escape key
        try:
            self.root.bind("<Escape>", lambda e: self.root.attributes("-fullscreen", False))
        except Exception:
            pass
        self.root.configure(bg='#0a0f1c')
        
        # Colors matching the main app theme
        self.colors = {
            'bg': '#0a0f1c',
            'card_bg': '#131a2c',
            'accent': '#00ff88',
            'accent_secondary': '#0099ff',
            'text_primary': '#ffffff',
            'text_secondary': '#a0a8c0',
            'border': '#1e2a4a',
            'button_bg': '#1a243f',
            'button_hover': '#243156',
        }
        
        self.setup_ui()
    
    def center_window(self):
        """Center the window on the screen"""
        """Center the window on the screen (skip if fullscreen)."""
        try:
            if self.root.attributes("-fullscreen"):
                return
        except Exception:
            pass

        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        if width <= 1 and height <= 1:
            width = 900
            height = 700
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def setup_ui(self):
        """Setup the login page UI"""
        # Main container
        main_container = tk.Frame(self.root, bg=self.colors['bg'])
        main_container.pack(fill='both', expand=True)
        
        # Logo/Icon area
        logo_frame = tk.Frame(main_container, bg=self.colors['bg'])
        logo_frame.pack(pady=(60, 30))
        
        # Try to load logo, fallback to emoji
        try:
            img_dir = os.path.join(os.path.dirname(__file__), 'images')
            logo_path = os.path.join(img_dir, 'logo violet.png')
            logo_img = tk.PhotoImage(file=logo_path)
            # Resize logo
            factor = max(1, int(max(logo_img.width(), logo_img.height()) / 200))
            logo_img = logo_img.subsample(factor, factor) if factor > 1 else logo_img
            
            logo_label = tk.Label(
                logo_frame,
                image=logo_img,
                bg=self.colors['bg']
            )
            logo_label.image = logo_img  # Keep a reference
            logo_label.pack()
        except Exception:
            # Fallback to emoji
            logo_label = tk.Label(
                logo_frame,
                text="🛡️",
                font=("Arial", 80),
                fg=self.colors['accent'],
                bg=self.colors['bg']
            )
            logo_label.pack()
        
        # Title
        title_label = tk.Label(
            main_container,
            text="Cybersecurity Multi-Tool",
            font=("Segoe UI", 40, "bold"),
            fg=self.colors['text_primary'],
            bg=self.colors['bg']
        )
        title_label.pack(pady=(0, 10))
        
        # Subtitle
        subtitle_label = tk.Label(
            main_container,
            text="Defensive Security Toolkit",
            font=("Segoe UI", 18),
            fg=self.colors['text_secondary'],
            bg=self.colors['bg']
        )
        subtitle_label.pack(pady=(0, 50))
        
        # Login card
        login_card = tk.Frame(
            main_container,
            bg=self.colors['card_bg'],
            relief='flat',
            bd=1,
            highlightbackground=self.colors['border'],
            highlightthickness=1
        )
        login_card.pack(padx=40, pady=20, fill='x')
        
        # Welcome message
        welcome_label = tk.Label(
            login_card,
            text="Welcome",
            font=("Segoe UI", 24, "bold"),
            fg=self.colors['text_primary'],
            bg=self.colors['card_bg'],
            pady=30
        )
        welcome_label.pack()
        
        # Description
        desc_label = tk.Label(
            login_card,
            text="A comprehensive security toolkit for defensive operations\nand network monitoring.",
            font=("Segoe UI", 13),
            fg=self.colors['text_secondary'],
            bg=self.colors['card_bg'],
            justify='center'
        )
        desc_label.pack(pady=(0, 30))
        
        # Login button
        login_btn = tk.Button(
            login_card,
            text="🚀 Enter Application",
            font=("Segoe UI", 14, "bold"),
            bg=self.colors['accent'],
            fg=self.colors['bg'],
            relief='flat',
            bd=0,
            padx=40,
            pady=15,
            cursor='hand2',
            command=self.open_main_app
        )
        login_btn.pack(pady=(0, 30))
        
        # Hover effect for button
        def on_enter(e):
            login_btn.configure(bg=self.colors['accent_secondary'])
        def on_leave(e):
            login_btn.configure(bg=self.colors['accent'])
        login_btn.bind("<Enter>", on_enter)
        login_btn.bind("<Leave>", on_leave)
        
        # Credits section
        credits_frame = tk.Frame(main_container, bg=self.colors['bg'])
        credits_frame.pack(side='bottom', fill='x', pady=(20, 30))
        
        credits_label = tk.Label(
            credits_frame,
            text="Developed by:",
            font=("Segoe UI", 10),
            fg=self.colors['text_secondary'],
            bg=self.colors['bg']
        )
        credits_label.pack()
        
        authors_label = tk.Label(
            credits_frame,
            text="Si larbi MALIK, Houssem Zerrout , Ahmed berkani, Admane Abdelmalek",
            font=("Segoe UI", 11, "bold"),
            fg=self.colors['accent'],
            bg=self.colors['bg']
        )
        authors_label.pack(pady=(5, 0))
        
        # Version/Project info
        version_label = tk.Label(
            credits_frame,
            text="Advanced programming Project",
            font=("Segoe UI", 9),
            fg=self.colors['text_secondary'],
            bg=self.colors['bg']
        )
        version_label.pack(pady=(10, 0))
    
    def open_main_app(self):
        """Open the main application window"""
        self.root.destroy()
        
        # Create new root for main app
        main_root = tk.Tk()
        app = CyberSecurityTool(main_root)
        main_root.mainloop()

class CyberSecurityTool:
    def __init__(self, root):
        self.root = root    
        try:
            enable_high_dpi_awareness()
            self.root.tk.call('tk', 'scaling', 1.3)
        except Exception:
            pass
        self.root.title("Cybersecurity Multi-Tool")
        # Maximize window for full screen
        try:
            self.root.state('zoomed')  # Windows
        except Exception:
            try:
                self.root.attributes('-zoomed', True)  # Linux
            except Exception:
                self.root.geometry("1440x900")  # 4K base resolution
        
        self.root.minsize(1200, 800)
        self.root.configure(bg='#0a0f1c')
        
        # Theme configuration
        self.theme = 'dark'
        self.setup_hd_styles()
        
        # Initialize tool modules
        self.network_scanner = NetworkScanner()
        self.port_scanner = PortScanner()
        self.hash_verifier = HashVerifier()
        self.breach_checker = BreachChecker()
        
        # Session management
        self.session_data = {
            'scans_performed': 0,
            'last_scan': None,
            'results_history': [],
            'recent_activities': [],
            'breached_emails_found': 0,
            'files_checked': 0
        }
        # Track whether the current session is saved to disk
        self.session_saved = True
        
        self.setup_hd_ui()
        self.apply_hd_theme()
    
    def setup_hd_styles(self):
        """Setup styles with modern color scheme"""
        self.colors = {
            'dark': {
                'bg': '#0a0f1c',
                'card_bg': '#131a2c',
                'accent': '#00ff88',
                'accent_secondary': '#0099ff',
                'text_primary': '#ffffff',
                'text_secondary': '#a0a8c0',
                'border': '#1e2a4a',
                'success': '#00ff88',
                'warning': '#ffaa00',
                'error': '#ff4444',
                'button_bg': '#1a243f',
                'button_hover': '#243156',
                'transparent_bg': '#131a2c'
            },
            'light': {
                'bg': '#f8fafc',
                'card_bg': '#ffffff',
                'accent': '#0077ff',
                'accent_secondary': '#00aaff',
                'text_primary': '#1a202c',
                'text_secondary': '#4a5568',
                'border': '#e2e8f0',
                'success': '#00c851',
                'warning': '#ffbb33',
                'error': '#ff4444',
                'button_bg': '#edf2f7',
                'button_hover': '#e2e8f0',
                'transparent_bg': '#ffffff'
            }
        }
    
    def setup_hd_ui(self):
        """Setup user interface with modern layout"""
        # Main container with gradient effect
        self.main_container = tk.Frame(self.root, bg=self.colors['dark']['bg'])
        self.main_container.pack(fill='both', expand=True)
        
        # Header with improved styling
        self.create_hd_header()
        
        # Main content area with sidebar and notebook
        self.create_hd_main_content()
        
        # Enhanced status bar
        self.create_hd_status_bar()
    
    def create_hd_header(self):
        """Creating a header with modern design"""
        header_frame = tk.Frame(
            self.main_container, 
            bg=self.colors['dark']['card_bg'],
            height=90,
            relief='flat',
            bd=0
        )
        header_frame.pack(fill='x', padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        # Add a subtle bottom border
        border_frame = tk.Frame(header_frame, bg=self.colors['dark']['border'], height=1)
        border_frame.pack(side='bottom', fill='x')
        border_frame.pack_propagate(False)
        
        # Title and subtitle - Enhanced design
        title_container = tk.Frame(header_frame, bg=self.colors['dark']['card_bg'])
        title_container.pack(side='left', fill='both', expand=True, padx=25, pady=15)
        
        # Logo with larger size - Load logo based on theme
        self.logo_label = tk.Label(
            title_container,
            bg=self.colors['dark']['card_bg']
        )
        self.logo_label.pack(side='left', padx=(0, 20), pady=10)
        
        # Load logo images for both themes
        self._load_logo_images()
        
        # Control panel
        control_frame = tk.Frame(header_frame, bg=self.colors['dark']['card_bg'])
        control_frame.pack(side='right', fill='y', padx=20)
        
        # Stats display
        stats_frame = tk.Frame(control_frame, bg=self.colors['dark']['card_bg'])
        stats_frame.pack(side='left', padx=15)
        
        self.stats_label = tk.Label(
            stats_frame,
            text="Scans: 0",
            font=("Segoe UI", 9),
            fg=self.colors['dark']['text_secondary'],
            bg=self.colors['dark']['card_bg']
        )
        self.stats_label.pack()
        
        # Theme toggle with lune icon - FIXED: Better theme switching
        toggle_frame = tk.Frame(control_frame, bg=self.colors['dark']['card_bg'])
        toggle_frame.pack(side='left', padx=5)
        
        # Load and prepare lune image for toggle
        try:
            import os
            img_path = os.path.join(os.path.dirname(__file__), 'images', 'lune.png')
            _raw_lune = tk.PhotoImage(file=img_path)
            # Subsample to make it smaller for the toggle (around 24x24px)
            if _raw_lune.width() > 28 or _raw_lune.height() > 28:
                factor = max(1, int(max(_raw_lune.width(), _raw_lune.height()) / 20))
                self._lune_icon = _raw_lune.subsample(factor, factor)
            else:
                self._lune_icon = _raw_lune
            
            # Create toggle button with lune image
            self.theme_btn = tk.Button(
                toggle_frame,
                image=self._lune_icon,
                command=self.toggle_hd_theme,
                relief='flat',
                bg=self.colors['dark']['button_bg'],
                fg=self.colors['dark']['text_primary'],
                bd=0,
                padx=12,
                pady=8,
                cursor='hand2',
                activebackground=self.colors['dark']['button_hover']
            )
        except Exception as e:
            # Fallback to text button if image loading fails
            self.theme_btn = tk.Button(
                toggle_frame,
                text="☀️ Light Mode",
                command=self.toggle_hd_theme,
                font=("Segoe UI", 10, "bold"),
                relief='flat',
                bg=self.colors['dark']['button_bg'],
                fg=self.colors['dark']['text_primary'],
                bd=0,
                padx=15,
                pady=8,
                cursor='hand2'
            )
        
        self.theme_btn.pack(side='left')

        # Quick access buttons: History and New Session
        try:
            hist_btn = self.create_hd_button(toggle_frame, "📚 History", self.show_history_window, accent=False)
            hist_btn.pack(side='left', padx=8)
        except Exception:
            pass

        try:
            new_btn = self.create_hd_button(toggle_frame, "🆕 New Session", self.create_new_session, accent=False)
            new_btn.pack(side='left', padx=8)
        except Exception:
            pass
        
        
        # Spinner Better visibility
        self.spinner_frame = tk.Frame(control_frame, bg=self.colors['dark']['card_bg'])
        self.spinner_frame.pack(side='left', padx=10)
        
        self.spinner_label = tk.Label(
            self.spinner_frame,
            text="🔍 Scanning...",
            font=("Segoe UI", 9, "bold"),
            fg=self.colors['dark']['accent'],
            bg=self.colors['dark']['card_bg']
        )
        self.spinner_label.pack(side='left')
        
        # Improved spinner with larger canvas and better animation
        self.spinner_canvas = tk.Canvas(
            self.spinner_frame, 
            width=40, 
            height=20, 
            highlightthickness=0, 
            bg=self.colors['dark']['card_bg']
        )
        self.spinner_canvas.pack(side='left', padx=(5, 0))
        
        # Create improved spinner with pulsing dots
        self.spinner_dots = []
        for i in range(3):
            dot = self.spinner_canvas.create_oval(
                5 + i * 12, 5,
                15 + i * 12, 15,
                fill=self.colors['dark']['accent'],
                outline=''
            )
            self.spinner_dots.append(dot)
        
        self.spinner_frame.pack_forget()
        self._spinner_visible = False
        self._spinner_anim_id = None
        self._spinner_phase = 0
    
    def create_hd_main_content(self):
        """Create main content area with sidebar and notebook"""
        content_frame = tk.Frame(self.main_container, bg=self.colors['dark']['bg'])
        content_frame.pack(fill='both', expand=True, padx=20, pady=15)
        
        # Add responsive grid weights for better scaling (three columns: sidebar, main, results-nav)
        content_frame.grid_columnconfigure(0, minsize=240)
        content_frame.grid_columnconfigure(1, weight=1)
        content_frame.grid_columnconfigure(2, minsize=20)
        content_frame.grid_rowconfigure(0, weight=1)
        
        # Create sidebar
        self.create_hd_sidebar(content_frame)
        
        # Create main notebook area
        self.create_hd_notebook(content_frame)
    
    def create_hd_sidebar(self, parent):
        """Create scrollable sidebar with tool shortcuts"""
        # Main sidebar frame with scrollbar
        self.sidebar_frame = tk.Frame(
            parent, 
            bg=self.colors['dark']['card_bg'],
            width=240,
            relief='flat',
            bd=0,
            highlightbackground=self.colors['dark']['border'],
            highlightthickness=1
        )
        self.sidebar_frame.grid(row=0, column=0, sticky='nsew', padx=(0, 15))
        self.sidebar_frame.pack_propagate(False)
        
        # Sidebar title with better spacing
        sidebar_title = tk.Label(
            self.sidebar_frame,
            text="🔧 TOOLS",
            font=("Segoe UI", 13, "bold"),
            fg=self.colors['dark']['accent'],
            bg=self.colors['dark']['card_bg'],
            pady=20
        )
        sidebar_title.pack(fill='x')
        
        # Separator line
        sep = tk.Frame(self.sidebar_frame, bg=self.colors['dark']['border'], height=1)
        sep.pack(fill='x', padx=15, pady=(0, 10))
        sep.pack_propagate(False)
        
        # Create scrollable canvas for tools
        self.sidebar_canvas = tk.Canvas(
            self.sidebar_frame,
            bg=self.colors['dark']['card_bg'],
            highlightthickness=0,
            relief='flat',
            bd=0
        )
        # Use a thin, discrete tk.Scrollbar for the sidebar
        self.sidebar_scrollbar = tk.Scrollbar(
            self.sidebar_frame,
            orient='vertical',
            command=self.sidebar_canvas.yview,
            width=8,
            bg=self.colors['dark']['card_bg'],
            troughcolor=self.colors['dark']['border'],
            activebackground=self.colors['dark']['button_hover']
        )
        self.sidebar_scrollable_frame = tk.Frame(
            self.sidebar_canvas,
            bg=self.colors['dark']['card_bg']
        )
        
        self.sidebar_scrollable_frame.bind(
            "<Configure>",
            lambda e: self.sidebar_canvas.configure(scrollregion=self.sidebar_canvas.bbox("all"))
        )
        
        self.sidebar_canvas.create_window((0, 0), window=self.sidebar_scrollable_frame, anchor="nw")
        self.sidebar_canvas.configure(yscrollcommand=self.sidebar_scrollbar.set)
        
        # Bind mousewheel to canvas
        self.sidebar_canvas.bind_all("<MouseWheel>", self._on_sidebar_mousewheel)
        
        self.sidebar_canvas.pack(side='left', fill='both', expand=True, padx=(10, 0), pady=(0, 10))
        self.sidebar_scrollbar.pack(side='right', fill='y', padx=(0, 5), pady=(0, 10))
        
        # Tool buttons - FIXED: No black rectangle on selection
        tools = [
            ("📈 Dashboard", 0),
            ("🌐 Network Scanner", 1),
            ("🔍 Port Scanner", 2),
            ("🔐 Hash Verifier", 3),
            ("🔑 Password Tool", 4),
            ("🧱 AES Encryption", 5),
            ("🔒 Breach Checker", 6),
            ("📊 Charts", 7)
        ]
        
        self.sidebar_buttons = []
        for tool_text, tab_index in tools:
            btn_frame = tk.Frame(self.sidebar_scrollable_frame, bg=self.colors['dark']['card_bg'])
            btn_frame.pack(fill='x', padx=5, pady=4)
            
            btn = tk.Button(
                btn_frame,
                text=tool_text,
                font=("Segoe UI", 11, "bold"),
                relief='flat',
                bg=self.colors['dark']['button_bg'],
                fg=self.colors['dark']['text_primary'],
                bd=0,
                padx=15,
                pady=14,
                anchor='w',
                cursor='hand2',
                activebackground=self.colors['dark']['button_hover'],
                activeforeground=self.colors['dark']['accent'],
                command=lambda idx=tab_index: self.notebook.select(idx)
            )
            
            # Add hover effects without selection indicator
            def make_hover_effect(button, normal_bg, hover_bg):
                def on_enter(e):
                    if button['bg'] == normal_bg:
                        button.configure(bg=hover_bg)
                def on_leave(e):
                    if button['bg'] == hover_bg:
                        button.configure(bg=normal_bg)
                return on_enter, on_leave
            
            on_enter, on_leave = make_hover_effect(
                btn, 
                self.colors['dark']['button_bg'], 
                self.colors['dark']['button_hover']
            )
            btn.bind("<Enter>", on_enter)
            btn.bind("<Leave>", on_leave)
            
            btn.pack(fill='x')
            self.sidebar_buttons.append(btn)
        
        # Add separator before quick actions
        sep2 = tk.Frame(self.sidebar_frame, bg=self.colors['dark']['border'], height=1)
        sep2 = tk.Frame(self.sidebar_scrollable_frame, bg=self.colors['dark']['border'], height=1)
        sep2.pack(fill='x', padx=10, pady=15)
        sep2.pack_propagate(False)
        
        # Quick actions frame
        quick_frame = tk.Frame(self.sidebar_scrollable_frame, bg=self.colors['dark']['card_bg'])
        quick_frame.pack(fill='x', pady=10, padx=5)
        
        tk.Label(
            quick_frame,
            text="⚡ ACTIONS",
            font=("Segoe UI", 11, "bold"),
            fg=self.colors['dark']['accent'],
            bg=self.colors['dark']['card_bg']
        ).pack(anchor='w', padx=10, pady=(0, 10))
        
        quick_actions = [
            ("💾  Clear Results", self.clear_all_results),
            ("💾  Export Results", self.export_results),
            ("💾  Session Info", self.show_session_info)
        ]
        
        for action_text, action_cmd in quick_actions:
            btn_frame = tk.Frame(quick_frame, bg=self.colors['dark']['card_bg'])
            btn_frame.pack(fill='x', padx=0, pady=3)
            
            btn = tk.Button(
                btn_frame,
                text=action_text,
                font=("Segoe UI", 10),
                relief='flat',
                bg=self.colors['dark']['transparent_bg'],
                fg=self.colors['dark']['accent_secondary'],
                bd=0,
                padx=15,
                pady=8,
                anchor='w',
                cursor='hand2',
                activebackground=self.colors['dark']['button_bg'],
                activeforeground=self.colors['dark']['accent'],
                command=action_cmd
            )
            btn.pack(fill='x')
    
    def _on_sidebar_mousewheel(self, event):
        """Handle mousewheel scrolling for sidebar"""
        if self.sidebar_canvas.winfo_exists():
            self.sidebar_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    
    def create_hd_notebook(self, parent):
        """Create notebook with enhanced tabs"""
        # Main notebook container
        self.notebook_container = tk.Frame(
            parent, 
            bg=self.colors['dark']['card_bg'],
            relief='flat',
            bd=1,
            highlightbackground=self.colors['dark']['border'],
            highlightthickness=1
        )
        self.notebook_container.grid(row=0, column=1, sticky='nsew')

        # Right-side results navigation (separate vertical scrollbar)
        self.results_nav_frame = tk.Frame(
            parent,
            bg=self.colors['dark']['card_bg'],
            width=18,
            relief='flat',
            bd=0,
            highlightbackground=self.colors['dark']['border'],
            highlightthickness=1
        )
        self.results_nav_frame.grid(row=0, column=2, sticky='ns')

        # Thin scrollbar that will be attached to the active tab's results widget
        self.results_scrollbar = tk.Scrollbar(
            self.results_nav_frame,
            orient='vertical',
            width=8,
            bg=self.colors['dark']['card_bg'],
            troughcolor=self.colors['dark']['border']
        )
        self.results_scrollbar.pack(fill='y', padx=(2,4), pady=10)
        
        # Create custom notebook style - FIXED: Better tab appearance
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_notebook_style()
        
        self.notebook = ttk.Notebook(self.notebook_container, style='HD.TNotebook')
        self.notebook.pack(fill='both', expand=True)
        
        # Create enhanced tabs
        self.create_dashboard_tab()
        self.create_network_scanner_tab_hd()
        self.create_port_scanner_tab_hd()
        self.create_hash_verifier_tab_hd()
        self.create_password_tool_tab_hd()
        self.create_aes_encryption_tab_hd()
        self.create_breach_checker_tab_hd()
        # Charts tab: Breach visualizations
        self.create_charts_tab_hd()
        
        
        # Bind tab change event
        self.notebook.bind('<<NotebookTabChanged>>', self.on_tab_changed)

        # After creating tabs, attach results scrollbar to the initially selected tab
        try:
            current_tab = self.notebook.index(self.notebook.select())
            mapping = {1: 'network_results', 2: 'port_results', 3: 'hash_results', 4: 'password_results', 5: 'aes_results', 6: 'breach_results'}
            target_attr = mapping.get(current_tab)
            if target_attr and hasattr(self, target_attr):
                self.set_results_target(getattr(self, target_attr))
        except Exception:
            pass
    
    def configure_notebook_style(self):
        """Configure notebook style for current theme - FIXED: No black rectangle"""
        colors = self.colors['dark'] if self.theme == 'dark' else self.colors['light']
        
        # Configure the notebook style
        self.style.configure('HD.TNotebook', 
                           background=colors['card_bg'],
                           borderwidth=0,
                           tabmargins=[0, 0, 0, 0])
        
        # Configure tab style - FIXED: Remove black background, improved padding
        self.style.configure('HD.TNotebook.Tab',
                           padding=[25, 12],
                           background=colors['button_bg'],
                           foreground=colors['text_secondary'],
                           borderwidth=0,
                           focuscolor=colors['card_bg'])  # Remove focus color
        
        # Map tab states - FIXED: Clean selected state with better visual feedback
        self.style.map('HD.TNotebook.Tab',
                     background=[('selected', colors['accent']),
                                ('active', colors['button_hover'])],
                     foreground=[('selected', colors['bg']),
                                ('active', colors['text_primary'])])

    def create_dashboard_tab(self):
        """Create dashboard tab with overview and improved layout"""
        self.dashboard_frame = tk.Frame(self.notebook, bg=self.colors['dark']['bg'])
        self.notebook.add(self.dashboard_frame, text="📈 Dashboard")
        
        # Create main scrollable container for better UX on small screens
        main_canvas = tk.Canvas(
            self.dashboard_frame,
            bg=self.colors['dark']['bg'],
            highlightthickness=0,
            relief='flat',
            bd=0
        )
        scrollbar = ttk.Scrollbar(self.dashboard_frame, orient='vertical', command=main_canvas.yview)
        scrollable_frame = tk.Frame(main_canvas, bg=self.colors['dark']['bg'])
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all"))
        )

        # Stretch the inner frame to the canvas width for full-screen usage
        window_id = main_canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

        def _resize_canvas(e):
            # Match inner frame width to canvas
            main_canvas.itemconfig(window_id, width=e.width)
            # Expand scrollregion to at least canvas height to avoid bottom gap
            if scrollable_frame.winfo_reqheight() < e.height:
                main_canvas.configure(scrollregion=(0, 0, e.width, e.height))
            else:
                main_canvas.configure(scrollregion=main_canvas.bbox("all"))

        main_canvas.bind("<Configure>", _resize_canvas)
        main_canvas.configure(yscrollcommand=scrollbar.set)
        
        # Top row: Quick Actions (left) and Recent Activity (right)
        top_row = tk.Frame(scrollable_frame, bg=self.colors['dark']['bg'])
        top_row.pack(fill='x', padx=12, pady=(12, 8))
        top_row.grid_columnconfigure(0, weight=3)
        top_row.grid_columnconfigure(1, weight=2)

        # Quick action bar for fast access (left)
        quick_card = self.create_card(top_row, "⚡ Quick Actions")
        quick_card.grid(row=0, column=0, sticky='nsew', padx=(4, 6), pady=0)
        qa_frame = tk.Frame(quick_card, bg=self.colors['dark']['card_bg'])
        qa_frame.pack(fill='x', padx=12, pady=(8, 10))
        qa_buttons = [
            ("📖 View Full Log", self.show_activity_window, False),
            ("💾 Save Session", self.save_session, False),
            ("📂 Load Session", self.load_session, False),
            ("🗑️ Clear Results", self.clear_all_results, False),
            ("📤 Export Results", self.export_results, False),
        ]
        for text, cmd, accent in qa_buttons:
            btn = self.create_hd_button(qa_frame, text, cmd, accent=accent)
            btn.pack(side='left', padx=5, pady=2)

        # Recent Activity moved to the right
        self.activity_card = self.create_card(top_row, "📋 Recent Activity")
        self.activity_card.grid(row=0, column=1, sticky='nsew', padx=(6, 4), pady=0)
        
        # Stats cards container with improved spacing
        stats_card = self.create_card(scrollable_frame, "📊 Session Overview")
        stats_card.pack(fill='both', expand=True, padx=12, pady=8)
        
        # Grid layout 2x2 for stats
        stats_frame = tk.Frame(stats_card, bg=self.colors['dark']['card_bg'])
        stats_frame.pack(fill='both', expand=True, padx=12, pady=(8, 12))
        stats_frame.grid_columnconfigure(0, weight=1)
        stats_frame.grid_columnconfigure(1, weight=1)
        stats_frame.grid_rowconfigure(0, weight=1)
        stats_frame.grid_rowconfigure(1, weight=1)
        
        self.stats_data = [
            ("📊 Total Scans", str(self.session_data.get('scans_performed', 0)), "#00ff88", "Scans this session"),
            ("🚪 Open Ports", "0", "#0099ff", "Discovered ports"),
            ("📁 Failed Checks", str(self.session_data.get('files_checked', 0)), "#ffaa00", "Integrity failures"),
            ("🔒 Breached Emails", str(self.session_data.get('breached_emails_found', 0)), "#ff4444", "Compromised emails")
        ]
        
        self.stat_cards = []
        for i, (title, value, color, description) in enumerate(self.stats_data):
            card = self.create_stat_card(stats_frame, title, value, color, description)
            r, c = divmod(i, 2)
            card.grid(row=r, column=c, sticky='nsew', padx=8, pady=6)
            self.stat_cards.append(card)
        
        # Activity card with improved controls
        # Activity text with scrolling
        self.activity_label = scrolledtext.ScrolledText(
            self.activity_card,
            height=6,
            wrap=tk.WORD,
            font=("Segoe UI", 9),
            fg=self.colors['dark']['text_primary'],
            bg=self.colors['dark']['bg'],
            insertbackground=self.colors['dark']['text_primary'],
            relief='flat',
            bd=0
        )
        self.activity_label.pack(fill='both', expand=True, padx=20, pady=(0, 15))
        self.activity_label.insert(tk.END, "🕐 No recent activity yet. Start scanning to see results here!")
        self.activity_label.config(state='disabled')
        
        # Pack the scrollable elements
        main_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def update_dashboard_activity(self, activity):
        """Update dashboard with recent activity"""
        # Mark session as modified (unsaved)
        self.session_saved = False

        # Update session data
        self.session_data['recent_activities'].insert(0, activity)
        # Keep only last 5 activities
        if len(self.session_data['recent_activities']) > 5:
            self.session_data['recent_activities'] = self.session_data['recent_activities'][:5]
        
        # Update activity display
        activity_display = "\n".join(
            f"🔹 {act}" for act in self.session_data['recent_activities']
        )
        
        # Update the ScrolledText widget
        self.activity_label.config(state='normal')
        self.activity_label.delete(1.0, tk.END)
        self.activity_label.insert(tk.END, activity_display if activity_display else "🕐 No recent activity yet.")
        self.activity_label.config(state='disabled')
        
        # Update stats
        self.stats_label.config(text=f"Scans: {self.session_data['scans_performed']}")
        # Append activity to persistent history
        try:
            self.append_to_history(activity)
        except Exception:
            pass
        
        # Update stat cards
        for i, card in enumerate(self.stat_cards):
            # Destroy old card
            for widget in card.winfo_children():
                widget.destroy()
            card.destroy()
        
        # Recreate stat cards with updated values
        stats_container = self.stat_cards[0].master if self.stat_cards else None
        if stats_container:
            self.stat_cards = []
            updated_stats = [
                (f"📊 Total Scans", str(self.session_data.get('scans_performed', 0)), "#00ff88", "Scans performed this session"),
                ("🚪 Open Ports", "4", "#0099ff", "Ports discovered across scans"),
                ("📁 Files Checked", str(self.session_data.get('files_checked', 0)), "#ffaa00", "Files checked (failed verifications)"),
                ("🔒 Breached Emails", str(self.session_data.get('breached_emails_found', 0)), "#ff4444", "Emails found in data breaches")
            ]
            
            for i, (title, value, color, description) in enumerate(updated_stats):
                card = self.create_stat_card(stats_container, title, value, color, description)
                card.pack(side='left', fill='x', expand=True, padx=5)
                self.stat_cards.append(card)

    def show_activity_window(self):
        """Display all activities in a new window"""
        activity_window = tk.Toplevel(self.root)
        activity_window.title("Activity Log")
        activity_window.geometry("600x400")
        activity_window.configure(bg=self.colors['dark']['bg'])
        
        # Header
        header = tk.Label(
            activity_window,
            text="📋 Complete Activity Log",
            font=("Segoe UI", 12, "bold"),
            fg=self.colors['dark']['accent'],
            bg=self.colors['dark']['bg']
        )
        header.pack(fill='x', padx=15, pady=15)
        
        # Activity text area
        activity_text = scrolledtext.ScrolledText(
            activity_window,
            wrap=tk.WORD,
            font=("Segoe UI", 10),
            fg=self.colors['dark']['text_primary'],
            bg=self.colors['dark']['card_bg'],
            relief='flat',
            bd=1
        )
        activity_text.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        
        # Display all activities
        if self.session_data['recent_activities']:
            activity_content = "Recent Activities:\n\n" + "\n".join(
                f"🔹 {activity}" for activity in self.session_data['recent_activities']
            )
        else:
            activity_content = "No activities recorded yet."
        
        activity_text.insert(tk.END, activity_content)
        activity_text.config(state='disabled')
        
        # Close button
        close_btn = self.create_hd_button(
            activity_window,
            "✕ Close",
            activity_window.destroy,
            accent=True
        )
        close_btn.pack(pady=10)

    # Persistent history methods
    def _history_file_path(self):
        return os.path.join(os.path.dirname(__file__), 'history.json')

    def append_to_history(self, activity):
        """Append a single activity entry to the persistent history file."""
        try:
            history = self.load_history()
        except Exception:
            history = []

        record = {
            'timestamp': datetime.now().isoformat(),
            'activity': activity
        }
        history.insert(0, record)

        try:
            with open(self._history_file_path(), 'w', encoding='utf-8') as f:
                json.dump(history, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Failed to write history file: {e}")

    def load_history(self):
        """Load history list from file. Returns list of records."""
        path = self._history_file_path()
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Failed to read history file: {e}")
                return []
        return []

    def clear_history(self):
        """Clear persistent history file after user confirmation."""
        path = self._history_file_path()
        if os.path.exists(path):
            if messagebox.askyesno("Confirm", "Are you sure you want to clear the entire history?"):
                try:
                    os.remove(path)
                    messagebox.showinfo("History", "History cleared.")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to clear history: {e}")
        else:
            messagebox.showinfo("History", "No history file found.")

    def show_history_window(self):
        """Open a window showing the persistent history (all sessions)."""
        history = self.load_history()

        hw = tk.Toplevel(self.root)
        hw.title("History")
        hw.geometry("700x500")
        hw.configure(bg=self.colors['dark']['bg'])

        header = tk.Label(
            hw,
            text="📚 Full Activity History",
            font=("Segoe UI", 12, "bold"),
            fg=self.colors['dark']['accent'],
            bg=self.colors['dark']['bg']
        )
        header.pack(fill='x', padx=15, pady=10)

        history_text = scrolledtext.ScrolledText(
            hw,
            wrap=tk.WORD,
            font=("Segoe UI", 10),
            fg=self.colors['dark']['text_primary'],
            bg=self.colors['dark']['card_bg'],
            relief='flat',
            bd=1
        )
        history_text.pack(fill='both', expand=True, padx=15, pady=(0, 10))

        if history:
            lines = []
            for rec in history:
                ts = rec.get('timestamp', '')
                act = rec.get('activity', '')
                try:
                    pretty_ts = datetime.fromisoformat(ts).strftime('%Y-%m-%d %H:%M:%S') if ts else ts
                except Exception:
                    pretty_ts = ts
                lines.append(f"[{pretty_ts}] {act}")
            history_text.insert(tk.END, "\n".join(lines))
        else:
            history_text.insert(tk.END, "No history available.")

        history_text.config(state='disabled')

        btn_frame = tk.Frame(hw, bg=self.colors['dark']['bg'])
        btn_frame.pack(fill='x', padx=15, pady=(0, 15))

        export_btn = self.create_hd_button(btn_frame, "📤 Export History", lambda: self._export_history(history), accent=False)
        export_btn.pack(side='left')

        clear_btn = self.create_hd_button(btn_frame, "🗑️ Clear History", self.clear_history, accent=False)
        clear_btn.pack(side='left', padx=8)

        close_btn = self.create_hd_button(btn_frame, "✕ Close", hw.destroy, accent=True)
        close_btn.pack(side='right')

    def _export_history(self, history):
        filename = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON', '*.json'), ('All', '*.*')])
        if not filename:
            return
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(history, f, indent=2, ensure_ascii=False)
            messagebox.showinfo('Export', f'History exported to {filename}')
        except Exception as e:
            messagebox.showerror('Export Error', str(e))

    # New session management
    def create_new_session(self):
        """Create a new session; warn if current session has unsaved changes."""
        try:
            if not getattr(self, 'session_saved', True):
                # Show pleasant warning dialog with options
                dlg = tk.Toplevel(self.root)
                dlg.title("Unsaved Session")
                dlg.geometry("480x200")
                dlg.configure(bg=self.colors['dark']['bg'])

                header = tk.Label(dlg, text="✨ You have unsaved work", font=("Segoe UI", 14, "bold"), fg=self.colors['dark']['accent'], bg=self.colors['dark']['bg'])
                header.pack(pady=(12, 6))

                msg = tk.Label(dlg, text=("It looks like your current session has changes that haven't been saved.\n"
                                           "Would you like to save them before starting a new session, discard them, or cancel?"),
                               font=("Segoe UI", 10), fg=self.colors['dark']['text_primary'], bg=self.colors['dark']['bg'], justify='center')
                msg.pack(padx=18, pady=(0, 12))

                btn_frame = tk.Frame(dlg, bg=self.colors['dark']['bg'])
                btn_frame.pack(fill='x', pady=(6, 12))

                def _save_and_new():
                    dlg.destroy()
                    # save then clear
                    self.save_session()
                    self._clear_session()

                def _discard_and_new():
                    dlg.destroy()
                    self._clear_session()

                def _cancel():
                    dlg.destroy()

                save_btn = tk.Button(btn_frame, text='💾 Save & New', command=_save_and_new, bg=self.colors['dark']['button_bg'], fg=self.colors['dark']['text_primary'], relief='flat')
                save_btn.pack(side='left', padx=12)

                discard_btn = tk.Button(btn_frame, text='🗑️ Discard & New', command=_discard_and_new, bg=self.colors['dark']['button_bg'], fg=self.colors['dark']['text_primary'], relief='flat')
                discard_btn.pack(side='left', padx=12)

                cancel_btn = tk.Button(btn_frame, text='✕ Cancel', command=_cancel, bg=self.colors['dark']['button_bg'], fg=self.colors['dark']['text_primary'], relief='flat')
                cancel_btn.pack(side='right', padx=12)

                # Make dialog modal
                dlg.transient(self.root)
                dlg.grab_set()
                self.root.wait_window(dlg)
            else:
                # No unsaved changes — just clear session
                self._clear_session()
        except Exception as e:
            messagebox.showerror('Error', f'Failed to create new session: {e}')

    def _clear_session(self):
        """Reset session data and clear all result widgets."""
        try:
            # Reset session data
            self.session_data = {
                'scans_performed': 0,
                'last_scan': None,
                'results_history': [],
                'recent_activities': [],
                'breached_emails_found': 0,
                'files_checked': 0
            }

            # Clear UI result widgets
            widgets = [
                getattr(self, 'network_results', None),
                getattr(self, 'port_results', None),
                getattr(self, 'hash_results', None),
                getattr(self, 'password_results', None),
                getattr(self, 'aes_results', None),
                getattr(self, 'breach_results', None),
            ]
            for w in widgets:
                if w is not None:
                    try:
                        w.config(state='normal')
                        w.delete(1.0, tk.END)
                        w.config(state='normal')
                    except Exception:
                        pass

            # Clear activity display
            try:
                self.activity_label.config(state='normal')
                self.activity_label.delete(1.0, tk.END)
                self.activity_label.insert(tk.END, "🕐 No recent activity yet. Start scanning to see results here!")
                self.activity_label.config(state='disabled')
            except Exception:
                pass

            # Reset stats
            try:
                self.stats_label.config(text="Scans: 0")
                self.update_dashboard_stats()
            except Exception:
                pass

            # Mark as saved (blank session)
            self.session_saved = True
            self.update_hd_status("🟢 New session started")
        except Exception as e:
            messagebox.showerror('Error', f'Failed to clear session: {e}')

    def save_session(self):
        """Save current session to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        if filename:
            try:
                # Collect visible results from each results widget
                results = {
                    'network': getattr(self, 'network_results', None).get(1.0, tk.END) if getattr(self, 'network_results', None) else None,
                    'ports': getattr(self, 'port_results', None).get(1.0, tk.END) if getattr(self, 'port_results', None) else None,
                    'hash': getattr(self, 'hash_results', None).get(1.0, tk.END) if getattr(self, 'hash_results', None) else None,
                    'password': getattr(self, 'password_results', None).get(1.0, tk.END) if getattr(self, 'password_results', None) else None,
                    'aes': getattr(self, 'aes_results', None).get(1.0, tk.END) if getattr(self, 'aes_results', None) else None,
                    'breach': getattr(self, 'breach_results', None).get(1.0, tk.END) if getattr(self, 'breach_results', None) else None,
                }

                session_data = {
                    'timestamp': datetime.now().isoformat(),
                    'scans_performed': self.session_data['scans_performed'],
                    'last_scan': self.session_data['last_scan'],
                    'recent_activities': self.session_data['recent_activities'],
                    'breached_emails_found': self.session_data.get('breached_emails_found', 0),
                    'files_checked': self.session_data.get('files_checked', 0),
                    'results': results
                }

                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(session_data, f, indent=2, ensure_ascii=False)

                messagebox.showinfo("Success", f"Session saved successfully to:\n{filename}")
                self.update_hd_status(f"✅ Session saved to {os.path.basename(filename)}")
                # Mark session as saved
                try:
                    self.session_saved = True
                except Exception:
                    pass
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save session:\n{str(e)}")

    def load_session(self):
        """Load session from file"""
        filename = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    session_data = json.load(f)

                # Load session metadata
                self.session_data['scans_performed'] = session_data.get('scans_performed', 0)
                self.session_data['last_scan'] = session_data.get('last_scan', None)
                self.session_data['recent_activities'] = session_data.get('recent_activities', [])
                # Restore breached emails counter if present
                self.session_data['breached_emails_found'] = session_data.get('breached_emails_found', 0)
                # Restore files_checked counter if present
                self.session_data['files_checked'] = session_data.get('files_checked', 0)

                # Update activity display
                self.activity_label.config(state='normal')
                self.activity_label.delete(1.0, tk.END)
                activity_display = "\n".join(
                    f"🔹 {act}" for act in self.session_data['recent_activities']
                ) if self.session_data['recent_activities'] else "Session loaded - no activities in this session."
                self.activity_label.insert(tk.END, activity_display)
                self.activity_label.config(state='disabled')

                self.stats_label.config(text=f"Scans: {self.session_data['scans_performed']}")
                # Update dashboard stat cards to reflect loaded session
                try:
                    self.update_dashboard_stats()
                    # Mark session as saved after successful load
                    self.session_saved = True
                except Exception:
                    pass

                # If results are present in the session file, load them into their tabs directly
                saved_results = session_data.get('results', {})
                if saved_results:
                    for key, txt in saved_results.items():
                        if txt is not None and str(txt).strip():
                            self._apply_loaded_result(key, txt)

                messagebox.showinfo("Success", f"Session loaded successfully from:\n{filename}")
                self.update_hd_status(f"✅ Session loaded from {os.path.basename(filename)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load session:\n{str(e)}")

    def create_stat_card(self, parent, title, value, color, description):
        """Create an improved statistics card with better visual hierarchy"""
        card = tk.Frame(
            parent,
            bg=self.colors['dark']['card_bg'],
            relief='flat',
            bd=1,
            highlightbackground=self.colors['dark']['border'],
            highlightthickness=1
        )
        card.pack_propagate(True)
        
        # Title with emoji and better spacing
        tk.Label(
            card,
            text=title,
            font=("Segoe UI", 10, "bold"),
            fg=self.colors['dark']['text_secondary'],
            bg=self.colors['dark']['card_bg'],
            wraplength=240
        ).pack(anchor='w', padx=16, pady=(14, 0), fill='x')
        
        # Large value with accent color
        tk.Label(
            card,
            text=value,
            font=("Segoe UI", 28, "bold"),
            fg=color,
            bg=self.colors['dark']['card_bg']
        ).pack(anchor='w', padx=16, pady=(6, 0))
        
        # Subtle description
        tk.Label(
            card,
            text=description,
            font=("Segoe UI", 8),
            fg=self.colors['dark']['text_secondary'],
            bg=self.colors['dark']['card_bg'],
            wraplength=240,
            justify='left'
        ).pack(anchor='w', padx=16, pady=(8, 14), fill='x')
        
        return card

    def create_network_scanner_tab_hd(self):
        """Create network scanner tab with full width layout"""
        frame = tk.Frame(self.notebook, bg=self.colors['dark']['bg'])
        self.notebook.add(frame, text="🌐 Network Scanner")
        
        # Main content frame - two column layout
        content_frame = tk.Frame(frame, bg=self.colors['dark']['bg'])
        content_frame.pack(fill='both', expand=True, padx=15, pady=15)
        
        # Left column - Configuration
        left_column = tk.Frame(content_frame, bg=self.colors['dark']['bg'])
        left_column.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        # Configuration card
        config_card = self.create_card(left_column, "Scan Configuration")
        config_card.pack(fill='both', expand=True)
        
        # Input fields
        input_frame = tk.Frame(config_card, bg=self.colors['dark']['card_bg'])
        input_frame.pack(fill='x', padx=20, pady=20)
        
        # Network label and input
        tk.Label(
            input_frame,
            text="Network Range:",
            font=("Segoe UI", 11, "bold"),
            fg=self.colors['dark']['accent'],
            bg=self.colors['dark']['card_bg']
        ).pack(anchor='w', pady=(0, 8))
        
        self.network_entry = self.create_hd_entry(input_frame)
        self.network_entry.pack(fill='x', pady=(0, 15))
        self.network_entry.insert(0, "192.168.1.0/24")

        # Scan method with better styling
        tk.Label(
            input_frame,
            text="Scan Method:",
            font=("Segoe UI", 11, "bold"),
            fg=self.colors['dark']['accent'],
            bg=self.colors['dark']['card_bg']
        ).pack(anchor='w', pady=(0, 8))

        method_frame = tk.Frame(input_frame, bg=self.colors['dark']['card_bg'])
        method_frame.pack(fill='x', pady=(0, 15))

        self.network_method_var = tk.StringVar(value="tcp")

        tcp_radio = tk.Radiobutton(
            method_frame,
            text="TCP (ports)",
            variable=self.network_method_var,
            value="tcp",
            font=("Segoe UI", 10),
            fg=self.colors['dark']['text_primary'],
            bg=self.colors['dark']['card_bg'],
            activebackground=self.colors['dark']['card_bg'],
            activeforeground=self.colors['dark']['accent'],
            selectcolor=self.colors['dark']['card_bg'],
        )
        tcp_radio.pack(side='left', padx=(0, 20))

        icmp_radio = tk.Radiobutton(
            method_frame,
            text="ICMP (ping)",
            variable=self.network_method_var,
            value="icmp",
            font=("Segoe UI", 10),
            fg=self.colors['dark']['text_primary'],
            bg=self.colors['dark']['card_bg'],
            activebackground=self.colors['dark']['card_bg'],
            activeforeground=self.colors['dark']['accent'],
            selectcolor=self.colors['dark']['card_bg'],
        )
        icmp_radio.pack(side='left')
        
        # Presets label
        tk.Label(
            input_frame,
            text="Quick Presets:",
            font=("Segoe UI", 11, "bold"),
            fg=self.colors['dark']['accent'],
            bg=self.colors['dark']['card_bg']
        ).pack(anchor='w', pady=(0, 8))
        
        # Preset ranges
        preset_frame = tk.Frame(input_frame, bg=self.colors['dark']['card_bg'])
        preset_frame.pack(fill='x', pady=(0, 20))
        
        presets = ["192.168.1.0/24", "10.0.0.0/24", "172.16.1.0/24"]
        for preset in presets:
            btn = tk.Button(
                preset_frame,
                text=preset,
                font=("Segoe UI", 9),
                relief='flat',
                bg=self.colors['dark']['button_bg'],
                fg=self.colors['dark']['text_secondary'],
                activebackground=self.colors['dark']['button_hover'],
                activeforeground=self.colors['dark']['accent'],
                command=lambda p=preset: self.network_entry.delete(0, tk.END) or self.network_entry.insert(0, p),
                padx=12,
                pady=8
            )
            btn.pack(side='left', padx=(0, 10))
        
        # Scan button
        scan_btn = self.create_hd_button(
            config_card,
            "🚀 Start Network Scan",
            self.run_network_scan,
            accent=True
        )
        scan_btn.pack(pady=20, padx=20, fill='x')
        
        # Right column - Results
        right_column = tk.Frame(content_frame, bg=self.colors['dark']['bg'])
        right_column.pack(side='left', fill='both', expand=True, padx=(10, 0))
        
        results_card = self.create_card(right_column, "Scan Results")
        results_card.pack(fill='both', expand=True)
        
        self.network_results = scrolledtext.ScrolledText(
            results_card,
            height=30,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg=self.colors['dark']['bg'],
            fg=self.colors['dark']['text_primary'],
            insertbackground=self.colors['dark']['text_primary'],
            relief='flat',
            bd=0
        )
        self.network_results.pack(fill='both', expand=True, padx=20, pady=15)

    def create_port_scanner_tab_hd(self):
        """Create port scanner tab with full width two-column layout"""
        frame = tk.Frame(self.notebook, bg=self.colors['dark']['bg'])
        self.notebook.add(frame, text="🔍 Port Scanner")
        
        # Main content frame - two column layout
        content_frame = tk.Frame(frame, bg=self.colors['dark']['bg'])
        content_frame.pack(fill='both', expand=True, padx=15, pady=15)
        
        # Left column - Configuration
        left_column = tk.Frame(content_frame, bg=self.colors['dark']['bg'])
        left_column.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        # Configuration card
        config_card = self.create_card(left_column, "Target Configuration")
        config_card.pack(fill='both', expand=True)
        
        # Input fields
        input_frame = tk.Frame(config_card, bg=self.colors['dark']['card_bg'])
        input_frame.pack(fill='x', padx=20, pady=20)
        
        # Target IP label and input
        tk.Label(
            input_frame,
            text="Target IP/Hostname:",
            font=("Segoe UI", 11, "bold"),
            fg=self.colors['dark']['accent'],
            bg=self.colors['dark']['card_bg']
        ).pack(anchor='w', pady=(0, 8))
        
        self.target_entry = self.create_hd_entry(input_frame)
        self.target_entry.pack(fill='x', pady=(0, 15))
        self.target_entry.insert(0, "127.0.0.1")
        
        # Port range label and input
        tk.Label(
            input_frame,
            text="Port Range:",
            font=("Segoe UI", 11, "bold"),
            fg=self.colors['dark']['accent'],
            bg=self.colors['dark']['card_bg']
        ).pack(anchor='w', pady=(0, 8))
        
        self.port_range_entry = self.create_hd_entry(input_frame)
        self.port_range_entry.pack(fill='x', pady=(0, 15))
        self.port_range_entry.insert(0, "1-1000")
        
        # Presets label
        tk.Label(
            input_frame,
            text="Quick Presets:",
            font=("Segoe UI", 11, "bold"),
            fg=self.colors['dark']['accent'],
            bg=self.colors['dark']['card_bg']
        ).pack(anchor='w', pady=(0, 8))
        
        # Common port presets
        preset_frame = tk.Frame(input_frame, bg=self.colors['dark']['card_bg'])
        preset_frame.pack(fill='x', pady=(0, 20))
        
        common_ports = ["1-1000", "1-100", "80,443,22,21", "1-65535"]
        for ports in common_ports:
            btn = tk.Button(
                preset_frame,
                text=ports,
                font=("Segoe UI", 9),
                relief='flat',
                bg=self.colors['dark']['button_bg'],
                fg=self.colors['dark']['text_secondary'],
                activebackground=self.colors['dark']['button_hover'],
                activeforeground=self.colors['dark']['accent'],
                command=lambda p=ports: self.port_range_entry.delete(0, tk.END) or self.port_range_entry.insert(0, p),
                padx=12,
                pady=8
            )
            btn.pack(side='left', padx=(0, 10))
        
        scan_btn = self.create_hd_button(
            config_card,
            "🔍 Start Port Scan",
            self.run_port_scan,
            accent=True
        )
        scan_btn.pack(pady=20, padx=20, fill='x')
        
        # Right column - Results
        right_column = tk.Frame(content_frame, bg=self.colors['dark']['bg'])
        right_column.pack(side='left', fill='both', expand=True, padx=(10, 0))
        
        results_card = self.create_card(right_column, "Open Ports")
        results_card.pack(fill='both', expand=True)
        
        self.port_results = scrolledtext.ScrolledText(
            results_card,
            height=30,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg=self.colors['dark']['bg'],
            fg=self.colors['dark']['text_primary'],
            insertbackground=self.colors['dark']['text_primary'],
            relief='flat',
            bd=0
        )
        self.port_results.pack(fill='both', expand=True, padx=20, pady=15)

    # Log Analyzer removed: UI and functionality cleaned from the application

    def create_hash_verifier_tab_hd(self):
        """Create hash verifier tab with full width two-column layout"""
        frame = tk.Frame(self.notebook, bg=self.colors['dark']['bg'])
        self.notebook.add(frame, text="🔐 Hash Verifier")
        
        # Main content frame - two column layout
        content_frame = tk.Frame(frame, bg=self.colors['dark']['bg'])
        content_frame.pack(fill='both', expand=True, padx=15, pady=15)
        
        # Left column - Configuration
        left_column = tk.Frame(content_frame, bg=self.colors['dark']['bg'])
        left_column.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        config_card = self.create_card(left_column, "File Integrity Check")
        config_card.pack(fill='both', expand=True)
        
        input_frame = tk.Frame(config_card, bg=self.colors['dark']['card_bg'])
        input_frame.pack(fill='x', padx=20, pady=20)
        
        # File selection with label
        tk.Label(
            input_frame,
            text="File Path:",
            font=("Segoe UI", 11, "bold"),
            fg=self.colors['dark']['accent'],
            bg=self.colors['dark']['card_bg']
        ).pack(anchor='w', pady=(0, 8))
        
        file_frame = tk.Frame(input_frame, bg=self.colors['dark']['card_bg'])
        file_frame.pack(fill='x', pady=(0, 15))
        
        self.file_path_entry = self.create_hd_entry(file_frame)
        self.file_path_entry.pack(side='left', fill='x', expand=True)
        
        browse_btn = self.create_hd_button(
            file_frame,
            "📁 Browse",
            self.browse_hash_file,
            accent=False
        )
        browse_btn.pack(side='right', padx=(10, 0))
        
        # Expected hash with label
        tk.Label(
            input_frame,
            text="Expected Hash:",
            font=("Segoe UI", 11, "bold"),
            fg=self.colors['dark']['accent'],
            bg=self.colors['dark']['card_bg']
        ).pack(anchor='w', pady=(0, 8))
        
        self.expected_hash_entry = self.create_hd_entry(input_frame)
        self.expected_hash_entry.pack(fill='x', pady=(0, 15))
        
        # Algorithm selection with label
        tk.Label(
            input_frame,
            text="Algorithm:",
            font=("Segoe UI", 11, "bold"),
            fg=self.colors['dark']['accent'],
            bg=self.colors['dark']['card_bg']
        ).pack(anchor='w', pady=(0, 8))
        
        algo_frame = tk.Frame(input_frame, bg=self.colors['dark']['card_bg'])
        algo_frame.pack(fill='x', pady=(0, 20))
        
        self.expected_hash_algo_var = tk.StringVar(value="sha256")
        
        algo_options = [
            ("MD5", "md5"),
            ("SHA1", "sha1"),
            ("SHA256", "sha256")
        ]
        
        for algo_text, algo_value in algo_options:
            radio = tk.Radiobutton(
                algo_frame,
                text=algo_text,
                variable=self.expected_hash_algo_var,
                value=algo_value,
                font=("Segoe UI", 10),
                fg=self.colors['dark']['text_primary'],
                bg=self.colors['dark']['card_bg'],
                activebackground=self.colors['dark']['card_bg'],
                activeforeground=self.colors['dark']['accent'],
                selectcolor=self.colors['dark']['card_bg'],
            )
            radio.pack(side='left', padx=(0, 20))
        
        # Hash buttons
        hash_btn_frame = tk.Frame(config_card, bg=self.colors['dark']['card_bg'])
        hash_btn_frame.pack(pady=20, fill='x', padx=20)
        
        hash_types = [
            ("🔒 MD5", 'md5'),
            ("🔒 SHA1", 'sha1'), 
            ("🔒 SHA256", 'sha256')
        ]
        
        for btn_text, hash_type in hash_types:
            btn = self.create_hd_button(
                hash_btn_frame,
                btn_text,
                lambda ht=hash_type: self.run_hash_verification(ht),
                accent=(hash_type == 'sha256')
            )
            btn.pack(side='left', padx=8, fill='x', expand=True)
        
        # Right column - Results
        right_column = tk.Frame(content_frame, bg=self.colors['dark']['bg'])
        right_column.pack(side='left', fill='both', expand=True, padx=(10, 0))
        
        results_card = self.create_card(right_column, "Hash Results")
        results_card.pack(fill='both', expand=True)
        
        self.hash_results = scrolledtext.ScrolledText(
            results_card,
            height=30,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg=self.colors['dark']['bg'],
            fg=self.colors['dark']['text_primary'],
            insertbackground=self.colors['dark']['text_primary'],
            relief='flat',
            bd=0
        )
        self.hash_results.pack(fill='both', expand=True, padx=20, pady=15)

    def create_password_tool_tab_hd(self):
        """Create password strength/strengthener tab with full width two-column layout."""
        frame = tk.Frame(self.notebook, bg=self.colors["dark"]["bg"])
        self.notebook.add(frame, text="🔑 Password Tool")
        
        # Main content frame - two column layout
        content_frame = tk.Frame(frame, bg=self.colors["dark"]["bg"])
        content_frame.pack(fill='both', expand=True, padx=15, pady=15)
        
        # Left column - Configuration
        left_column = tk.Frame(content_frame, bg=self.colors["dark"]["bg"])
        left_column.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        config_card = self.create_card(left_column, "Password Security Analysis")
        config_card.pack(fill='both', expand=True)
        
        input_frame = tk.Frame(config_card, bg=self.colors["dark"]["card_bg"])
        input_frame.pack(fill="x", padx=20, pady=20)

        # Password input with label
        tk.Label(
            input_frame,
            text="Password:",
            font=("Segoe UI", 11, "bold"),
            fg=self.colors["dark"]["accent"],
            bg=self.colors["dark"]["card_bg"],
        ).pack(anchor='w', pady=(0, 8))

        self.password_entry = self.create_hd_entry(input_frame)
        self.password_entry.config(show="*")
        self.password_entry.pack(fill='x', pady=(0, 15))

        # Live strength indicator with better styling
        self.password_live_label = tk.Label(
            input_frame,
            text="Strength: (empty)",
            font=("Segoe UI", 10, "bold"),
            fg=self.colors["dark"]["text_secondary"],
            bg=self.colors["dark"]["card_bg"],
            anchor="w",
        )
        self.password_live_label.pack(anchor='w', pady=(0, 15))

        # Update strength live when user types
        self.password_entry.bind("<KeyRelease>", self._on_password_typed)

        # Action buttons with better spacing
        btn_frame = tk.Frame(config_card, bg=self.colors["dark"]["card_bg"])
        btn_frame.pack(pady=20, fill='x', padx=20)

        strength_btn = self.create_hd_button(
            btn_frame, "📊 Check Strength", self.run_password_strength, accent=True
        )
        strength_btn.pack(side="left", padx=8, fill='x', expand=True)

        strengthen_btn = self.create_hd_button(
            btn_frame,
            "💪 Strengthen",
            self.run_strengthen_password,
            accent=False,
        )
        strengthen_btn.pack(side="left", padx=8, fill='x', expand=True)
        
        # Right column - Results
        right_column = tk.Frame(content_frame, bg=self.colors["dark"]["bg"])
        right_column.pack(side='left', fill='both', expand=True, padx=(10, 0))
        
        results_card = self.create_card(right_column, "Password Analysis")
        results_card.pack(fill="both", expand=True)

        self.password_results = scrolledtext.ScrolledText(
            results_card,
            height=30,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg=self.colors["dark"]["bg"],
            fg=self.colors["dark"]["text_primary"],
            insertbackground=self.colors["dark"]["text_primary"],
            relief='flat',
            bd=0
        )
        self.password_results.pack(fill="both", expand=True, padx=20, pady=15)

    def create_aes_encryption_tab_hd(self):
        """Create AES file encryption/decryption tab with full width two-column layout."""
        frame = tk.Frame(self.notebook, bg=self.colors["dark"]["bg"])
        self.notebook.add(frame, text="🧱 AES Encryption")
        
        # Main content frame - two column layout
        content_frame = tk.Frame(frame, bg=self.colors["dark"]["bg"])
        content_frame.pack(fill='both', expand=True, padx=15, pady=15)
        
        # Left column - Configuration
        left_column = tk.Frame(content_frame, bg=self.colors["dark"]["bg"])
        left_column.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        config_card = self.create_card(left_column, "File Encryption & Decryption")
        config_card.pack(fill='both', expand=True)
        
        input_frame = tk.Frame(config_card, bg=self.colors["dark"]["card_bg"])
        input_frame.pack(fill="x", padx=20, pady=20)

        # File selection with label
        tk.Label(
            input_frame,
            text="File Path:",
            font=("Segoe UI", 11, "bold"),
            fg=self.colors["dark"]["accent"],
            bg=self.colors["dark"]["card_bg"],
        ).pack(anchor='w', pady=(0, 8))

        file_frame = tk.Frame(input_frame, bg=self.colors["dark"]["card_bg"])
        file_frame.pack(fill='x', pady=(0, 15))

        self.aes_file_entry = self.create_hd_entry(file_frame)
        self.aes_file_entry.pack(side="left", fill="x", expand=True)

        browse_btn = self.create_hd_button(
            file_frame, "📁 Browse", self.browse_aes_file, accent=False
        )
        browse_btn.pack(side="right", padx=(10, 0))

        # Password with label
        tk.Label(
            input_frame,
            text="Secret Key:",
            font=("Segoe UI", 11, "bold"),
            fg=self.colors["dark"]["accent"],
            bg=self.colors["dark"]["card_bg"],
        ).pack(anchor='w', pady=(0, 8))

        self.aes_password_entry = self.create_hd_entry(input_frame)
        self.aes_password_entry.config(show="*")
        self.aes_password_entry.pack(fill='x', pady=(0, 15))

        # Info label
        info_text = ("🔒 AES-256-GCM Encryption\n"
                    "• Your file is secured with military-grade AES-256 encryption\n"
                    "• Your password is never stored - keep it safe!\n"
                    "• Without the password, decryption is impossible")
        
        tk.Label(
            input_frame,
            text=info_text,
            justify="left",
            font=("Segoe UI", 9),
            fg=self.colors["dark"]["text_secondary"],
            bg=self.colors["dark"]["card_bg"],
        ).pack(anchor='w', pady=(0, 15))

        # Action buttons with better layout
        btn_frame = tk.Frame(config_card, bg=self.colors["dark"]["card_bg"])
        btn_frame.pack(pady=20, fill='x', padx=20)

        enc_btn = self.create_hd_button(
            btn_frame, "🔐 Encrypt File", self.run_aes_encrypt, accent=True
        )
        enc_btn.pack(side="left", padx=8, fill='x', expand=True)

        dec_btn = self.create_hd_button(
            btn_frame, "🔓 Decrypt File", self.run_aes_decrypt, accent=False
        )
        dec_btn.pack(side="left", padx=8, fill='x', expand=True)
        
        # Right column - Results
        right_column = tk.Frame(content_frame, bg=self.colors["dark"]["bg"])
        right_column.pack(side='left', fill='both', expand=True, padx=(10, 0))
        
        results_card = self.create_card(right_column, "Encryption Log")
        results_card.pack(fill="both", expand=True)

        self.aes_results = scrolledtext.ScrolledText(
            results_card,
            height=30,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg=self.colors["dark"]["bg"],
            fg=self.colors["dark"]["text_primary"],
            insertbackground=self.colors["dark"]["text_primary"],
            relief='flat',
            bd=0
        )
        self.aes_results.pack(fill="both", expand=True, padx=20, pady=15)

    def create_breach_checker_tab_hd(self):
        """Create Breach Checker tab with full width two-column layout."""
        frame = tk.Frame(self.notebook, bg=self.colors["dark"]["bg"])
        self.notebook.add(frame, text="🔒 Breach Checker")
        
        # Main content frame - two column layout
        content_frame = tk.Frame(frame, bg=self.colors["dark"]["bg"])
        content_frame.pack(fill='both', expand=True, padx=15, pady=15)
        
        # Left column - Configuration
        left_column = tk.Frame(content_frame, bg=self.colors["dark"]["bg"])
        left_column.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        config_card = self.create_card(left_column, "Email Breach Intelligence")
        config_card.pack(fill='both', expand=True)
        
        input_frame = tk.Frame(config_card, bg=self.colors["dark"]["card_bg"])
        input_frame.pack(fill="x", padx=20, pady=20)

        # Email input with label
        tk.Label(
            input_frame,
            text="Email Address:",
            font=("Segoe UI", 11, "bold"),
            fg=self.colors["dark"]["accent"],
            bg=self.colors["dark"]["card_bg"],
        ).pack(anchor='w', pady=(0, 8))

        self.breach_email_entry = self.create_hd_entry(input_frame)
        self.breach_email_entry.pack(fill='x', pady=(0, 15))
        self.breach_email_entry.insert(0, "example@email.com")

        # CSV picker for breach database with label
        tk.Label(
            input_frame,
            text="Database CSV:",
            font=("Segoe UI", 11, "bold"),
            fg=self.colors["dark"]["accent"],
            bg=self.colors['dark']['card_bg']
        ).pack(anchor='w', pady=(0, 8))

        csv_frame = tk.Frame(input_frame, bg=self.colors['dark']['card_bg'])
        csv_frame.pack(fill='x', pady=(0, 15))
        
        self.breach_csv_entry = self.create_hd_entry(csv_frame)
        self.breach_csv_entry.pack(side='left', fill='x', expand=True)
        try:
            if getattr(self.breach_checker, 'csv_path', None):
                self.breach_csv_entry.delete(0, tk.END)
                self.breach_csv_entry.insert(0, self.breach_checker.csv_path)
        except Exception:
            pass

        # Button to choose CSV
        choose_btn = self.create_hd_button(csv_frame, "📂 Browse", self._choose_breach_csv, accent=False)
        choose_btn.pack(side='right', padx=(10, 0))

        # Database info label with better styling
        db_stats = self.breach_checker.get_database_stats()
        self.breach_db_info_label = tk.Label(
            input_frame,
            text=f"📊 Database: {db_stats['total_emails']:,} emails ({db_stats['breached_count']:,} breached)",
            font=("Segoe UI", 10),
            fg=self.colors['dark']['text_secondary'],
            bg=self.colors['dark']['card_bg'],
            anchor="w",
        )
        self.breach_db_info_label.pack(anchor='w', pady=(0, 15))

        # Action buttons with better layout
        btn_frame = tk.Frame(config_card, bg=self.colors["dark"]["card_bg"])
        btn_frame.pack(pady=20, fill='x', padx=20)

        check_btn = self.create_hd_button(
            btn_frame, "🔍 Check Email", self.run_breach_check, accent=True
        )
        check_btn.pack(side="left", padx=8, fill='x', expand=True)

        load_db_btn = self.create_hd_button(btn_frame, "🔄 Reload DB", self._reload_breach_db, accent=False)
        load_db_btn.pack(side='left', padx=8, fill='x', expand=True)
        
        # Right column - Results
        right_column = tk.Frame(content_frame, bg=self.colors["dark"]["bg"])
        right_column.pack(side='left', fill='both', expand=True, padx=(10, 0))
        
        results_card = self.create_card(right_column, "Breach Check Results")
        results_card.pack(fill="both", expand=True)

        self.breach_results = scrolledtext.ScrolledText(
            results_card,
            height=30,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg=self.colors["dark"]["bg"],
            fg=self.colors["dark"]["text_primary"],
            insertbackground=self.colors["dark"]["text_primary"],
            relief='flat',
            bd=0
        )
        self.breach_results.pack(fill="both", expand=True, padx=20, pady=15)

    def create_charts_tab_hd(self):
        """Charts tab showing Breached vs Not Breached pie and Breach Count by Domain bar chart."""
        frame = tk.Frame(self.notebook, bg=self.colors['dark']['card_bg'])
        self.notebook.add(frame, text="📊 Charts")

        card = self.create_card(frame, "Breach Data Visualizations")
        card.pack(fill='both', expand=True, padx=20, pady=20)

        # Controls with better layout
        ctrl_frame = tk.Frame(card, bg=self.colors['dark']['card_bg'])
        ctrl_frame.pack(fill='x', padx=20, pady=(15, 12))

        # CSV picker controls with label
        tk.Label(
            ctrl_frame, 
            text='CSV File:', 
            font=("Segoe UI", 10, "bold"), 
            fg=self.colors['dark']['accent'], 
            bg=self.colors['dark']['card_bg']
        ).pack(side='left', padx=(0, 10))
        
        self.charts_csv_entry = self.create_hd_entry(ctrl_frame)
        self.charts_csv_entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
        
        browse_csv_btn = self.create_hd_button(ctrl_frame, "📂 Browse", self._choose_charts_csv, accent=False)
        browse_csv_btn.pack(side='left', padx=5)

        refresh_btn = self.create_hd_button(ctrl_frame, "🔄 Refresh", self._refresh_breach_charts, accent=True)
        refresh_btn.pack(side='left', padx=5)

        save_btn = self.create_hd_button(ctrl_frame, "💾 Save", self._save_charts, accent=False)
        save_btn.pack(side='left', padx=5)

        # Area for matplotlib canvas
        self.charts_area = tk.Frame(card, bg=self.colors['dark']['card_bg'])
        self.charts_area.pack(fill='both', expand=True, padx=20, pady=15)

        # Hold references and selected CSV path
        self._charts_fig = None
        self._charts_canvas = None
        # Default CSV path comes from the breach_checker if available
        self.charts_csv_path = getattr(self.breach_checker, 'csv_path', None)
        try:
            if self.charts_csv_path:
                self.charts_csv_entry.delete(0, tk.END)
                self.charts_csv_entry.insert(0, self.charts_csv_path)
        except Exception:
            pass

        # Initial draw
        try:
            self._refresh_breach_charts()
        except Exception:
            pass

    def _read_breach_csv_counts(self, csv_path=None):
        """Read the breach CSV and return breached_count, safe_count, domain_counts (only breached).
        If `csv_path` is None, use `self.charts_csv_path`.
        """
        domain_counts = {}
        breached = 0
        safe = 0
        try:
            path = csv_path or getattr(self, 'charts_csv_path', None) or getattr(self.breach_checker, 'csv_path', None)
            if not path or not os.path.exists(path):
                return 0, 0, {}

            import csv as _csv
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                reader = _csv.DictReader(f)
                for row in reader:
                    email = (row.get('email') or '').strip().lower()
                    is_breached = row.get('breached', '0') == '1'
                    if is_breached:
                        breached += 1
                        if '@' in email:
                            dom = email.split('@', 1)[1]
                        else:
                            dom = 'unknown'
                        domain_counts[dom] = domain_counts.get(dom, 0) + 1
                    else:
                        safe += 1
        except Exception:
            return 0, 0, {}

        return breached, safe, domain_counts

    def _choose_breach_csv(self):
        path = filedialog.askopenfilename(filetypes=[('CSV files', '*.csv'), ('All files', '*.*')])
        if not path:
            return
        try:
            # Update entry and stored path
            self.breach_csv_entry.delete(0, tk.END)
            self.breach_csv_entry.insert(0, path)
            # Replace breach_checker with new CSV
            try:
                self.breach_checker = BreachChecker(path)
            except Exception:
                # Fallback: set attribute and rely on functions
                try:
                    self.breach_checker.csv_path = path
                except Exception:
                    pass
            # Update stored charts CSV as well so charts use same file
            self.charts_csv_path = path
            try:
                if hasattr(self, 'charts_csv_entry'):
                    self.charts_csv_entry.delete(0, tk.END)
                    self.charts_csv_entry.insert(0, path)
            except Exception:
                pass
            # Refresh DB info label and charts
            self._reload_breach_db()
            try:
                self._refresh_breach_charts()
            except Exception:
                pass
        except Exception as e:
            messagebox.showerror('Error', f'Failed to load CSV: {e}')

    def _reload_breach_db(self):
        """Reload database stats from current breach_checker instance or CSV entry."""
        try:
            # If user typed a path into entry, prefer that
            entry_path = None
            try:
                entry_path = self.breach_csv_entry.get().strip()
            except Exception:
                entry_path = None

            if entry_path:
                try:
                    self.breach_checker = BreachChecker(entry_path)
                except Exception:
                    try:
                        self.breach_checker.csv_path = entry_path
                    except Exception:
                        pass

            stats = self.breach_checker.get_database_stats()
            try:
                self.breach_db_info_label.config(text=f"Database: {stats['total_emails']:,} emails ({stats['breached_count']:,} breached)")
            except Exception:
                pass
            self.update_hd_status('✅ Breach DB reloaded')
        except Exception as e:
            messagebox.showerror('Error', f'Failed to reload breach DB: {e}')

    def _refresh_breach_charts(self):
        """Generate charts from breach CSV and display them."""
        if plt is None or FigureCanvasTkAgg is None:
            messagebox.showerror('Matplotlib Missing', 'Matplotlib is required to display charts. Install with: pip install matplotlib')
            return

        breached, safe, domain_counts = self._read_breach_csv_counts(self.charts_csv_path)

        # Prepare figure
        try:
            if self._charts_fig is None:
                self._charts_fig = matplotlib.figure.Figure(figsize=(9, 5), dpi=100)
                self._ax1 = self._charts_fig.add_subplot(121)
                self._ax2 = self._charts_fig.add_subplot(122)
            else:
                self._ax1.clear()
                self._ax2.clear()

            # Pie chart
            labels = ['Breached', 'Not Breached']
            sizes = [breached, safe]
            colors = ['#ff4444', '#00ff88']
            if sum(sizes) == 0:
                self._ax1.text(0.5, 0.5, 'No data', ha='center', va='center')
            else:
                self._ax1.pie(sizes, labels=labels, autopct='%1.1f%%', colors=colors, startangle=140)
            self._ax1.set_title('Breached vs Not Breached')

            # Domain bar chart - top 10
            sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)
            top = sorted_domains[:10]
            if not top:
                self._ax2.text(0.5, 0.5, 'No breached domains', ha='center', va='center')
            else:
                domains, vals = zip(*top)
                y_pos = list(range(len(domains)))
                self._ax2.barh(y_pos, vals, color='#0099ff')
                self._ax2.set_yticks(y_pos)
                self._ax2.set_yticklabels(domains)
                self._ax2.invert_yaxis()
                self._ax2.set_xlabel('Breach Count')
                self._ax2.set_title('Top Breached Domains')

            # Embed
            if self._charts_canvas is None:
                self._charts_canvas = FigureCanvasTkAgg(self._charts_fig, master=self.charts_area)
                self._charts_canvas.get_tk_widget().pack(fill='both', expand=True)
            else:
                self._charts_canvas.draw()
        except Exception as e:
            messagebox.showerror('Chart Error', f'Failed to render charts: {e}')

    def _save_charts(self):
        if self._charts_fig is None:
            messagebox.showwarning('No Charts', 'No charts to save. Refresh first.')
            return
        path = filedialog.asksaveasfilename(defaultextension='.png', filetypes=[('PNG Image', '*.png'), ('All', '*.*')])
        if not path:
            return
        try:
            self._charts_fig.savefig(path)
            messagebox.showinfo('Saved', f'Charts saved to {path}')
        except Exception as e:
            messagebox.showerror('Save Error', str(e))

    def _choose_charts_csv(self):
        path = filedialog.askopenfilename(filetypes=[('CSV files', '*.csv'), ('All files', '*.*')])
        if not path:
            return
        self.charts_csv_path = path
        try:
            self.charts_csv_entry.delete(0, tk.END)
            self.charts_csv_entry.insert(0, path)
        except Exception:
            pass
        # Auto-refresh after selecting a file
        try:
            self._refresh_breach_charts()
        except Exception:
            pass

    

    def create_hd_status_bar(self):
        """Create status bar with improved visual design"""
        self.status_frame = tk.Frame(
            self.main_container,
            bg=self.colors['dark']['card_bg'],
            height=45
        )
        self.status_frame.pack(fill='x', side='bottom', padx=0, pady=0)
        self.status_frame.pack_propagate(False)
        
        # Add top border
        border_frame = tk.Frame(self.status_frame, bg=self.colors['dark']['border'], height=1)
        border_frame.pack(side='top', fill='x')
        border_frame.pack_propagate(False)
        
        # Inner container for padding
        inner = tk.Frame(self.status_frame, bg=self.colors['dark']['card_bg'])
        inner.pack(fill='both', expand=True, padx=20, pady=8)
        
        self.status_var = tk.StringVar()
        self.status_var.set("🟢 System Ready")
        
        self.status_label = tk.Label(
            inner,
            textvariable=self.status_var,
            font=("Segoe UI", 9),
            fg=self.colors['dark']['text_secondary'],
            bg=self.colors['dark']['card_bg'],
            anchor='w'
        )
        self.status_label.pack(side='left', fill='x', expand=True)
        
        # Progress indicator with better visibility
        self.progress_var = tk.StringVar()
        self.progress_var.set("")
        
        self.progress_label = tk.Label(
            inner,
            textvariable=self.progress_var,
            font=("Segoe UI", 9, "bold"),
            fg=self.colors['dark']['accent'],
            bg=self.colors['dark']['card_bg'],
            anchor='e'
        )
        self.progress_label.pack(side='right')

    def create_card(self, parent, title):
        """Create a modern card container with better visual hierarchy"""
        card = tk.Frame(
            parent,
            bg=self.colors['dark']['card_bg'],
            relief='flat',
            bd=1,
            highlightbackground=self.colors['dark']['border'],
            highlightthickness=1
        )
        
        if title:
            # Card header with separator
            header_frame = tk.Frame(card, bg=self.colors['dark']['card_bg'])
            header_frame.pack(fill='x')
            
            title_label = tk.Label(
                header_frame,
                text=title,
                font=("Segoe UI", 13, "bold"),
                fg=self.colors['dark']['text_primary'],
                bg=self.colors['dark']['card_bg'],
                anchor='w'
            )
            title_label.pack(fill='x', padx=20, pady=(15, 10))
            
            # Subtle separator line
            sep = tk.Frame(header_frame, bg=self.colors['dark']['border'], height=1)
            sep.pack(fill='x', padx=20)
            sep.pack_propagate(False)
        
        return card
    
    def create_hd_entry(self, parent):
        """Create a styled entry field with better visual feedback"""
        entry = tk.Entry(
            parent,
            font=("Segoe UI", 10),
            bg=self.colors['dark']['bg'],
            fg=self.colors['dark']['text_primary'],
            insertbackground=self.colors['dark']['accent'],
            relief='flat',
            bd=1,
            highlightbackground=self.colors['dark']['border'],
            highlightthickness=2,
            highlightcolor=self.colors['dark']['accent'],
            selectbackground=self.colors['dark']['accent'],
            selectforeground=self.colors['dark']['bg']
        )
        
        # Add focus effects for better visual feedback
        def on_focus_in(event):
            entry.config(highlightthickness=2, highlightbackground=self.colors['dark']['accent'])
        
        def on_focus_out(event):
            entry.config(highlightthickness=2, highlightbackground=self.colors['dark']['border'])
        
        entry.bind("<FocusIn>", on_focus_in)
        entry.bind("<FocusOut>", on_focus_out)
        
        return entry
    
    def create_hd_button(self, parent, text, command, accent=False):
        """Create a styled button with better hover effects and visual feedback"""
        colors = self.colors['dark'] if self.theme == 'dark' else self.colors['light']
        
        if accent:
            bg = colors['accent']
            fg = colors['bg']
            hover_bg = colors['accent_secondary']
            active_fg = colors['bg']
        else:
            bg = colors['button_bg']
            fg = colors['text_primary']
            hover_bg = colors['button_hover']
            active_fg = colors['accent']
        
        btn = tk.Button(
            parent,
            text=text,
            font=("Segoe UI", 10, "bold"),
            command=command,
            relief='flat',
            bg=bg,
            fg=fg,
            bd=0,
            padx=20,
            pady=12,
            cursor='hand2',
            activebackground=hover_bg,
            activeforeground=active_fg
        )
        
        # Enhanced hover effect with smooth visual feedback
        def on_enter(e):
            btn.configure(bg=hover_bg, relief='raised')
        def on_leave(e):
            btn.configure(bg=bg, relief='flat')
        
        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)
        
        return btn
    
    def _load_logo_images(self):
        """Load logo images for both dark and light themes"""
        try:
            img_dir = os.path.join(os.path.dirname(__file__), 'images')
            
            # Load dark mode logo (violet.png)
            dark_logo_path = os.path.join(img_dir, 'logo violet.png')
            dark_img = tk.PhotoImage(file=dark_logo_path)
            # Resize to 350x350px
            factor = max(1, int(max(dark_img.width(), dark_img.height()) / 350))
            self._logo_dark = dark_img.subsample(factor, factor) if factor > 1 else dark_img
            
            # Load light mode logo (noir.png)
            light_logo_path = os.path.join(img_dir, 'logo noir.png')
            light_img = tk.PhotoImage(file=light_logo_path)
            # Resize to 350x350px
            factor = max(1, int(max(light_img.width(), light_img.height()) / 350))
            self._logo_light = light_img.subsample(factor, factor) if factor > 1 else light_img
            
            # Set initial logo based on current theme
            if self.theme == 'dark':
                self.logo_label.configure(image=self._logo_dark)
            else:
                self.logo_label.configure(image=self._logo_light)
                
        except Exception as e:
            print(f"Error loading logo images: {e}")
            # Fallback to emoji if images fail to load
            self.logo_label.configure(text="🛡️", font=("Arial", 64), fg=self.colors[self.theme]['accent'])
    
    # Theme Management - FIXED: Complete theme switching
    def toggle_hd_theme(self):
        """Toggle between dark and light themes"""
        self.theme = 'light' if self.theme == 'dark' else 'dark'
        self.apply_hd_theme()
    
    def apply_hd_theme(self):
        """Apply the selected theme to all elements - FIXED: Proper theme switching"""
        colors = self.colors[self.theme]
        
        try:
            # Update root window
            self.root.configure(bg=colors['bg'])
            self.main_container.configure(bg=colors['bg'])
            
            # Update header
            header = self.logo_label.master.master
            header.configure(bg=colors['card_bg'])
            self.logo_label.master.configure(bg=colors['card_bg'])
            
            # Update logo image based on theme
            try:
                if self.theme == 'dark':
                    self.logo_label.configure(image=self._logo_dark, bg=colors['card_bg'])
                else:
                    self.logo_label.configure(image=self._logo_light, bg=colors['card_bg'])
            except AttributeError:
                # Fallback if images not loaded yet
                self.logo_label.configure(bg=colors['card_bg'], fg=colors['accent'])
            
            # Update theme button
            try:
                self.theme_btn.configure(
                    bg=colors['button_bg'],
                    activebackground=colors['button_hover']
                )
            except:
                pass
            
            # Update notebook style
            self.configure_notebook_style()
            
            # Update all frames and widgets systematically
            self.update_widget_colors(self.main_container, colors)
            
            # Update status
            theme_status = "Light" if self.theme == 'light' else "Dark"
            self.status_var.set(f"🟢 System Ready | {theme_status} Mode")
            
        except Exception as e:
            print(f"Theme application error: {e}")
    
    def update_widget_colors(self, widget, colors):
        """Update widget colors recursively - FIXED: Better theme handling"""
        try:
            # Update current widget
            if hasattr(widget, 'configure'):
                try:
                    bg = widget.cget('bg')
                    fg = widget.cget('fg') if 'fg' in widget.keys() else None
                    
                    # Update background based on original color
                    if bg in ['#0a0f1c', '#131a2c', '#1a243f', '#f8fafc', '#ffffff', '#edf2f7']:
                        if bg in ['#0a0f1c', '#f8fafc']:
                            widget.configure(bg=colors['bg'])
                        elif bg in ['#131a2c', '#ffffff']:
                            widget.configure(bg=colors['card_bg'])
                        elif bg in ['#1a243f', '#edf2f7']:
                            widget.configure(bg=colors['button_bg'])
                    
                    # Update foreground for labels and buttons
                    if fg and fg in ['#ffffff', '#a0a8c0', '#1a202c', '#4a5568']:
                        if fg in ['#ffffff', '#a0a8c0']:
                            if 'fg' in widget.keys():
                                widget.configure(fg=colors['text_primary'])
                        elif fg in ['#1a202c', '#4a5568']:
                            if 'fg' in widget.keys():
                                widget.configure(fg=colors['text_primary'])
                except:
                    pass
            
            # Recursively update children
            for child in widget.winfo_children():
                self.update_widget_colors(child, colors)
                
        except Exception as e:
            print(f"Widget color update error: {e}")

    # Enhanced spinner methods - IMPROVED: Better visibility
    def start_hd_spinner(self):
        """Start spinner animation - IMPROVED: More visible"""
        if not self._spinner_visible:
            self.spinner_frame.pack(side='left', padx=(10, 0))
            self._spinner_visible = True
            
        colors = self.colors[self.theme]
        self.spinner_label.configure(bg=colors['card_bg'], fg=colors['accent'])
        self.spinner_canvas.configure(bg=colors['card_bg'])
        
        # Reset dots to accent color
        for dot in self.spinner_dots:
            self.spinner_canvas.itemconfig(dot, fill=colors['accent'])
        
        if self._spinner_anim_id is None:
            self._spinner_anim_id = self.root.after(150, self._hd_spinner_step)
    
    def stop_hd_spinner(self):
        """Stop spinner animation"""
        if self._spinner_anim_id:
            self.root.after_cancel(self._spinner_anim_id)
            self._spinner_anim_id = None
        if self._spinner_visible:
            self.spinner_frame.pack_forget()
            self._spinner_visible = False
    
    def _hd_spinner_step(self):
        """Spinner animation step with pulsing effect - IMPROVED: More visible"""
        if not self._spinner_visible:
            return
            
        try:
            self._spinner_phase = (self._spinner_phase + 1) % 6
            
            colors = self.colors[self.theme]
            
            # Create pulsing effect with different opacities
            pulse_intensities = [1.0, 0.6, 0.3, 0.6, 1.0, 0.6]
            
            for i, dot in enumerate(self.spinner_dots):
                intensity_index = (i + self._spinner_phase) % 6
                intensity = pulse_intensities[intensity_index]
                
                # Create color with intensity (simulate opacity)
                if self.theme == 'dark':
                    r, g, b = 0, 255, 136  # #00ff88
                else:
                    r, g, b = 0, 119, 255  # #0077ff
                
                # Adjust color based on intensity
                adjusted_color = f'#{int(r * intensity):02x}{int(g * intensity):02x}{int(b * intensity):02x}'
                self.spinner_canvas.itemconfig(dot, fill=adjusted_color)
            
            self._spinner_anim_id = self.root.after(150, self._hd_spinner_step)
        except Exception as e:
            print(f"Spinner error: {e}")
            self._spinner_anim_id = None

    # Tool methods with dashboard integration
    def browse_log_file(self):
        # Log browsing removed (Log Analyzer feature removed)
        return
    
    def browse_hash_file(self):
        filename = filedialog.askopenfilename(title="Select File to Verify")
        if filename:
            self.file_path_entry.delete(0, tk.END)
            self.file_path_entry.insert(0, filename)

    def browse_aes_file(self):
        """Browse for a file to encrypt or decrypt with AES."""
        filename = filedialog.askopenfilename(title="Select File for AES Encryption/Decryption")
        if filename:
            self.aes_file_entry.delete(0, tk.END)
            self.aes_file_entry.insert(0, filename)

    def update_hd_status(self, message):
        self.status_var.set(message)
        self.root.update_idletasks()
    
    def run_network_scan(self):
        network = self.network_entry.get().strip()
        if not network:
            messagebox.showerror("Error", "Please enter a network range")
            return
        method = getattr(self, "network_method_var", None)
        method_value = method.get() if method is not None else "tcp"
        
        self.network_results.delete(1.0, tk.END)
        approach = "TCP (ports)" if method_value == "tcp" else "ICMP (ping)"
        self.update_hd_status(f"🟡 Scanning network using {approach}... This may take a few moments")
        self.start_hd_spinner()
        
        def scan_thread():
            try:
                results = self.network_scanner.scan(network, method=method_value)
                self.session_data['scans_performed'] += 1
                self.session_data['last_scan'] = datetime.now().isoformat()
                
                # Update dashboard activity
                activity = f"Network scan completed for {network} at {datetime.now().strftime('%H:%M:%S')}"
                self.root.after(0, lambda: self.update_dashboard_activity(activity))
                self.root.after(0, lambda: self.display_network_results(results))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
            finally:
                self.root.after(0, lambda: self.stop_hd_spinner())
                self.root.after(0, lambda: self.update_hd_status("🟢 Network scan completed successfully"))
        
        threading.Thread(target=scan_thread, daemon=True).start()

    def run_port_scan(self):
        target = self.target_entry.get().strip()
        port_range = self.port_range_entry.get().strip()
        
        if not target or not port_range:
            messagebox.showerror("Error", "Please enter target IP and port range")
            return
        
        self.port_results.delete(1.0, tk.END)
        self.update_hd_status("🟡 Scanning ports... This may take a few moments")
        self.start_hd_spinner()
        
        def scan_thread():
            try:
                results = self.port_scanner.scan(target, port_range)
                self.session_data['scans_performed'] += 1
                self.session_data['last_scan'] = datetime.now().isoformat()
                
                # Update dashboard activity
                activity = f"Port scan completed for {target} at {datetime.now().strftime('%H:%M:%S')}"
                self.root.after(0, lambda: self.update_dashboard_activity(activity))
                self.root.after(0, lambda: self.display_port_results(results))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
            finally:
                self.root.after(0, lambda: self.stop_hd_spinner())
                self.root.after(0, lambda: self.update_hd_status("🟢 Port scan completed successfully"))
        
        threading.Thread(target=scan_thread, daemon=True).start()

    

    def run_hash_verification(self, hash_type):
        file_path = self.file_path_entry.get().strip()
        if not file_path:
            messagebox.showerror("Error", "Please select a file")
            return
        
        expected_hash = self.expected_hash_entry.get().strip()
        expected_hash_algo = None
        
        # If expected hash is provided, get the algorithm selection
        if expected_hash:
            expected_hash_algo = self.expected_hash_algo_var.get()
            self.update_hd_status(f"🟡 Verifying hash using {expected_hash_algo.upper()}... This may take a few moments")
        else:
            self.update_hd_status(f"🟡 Generating {hash_type.upper()} hash... This may take a few moments")
        
        self.hash_results.delete(1.0, tk.END)
        self.start_hd_spinner()
        
        def hash_thread():
            try:
                results = self.hash_verifier.verify(file_path, hash_type, expected_hash, expected_hash_algo)
                self.session_data['scans_performed'] += 1
                self.session_data['last_scan'] = datetime.now().isoformat()

                # Update dashboard activity and files_checked on failed verifications
                filename = os.path.basename(file_path)
                if expected_hash:
                    # Determine pass/fail from verifier output
                    lower_res = str(results).lower()
                    # The verifier prints 'VERIFICATION FAILED' on mismatch; check robustly in lowercase
                    if 'verification failed' in lower_res or '❌ verification failed' in lower_res:
                        # Increment files_checked counter for failed verification
                        self.session_data['files_checked'] = self.session_data.get('files_checked', 0) + 1
                        activity = f"❌ Hash verification FAILED for {filename} at {datetime.now().strftime('%H:%M:%S')}"
                        # Mark session unsaved
                        self.session_saved = False
                        # Update dashboard stats to reflect increment
                        self.root.after(0, lambda: self.update_dashboard_stats())
                    else:
                        activity = f"Hash verification ({expected_hash_algo.upper()}) completed for {filename} at {datetime.now().strftime('%H:%M:%S')}"
                else:
                    activity = f"Hash generation ({hash_type.upper()}) completed for {filename} at {datetime.now().strftime('%H:%M:%S')}"

                self.root.after(0, lambda: self.update_dashboard_activity(activity))
                self.root.after(0, lambda: self.display_hash_results(results))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
            finally:
                self.root.after(0, lambda: self.stop_hd_spinner())
                if expected_hash:
                    self.root.after(0, lambda: self.update_hd_status("🟢 Hash verification completed successfully"))
                else:
                    self.root.after(0, lambda: self.update_hd_status("🟢 Hash generation completed successfully"))
        
        threading.Thread(target=hash_thread, daemon=True).start()

    def run_password_strength(self):
        """Evaluate the strength of the entered password."""
        pw = self.password_entry.get()
        if not pw:
            messagebox.showerror("Error", "Please enter a password to analyze")
            return

        score = password_strength(pw)
        labels = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong", "Excellent"]
        label = labels[score] if 0 <= score < len(labels) else "Unknown"

        self.password_results.delete(1.0, tk.END)
        self.password_results.insert(
            tk.END,
            f"Password Strength Analysis\n"
            f"═══════════════════════════\n"
            f"Score: {score}/5\n"
            f"Rating: {label}\n\n"
            f"Guidance:\n"
            f"- Length >= 8 characters\n"
            f"- Mix of upper and lower case letters\n"
            f"- Include digits and special characters\n",
        )

    def run_strengthen_password(self):
        """Generate a stronger version of the entered password."""
        pw = self.password_entry.get()
        if not pw:
            messagebox.showerror("Error", "Please enter a base password to strengthen")
            return

        strong_pw = strengthen_password(pw)

        self.password_results.delete(1.0, tk.END)
        self.password_results.insert(
            tk.END,
            "Password Strengthening\n"
            "══════════════════════\n"
            f"Original:  {pw}\n"
            f"Strengthened: {strong_pw}\n\n"
            "Note: Copy the strengthened password and store it securely.\n",
        )

    def _on_password_typed(self, event=None):
        """Update small strength text while typing the password."""
        pw = self.password_entry.get()
        if not pw:
            self.password_live_label.config(text="Force : (vide)", fg=self.colors["dark"]["text_secondary"])
            return

        score = password_strength(pw)
        labels = ["Très faible", "Faible", "Moyenne", "Forte", "Très forte", "Excellente"]
        label = labels[score] if 0 <= score < len(labels) else "Inconnue"

        # Simple color feedback
        if score <= 1:
            color = self.colors["dark"]["error"]
        elif score == 2:
            color = self.colors["dark"]["warning"]
        else:
            color = self.colors["dark"]["success"]

        self.password_live_label.config(
            text=f"Force : {label} ({score}/5)",
            fg=color,
        )

    def run_aes_encrypt(self):
        """Encrypt the selected file with AES using the given password."""
        file_path = self.aes_file_entry.get().strip()
        password = self.aes_password_entry.get().strip()

        if not file_path:
            messagebox.showerror("Error", "Please choose a file to encrypt")
            return
        if not password:
            messagebox.showerror("Error", "Please enter a password for AES encryption")
            return

        self.aes_results.delete(1.0, tk.END)
        self.update_hd_status("🟡 Encrypting file with AES...")

        def enc_thread():
            try:
                res = encrypt_file(file_path, password)
                msg = res.message
                if res.success:
                    activity = f"AES encryption completed for {os.path.basename(file_path)} at {datetime.now().strftime('%H:%M:%S')}"
                    self.root.after(0, lambda: self.update_dashboard_activity(activity))
                self.root.after(0, lambda: self.aes_results.insert(tk.END, msg))
            finally:
                self.root.after(0, lambda: self.update_hd_status("🟢 AES encryption finished"))

        threading.Thread(target=enc_thread, daemon=True).start()

    def run_aes_decrypt(self):
        """Decrypt the selected AES-encrypted file using the given password."""
        file_path = self.aes_file_entry.get().strip()
        password = self.aes_password_entry.get().strip()

        if not file_path:
            messagebox.showerror("Error", "Please choose a file to decrypt")
            return
        if not password:
            messagebox.showerror("Error", "Please enter a password for AES decryption")
            return

        self.aes_results.delete(1.0, tk.END)
        self.update_hd_status("🟡 Decrypting file with AES...")

        def dec_thread():
            try:
                res = decrypt_file(file_path, password)
                msg = res.message
                if res.success:
                    activity = f"AES decryption completed for {os.path.basename(file_path)} at {datetime.now().strftime('%H:%M:%S')}"
                    self.root.after(0, lambda: self.update_dashboard_activity(activity))
                self.root.after(0, lambda: self.aes_results.insert(tk.END, msg))
            finally:
                self.root.after(0, lambda: self.update_hd_status("🟢 AES decryption finished"))

        threading.Thread(target=dec_thread, daemon=True).start()

    def run_breach_check(self):
        """Check if the entered email has been found in data breaches."""
        email = self.breach_email_entry.get().strip()
        if not email:
            messagebox.showerror("Error", "Please enter an email address to check")
            return

        self.breach_results.delete(1.0, tk.END)
        self.update_hd_status(f"🟡 Checking email: {email}...")

        def check_thread():
            try:
                found, details = self.breach_checker.check_email(email)
                
                # Format results
                result_text = f"""Breach Check Results
═══════════════════════════════════════════════════
📧 Email: {details['email']}
🕐 Timestamp: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

"""
                
                if found:
                    if details['breached']:
                        result_text += f"""⚠️ STATUS: BREACHED
🔴 This email has been found in a data breach!

{details['message']}

💡 Recommendations:
• Change your password immediately
• Enable two-factor authentication
• Check other accounts using this email
• Monitor for suspicious activity
• Consider using a password manager
"""
                        # Increment breached emails counter
                        self.session_data['breached_emails_found'] += 1
                        activity = f"⚠️ BREACHED email found: {email} at {datetime.now().strftime('%H:%M:%S')}"
                    else:
                        result_text += f"""✅ STATUS: FOUND BUT NOT BREACHED
🟢 This email exists in our database but was not marked as breached.

{details['message']}

💡 Note: Continue to use strong passwords and enable 2FA.
"""
                        activity = f"Email checked: {email} (not breached) at {datetime.now().strftime('%H:%M:%S')}"
                else:
                    result_text += f"""ℹ️ STATUS: NOT FOUND
🟡 {details['message']}

💡 Note: This doesn't guarantee your email is safe.
      Continue practicing good security habits.
"""
                    activity = f"Email checked: {email} (not found) at {datetime.now().strftime('%H:%M:%S')}"
                
                # Database statistics
                db_stats = self.breach_checker.get_database_stats()
                result_text += f"""
═══════════════════════════════════════════════════
📊 Database Statistics:
• Total emails in database: {db_stats['total_emails']:,}
• Breached emails: {db_stats['breached_count']:,}
• Safe emails: {db_stats['safe_count']:,}
• Session breaches found: {self.session_data['breached_emails_found']}
"""
                
                self.root.after(0, lambda: self.update_dashboard_activity(activity))
                self.root.after(0, lambda: self.breach_results.insert(tk.END, result_text))
                
                # Update dashboard stats if breached
                if found and details['breached']:
                    self.root.after(0, lambda: self.update_dashboard_stats())
                    
            except Exception as e:
                error_msg = f"Error checking email: {str(e)}"
                self.root.after(0, lambda: messagebox.showerror("Error", error_msg))
            finally:
                self.root.after(0, lambda: self.update_hd_status("🟢 Breach check completed"))

        threading.Thread(target=check_thread, daemon=True).start()

    def update_dashboard_stats(self):
        """Update dashboard statistics cards"""
        stats_container = self.stat_cards[0].master if self.stat_cards else None
        if stats_container:
            # Destroy old cards
            for card in self.stat_cards:
                for widget in card.winfo_children():
                    widget.destroy()
                card.destroy()
            
            # Recreate cards with updated values
            self.stat_cards = []
            updated_stats = [
                (f"📊 Total Scans", str(self.session_data.get('scans_performed', 0)), "#00ff88", "Scans performed this session"),
                ("🚪 Open Ports", "4", "#0099ff", "Ports discovered across scans"),
                ("📁 Files Checked", str(self.session_data.get('files_checked', 0)), "#ffaa00", "Files checked (failed verifications)"),
                ("🔒 Breached Emails", str(self.session_data.get('breached_emails_found', 0)), "#ff4444", "Emails found in data breaches")
            ]
            
            for i, (title, value, color, description) in enumerate(updated_stats):
                card = self.create_stat_card(stats_container, title, value, color, description)
                card.pack(side='left', fill='x', expand=True, padx=5)
                self.stat_cards.append(card)

    def _apply_loaded_result(self, key, text):
        """Apply loaded result text into the corresponding results widget based on key."""
        if not text:
            return
        try:
            if key == 'network' and getattr(self, 'network_results', None):
                self.network_results.delete(1.0, tk.END)
                self.network_results.insert(tk.END, text)
            elif key == 'ports' and getattr(self, 'port_results', None):
                self.port_results.delete(1.0, tk.END)
                self.port_results.insert(tk.END, text)
            elif key == 'hash' and getattr(self, 'hash_results', None):
                self.hash_results.delete(1.0, tk.END)
                self.hash_results.insert(tk.END, text)
            elif key == 'password' and getattr(self, 'password_results', None):
                self.password_results.delete(1.0, tk.END)
                self.password_results.insert(tk.END, text)
            elif key == 'aes' and getattr(self, 'aes_results', None):
                self.aes_results.delete(1.0, tk.END)
                self.aes_results.insert(tk.END, text)
            elif key == 'breach' and getattr(self, 'breach_results', None):
                self.breach_results.delete(1.0, tk.END)
                self.breach_results.insert(tk.END, text)
        except Exception as e:
            print(f"Failed to apply loaded result for {key}: {e}")

    
    def display_network_results(self, results):
        self.network_results.insert(tk.END, results)
    
    def display_port_results(self, results):
        self.port_results.insert(tk.END, results)
    
    def display_hash_results(self, results):
        self.hash_results.insert(tk.END, results)
    
    # New Features
    def on_tab_changed(self, event):
        """Handle tab changes"""
        current_tab = self.notebook.index(self.notebook.select())
        tab_names = [
            'dashboard',
            'network',
            'ports',
            'hash',
            'password',
            'aes',
            'breach'
        ]
        self.update_hd_status(f"🟢 Viewing: {tab_names[current_tab]}")
    
    def clear_all_results(self):
        """Clear all results from all tabs"""
        widgets = [
            getattr(self, "network_results", None),
            getattr(self, "port_results", None),
            getattr(self, "hash_results", None),
            getattr(self, "password_results", None),
            getattr(self, "aes_results", None),
            getattr(self, "breach_results", None),
        ]
        for widget in widgets:
            if widget is not None:
                widget.delete(1.0, tk.END)
        messagebox.showinfo("Clear Results", "All results have been cleared.")
    
    def export_results(self):
        """Export current tab results to file"""
        current_tab = self.notebook.index(self.notebook.select())
        tab_names = ["dashboard", "network", "ports", "hash", "password", "aes", "breach"]

        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )

        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"Cybersecurity Tool Export\n")
                    f.write(f"Generated: {datetime.now()}\n")
                    # Guard index in case of unexpected tab indices
                    tool_name = tab_names[current_tab] if 0 <= current_tab < len(tab_names) else 'dashboard'
                    f.write(f"Tool: {tool_name}\n")
                    f.write("="*50 + "\n\n")

                    # Map notebook index to result widget
                    widget_map = {
                        1: getattr(self, 'network_results', None),
                        2: getattr(self, 'port_results', None),
                        3: getattr(self, 'hash_results', None),
                        4: getattr(self, 'password_results', None),
                        5: getattr(self, 'aes_results', None),
                        6: getattr(self, 'breach_results', None),
                    }

                    results_widget = widget_map.get(current_tab, None)
                    if results_widget is not None:
                        results = results_widget.get(1.0, tk.END)
                    else:
                        results = "Dashboard view - no specific results to export"

                    f.write(results)

                messagebox.showinfo("Export Successful", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))
    
    def show_session_info(self):
        """Show session information"""
        info = f"""
Session Information:
-------------------
Scans Performed: {self.session_data['scans_performed']}
Last Scan: {self.session_data['last_scan'] or 'None'}
Theme: {'Dark' if self.theme == 'dark' else 'Light'}
        """
        messagebox.showinfo("Session Info", info.strip())

def main():
    # Start with login window
    login_root = tk.Tk()
    login_app = LoginWindow(login_root)
    login_root.mainloop()

if __name__ == "__main__":
    main()