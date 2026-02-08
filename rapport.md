# Defensive Cybersecurity Tools Documentation

This report provides a clear, explanatory overview of the security tools included in the multi-tool application. It explains the purpose, internal logic, and specific functions of each tool to help users understand how they operate.

---

## 1. AES Encryption/Decryption (`aes_tool.py`)

**Purpose**: Secures files and folders using industry-standard AES-256-GCM encryption.

**How it Works**:
The tool uses a password-based mechanism to protect data. When you encrypt a file, the system generates a random "salt" and uses it with your password to derive a high-security 256-bit key. The actual encryption uses AES-GCM, which provides "authenticated encryption"—ensuring both confidentiality and integrity.

**Key Functions**:
- `_derive_key(password, salt)`: Uses PBKDF2 with 200,000 iterations to turn a user password into a secure 256-bit encryption key.
- `_zip_folder(folder_path, zip_path)`: Compresses an entire directory into a temporary ZIP archive so it can be encrypted as a single file.
- `encrypt_file(input_path, password, is_folder)`: The main entry point for encryption. It handles folder zipping, key derivation, and the AES-GCM encryption process.
- `decrypt_file(input_path, password, output_path)`: Reverses the encryption. It verifies the authentication tag to ensure the file hasn't been tampered with and automatically extracts folders if they were zipped.

---

## 2. Breach Checker (`breach_checker.py`)

**Purpose**: Identifies if an email address has been compromised in known data breaches.

**How it Works**:
The tool interacts with a local CSV database. It searches for a normalized version of the user's email and checks for a 'breached' status flag.

**Key Functions**:
- `_load_statistics()`: Scans the entire local database once on startup to calculate total records and how many are marked as breached.
- `check_email(email)`: Performs a case-insensitive search through the database to find if the specific email exists and whether it has been compromised.
- `get_database_stats()`: Returns the pre-calculated statistics (total, safe, and breached counts) for display in the UI.

---

## 3. Hash Verifier (`hash_verifier.py`)

**Purpose**: Validates the integrity of files by calculating unique digital fingerprints (hashes).

**How it Works**:
The verifier reads files in chunks to remain memory-efficient and supports multiple algorithms like MD5, SHA-1, SHA-256, and SHA-512.

**Key Functions**:
- `calculate_hash(file_path, hash_type)`: Reads a file in 64KB chunks and updates a hash object to generate a final unique hexadecimal string.
- `get_file_info(file_path)`: Retrieves OS-level metadata about the file, such as its size, creation date, and permissions.
- `verify(file_path, hash_type, expected_hash)`: Orchestrates the full verification process, comparing a calculated hash against a user-provided one and generating a detailed pass/fail report.

---

## 4. Hidden File Finder (`hidden_file_finder.py`)

**Purpose**: Scans your system to locate files and folders that are hidden from normal view.

**How it Works**:
The tool uses cross-platform logic: dot-prefixed filenames for Unix/macOS and system attribute flags for Windows.

**Key Functions**:
- `_is_hidden_unix(name)`: A quick check to see if a filename starts with a dot, which is the standard way to hide files on Linux and macOS.
- `_is_hidden_windows(full_path)`: Uses the Windows `ctypes` API to check for the `FILE_ATTRIBUTE_HIDDEN` flag on the filesystem level.
- `find_hidden_files(root_path, recursive)`: Traverses the directory tree (optionally including all subfolders) and builds a list of every item identified as hidden.
- `format_hidden_results(result)`: Takes the list of hidden paths and cleans them up into a professional, human-readable report.

---

## 5. Network Scanner (`network_scanner.py`)

**Purpose**: Discovers active devices on a network and identifies their basic information.

**How it Works**:
The scanner uses multi-threading to quickly test a range of IP addresses using both TCP connection attempts and ICMP pings.

**Key Functions**:
- `_ping_host_tcp(ip)`: Attempts to connect to common ports (like 80 or 443). If any port responds, the host is marked as active.
- `_ping_host_icmp(ip)`: Sends a standard network "ping" request. This is used as a backup if a device has all its ports closed but is still online.
- `get_host_info(ip, mac)`: Resolves a device's hostname via DNS or NetBIOS and looks up the hardware manufacturer in a built-in vendor database.
- `get_mac_address(ip)`: Uses the ARP table to find the unique hardware address of a device on the local network.
- `scan(network_range, method)`: The main engine that manages the thread pool and coordinates the discovery of all hosts in a CIDR range (e.g., 192.168.1.0/24).

---

## 6. Password Tool (`password.py`)

**Purpose**: Evaluates password strength and provides suggestions for improvement.

**How it Works**:
It uses a scoring system based on character variety and length, and can auto-generate stronger versions of weak passwords.

**Key Functions**:
- `password_strength(pw)`: Analyzes a string for length and the presence of uppercase, lowercase, numbers, and symbols, returning a score from 0 to 5.
- `strengthen_password(pw)`: Takes an existing password and applies random transformations—like leet speak substitution and length enforcement—to make it significantly more secure.

---

## 7. Port Scanner (`port_scanner.py`)

**Purpose**: Checks a specific host to see which services (like web or email) are accessible.

**How it Works**:
The scanner tests a range of ports in parallel, identifying open services and attempting to extract version information from them.

**Key Functions**:
- `scan_port(target, port)`: Attempts a low-level TCP connection to a single port and records if it is "Open" or "Closed."
- `grab_banner(sock, port)`: Once a port is found to be open, this function tries to read a "welcome message" from the service to identify its software version.
- `parse_port_range(port_range)`: Converts user input (like "80-443" or "21,22") into a clean list of individual port numbers for the scanner to test.
- `scan(target, port_range)`: Coordinates the parallel scanning of the target host and generates a security report highlighting potentially dangerous open ports.

---

## 8. Steganography Tool (`steganography.py`)

**Purpose**: Hides secret text messages inside ordinary images without changing their appearance.

**How it Works**:
The tool uses "Least Significant Bit" (LSB) encoding, subtly shifting the color of pixels to store binary data.

**Key Functions**:
- `_str_to_bin(message)`: Converts a text message and its end-of-file marker into a long string of 0s and 1s.
- `_bin_to_str(binary_str)`: Reverses the process, taking binary data and reconstructing the original text characters.
- `hide_message(image_path, message, output_path)`: Loads an image, modifies the lowest bits of its red, green, and blue channels to store the binary message, and saves it as a lossless PNG.
- `extract_message(image_path)`: Scans every pixel of an image to pull out the LSBs and reconstruct the hidden secret message.

---

## 9. Session Management & History

**Purpose**: Allows users to save their progress, track recent activities, and manage multiple security sessions.

**How it Works**:
The application tracks all tool executions in a session object. This data can be persisted to disk as a JSON file, allowing you to load your results later. A separate persistent history file keeps a permanent log of all actions across different sessions.
**Key Functions & Storage Details**:

- `append_to_history(activity)`: Appends a single activity record to a persistent history file. The file is named `history.json` and is stored in the same directory as `main.py` (the path is produced by a helper `_history_file_path()` which uses `os.path.dirname(__file__)`). Each record is a small object with a timestamp and the activity text, for example:

```json
{
	"timestamp": "2026-02-08T12:34:56.789012",
	"activity": "Started network scan 192.168.1.0/24"
}
```

The function reads the existing file (if present) via `load_history()`, inserts the new record at the front of the list, and then writes the updated list back to `history.json` using `json.dump`. `load_history()` returns an empty list on read errors or if the file is absent. `clear_history()` deletes `history.json` after a user confirmation dialog.

- `save_session()`: Lets the user pick a destination filename (via a save dialog). It collects the current session metadata and visible results from each tab (the ScrolledText widgets) and writes a JSON object. The default suggested filename is `session_YYYYMMDD_HHMMSS.json` but the user may choose any path. Important fields written include:

```json
{
	"timestamp": "2026-02-08T12:34:56.789012",
	"scans_performed": 3,
	"last_scan": null,
	"recent_activities": ["Started scan...", "Found host 192.168.1.10"],
	"breached_emails_found": 0,
	"files_checked": 4,
	"results": {
		"network": "...text dumped from network results scrolled text...",
		"ports": "...text dumped from port results...",
		"hash": "...",
		"password": "...",
		"aes": "...",
		"breach": "..."
	}
}
```

Each `results` value is saved as the plain string captured from the UI widget (the code uses `.get(1.0, tk.END)` on each ScrolledText result widget). Because this is plain JSON, you can inspect or edit it with any text editor.

- `load_session()`: Prompts the user to open a previously saved JSON session file. After reading it, the application:
	- Restores counters such as `scans_performed`, `breached_emails_found`, and `files_checked` into the in-memory `session_data`.
	- Replaces the in-UI `recent_activities` list and repopulates the dashboard activity ScrolledText.
	- Updates the `stats_label` and any stat cards to reflect loaded values.
	- If `results` are present in the JSON, the loader will write those strings back into the corresponding result widgets (when the widget exists), which repopulates each tool tab with the saved output text.

`load_session()` sets the session as saved (`session_saved = True`) after a successful load.

**Storage format summary**:

- History: a JSON array stored in `history.json` next to `main.py`. Each element is an object with `timestamp` and `activity`.
- Sessions: user-chosen JSON files containing an object with metadata fields (`timestamp`, `scans_performed`, `last_scan`, etc.) and a `results` map of raw strings for each tab.
