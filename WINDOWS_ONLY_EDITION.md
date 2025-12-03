# Python Hacking Course - WINDOWS ONLY Edition

## ⚠️ Important: Windows-Specific Setup

This adapted version of the course is optimized for **Windows 10/11 systems** with no external tools or Linux VMs required.

---

## What You Need on Windows

### Minimum Requirements
```
- Windows 10 (Build 19041+) or Windows 11
- 8GB RAM minimum (16GB recommended)
- 50GB free disk space
- Python 3.9+
- Internet connection
```

### NO Linux, NO VirtualBox, NO Docker required!

---

## Installation for Windows

### Step 1: Install Python 3.9+

```powershell
# Download from: https://www.python.org/downloads/
# Choose: Windows installer (64-bit)
# Important: Check "Add Python to PATH" during installation

# Verify installation:
python --version
pip --version
```

### Step 2: Create Virtual Environment

```powershell
# Open PowerShell as Administrator
cd C:\Users\YourUsername\Documents

# Create course directory
mkdir python-hacking-course
cd python-hacking-course

# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1

# If you get execution policy error, run:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Step 3: Install Windows-Only Requirements

```powershell
# Create requirements-windows.txt with these packages:
pip install requests
pip install beautifulsoup4
pip install pycryptodome
pip install cryptography
pip install colorama
```

### Step 4: Install Development Tools

**Visual Studio Code** (Recommended):
```powershell
# Download from: https://code.microsoft.com/
# Or via Winget:
winget install Microsoft.VisualStudioCode
```

**Git for Windows**:
```powershell
winget install Git.Git
# Or download: https://git-scm.com/download/win
```

**Optional Tools** (for advanced modules):
```powershell
# Wireshark (packet analysis):
winget install Wireshark.Wireshark

# 7-Zip (file extraction):
winget install 7zip.7zip

# Notepad++ (text editor):
winget install Notepad++.Notepad++
```

---

## Windows-Specific Module Adaptations

### Module 1: Python Security Basics
**No changes needed** - All socket code works on Windows

```python
# Python socket programming works identically on Windows
import socket

def tcp_client_windows(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    response = sock.recv(1024)
    sock.close()
    return response
```

### Module 2: Networking Fundamentals
**Adapted for Windows** - Use Windows-compatible tools

```python
# Windows DNS lookup
import socket

def windows_dns_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"[+] {domain} -> {ip}")
        return ip
    except socket.gaierror:
        print(f"[-] DNS resolution failed")
        return None

# Windows nslookup alternative in Python
def advanced_dns_lookup(domain):
    import subprocess
    result = subprocess.run(['nslookup', domain], capture_output=True, text=True)
    print(result.stdout)
```

### Module 3: System Memory
**Windows Process Analysis**:

```python
# Windows process memory analysis
import ctypes
from ctypes import wintypes

# Get process handle
def get_process_handle_windows(pid):
    PROCESS_ALL_ACCESS = 0x1F0FFF
    handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    return handle

# Read process memory
def read_process_memory_windows(handle, address, size):
    buffer = ctypes.create_string_buffer(size)
    bytes_read = wintypes.SIZE_T()
    success = ctypes.windll.kernel32.ReadProcessMemory(
        handle, 
        address, 
        buffer, 
        size, 
        ctypes.byref(bytes_read)
    )
    if success:
        return buffer.raw
    return None

# Get process info
def list_processes_windows():
    import subprocess
    result = subprocess.run(['tasklist'], capture_output=True, text=True)
    return result.stdout
```

### Module 4: Exploitation (Windows)
**Windows-Specific Exploits**:

```python
# Windows buffer overflow exploitation
# Note: DEP/ASLR enabled by default on Windows 10/11

import ctypes
import struct

class WindowsExploit:
    """Windows-specific exploitation techniques"""
    
    @staticmethod
    def check_windows_protections():
        """Check what protections are enabled"""
        import subprocess
        
        # Run wmic to get OS info
        result = subprocess.run(
            ['wmic', 'OS', 'get', 'Caption'],
            capture_output=True,
            text=True
        )
        print("[*] Windows Version:")
        print(result.stdout)
        
        # DEP/ASLR enabled by default on Windows 10+
        print("[!] DEP: ENABLED (default)")
        print("[!] ASLR: ENABLED (default)")
        print("[!] CFG: ENABLED on many binaries")
    
    @staticmethod
    def get_windows_process_list():
        """Get running processes"""
        import subprocess
        result = subprocess.run(['tasklist', '/v'], capture_output=True, text=True)
        return result.stdout
    
    @staticmethod
    def find_vulnerable_service():
        """Find potentially vulnerable Windows services"""
        import subprocess
        
        # List services
        result = subprocess.run(['sc', 'query'], capture_output=True, text=True)
        lines = result.stdout.split('\n')
        
        services = []
        for line in lines:
            if 'SERVICE_NAME' in line:
                service = line.split(':')[1].strip()
                services.append(service)
        
        return services
```

### Module 5: Web Hacking (Windows)
**Windows Local Testing**:

```python
# Test web vulnerabilities locally on Windows
import subprocess
import time

class WindowsWebLab:
    """Run vulnerable web apps on Windows"""
    
    @staticmethod
    def install_vulnerable_app():
        """Install DVWA or WebGoat on Windows"""
        
        instructions = """
        OPTION 1: Using Docker Desktop for Windows
        1. Install Docker Desktop: https://www.docker.com/products/docker-desktop
        2. Run: docker run -p 80:80 vulnerables/web-dvwa
        3. Access: http://localhost
        
        OPTION 2: Using Local Python Server
        1. Use Python's built-in HTTP server
        2. Serve vulnerable files locally
        3. Test SQL injection and XSS
        
        OPTION 3: Online Vulnerable Sites
        - OWASP WebGoat: https://webgoat.herokuapp.com/
        - HackTheBox: https://www.hackthebox.eu/
        - TryHackMe: https://www.tryhackme.com/
        """
        
        print(instructions)
    
    @staticmethod
    def test_sql_injection_locally():
        """Test SQL injection on local Windows system"""
        
        # Create simple vulnerable Flask app
        flask_code = """
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/login')
def login():
    username = request.args.get('username', '')
    # VULNERABLE: No sanitization
    query = f"SELECT * FROM users WHERE username = '{username}'"
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    try:
        cursor.execute(query)
        return str(cursor.fetchall())
    except:
        return "SQL Error"

if __name__ == '__main__':
    app.run(port=5000)
"""
        
        return flask_code
```

### Module 6: Cryptography (Windows)
**All Python cryptography works on Windows**:

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

class CryptoWindows:
    """Cryptography attacks work identically on Windows"""
    
    @staticmethod
    def aes_ecb_attack():
        """ECB mode vulnerability - works on Windows"""
        
        key = os.urandom(16)
        iv = os.urandom(16)
        
        plaintext = b"This is a secret message that repeats this is a secret message"
        
        # Vulnerable ECB mode
        cipher_ecb = Cipher(
            algorithms.AES(key),
            modes.ECB(),
            backend=default_backend()
        )
        encryptor = cipher_ecb.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # ECB reveals patterns
        print("[*] Plaintext:", plaintext)
        print("[*] Ciphertext:", ciphertext.hex())
        print("[!] Notice the pattern repetition in ciphertext!")
        
        return ciphertext
```

### Module 7: Reverse Engineering (Windows)
**Windows Binary Analysis**:

```python
import subprocess
import os

class WindowsBinaryAnalysis:
    """Reverse engineer Windows executables"""
    
    @staticmethod
    def analyze_windows_exe(exe_path):
        """Analyze Windows EXE file"""
        
        if not os.path.exists(exe_path):
            print(f"[-] File not found: {exe_path}")
            return
        
        print(f"[*] Analyzing: {exe_path}")
        
        # Get file info
        result = subprocess.run(['wmic', 'datafile', 'where', f'name="{exe_path}"', 'get', 'Description'],
                              capture_output=True, text=True)
        print("[*] Description:")
        print(result.stdout)
        
        # Check file size
        size = os.path.getsize(exe_path)
        print(f"[*] File size: {size} bytes")
        
        # Extract strings from binary
        strings = extract_strings_windows(exe_path)
        print(f"[*] Found {len(strings)} strings")
        return strings
    
    @staticmethod
    def extract_strings_windows(exe_path):
        """Extract readable strings from Windows binary"""
        
        strings = []
        with open(exe_path, 'rb') as f:
            data = f.read()
        
        current_string = b''
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += bytes([byte])
            else:
                if len(current_string) >= 4:  # Minimum string length
                    strings.append(current_string.decode('ascii', errors='ignore'))
                current_string = b''
        
        return strings
    
    @staticmethod
    def check_security_features_windows(exe_path):
        """Check Windows binary protections"""
        
        print(f"[*] Checking security features in: {exe_path}")
        
        with open(exe_path, 'rb') as f:
            pe_header = f.read(2)
        
        features = {
            'DEP/NX': 'Usually ENABLED on Windows 10+',
            'ASLR': 'Usually ENABLED on Windows 10+',
            'Stack Canary': 'Check with debugger',
            'Code Integrity': 'Check with sigcheck.exe'
        }
        
        for feature, status in features.items():
            print(f"  {feature}: {status}")
        
        return features
```

### Module 8: Evasion (Windows)
**Windows-Specific Evasion**:

```python
import subprocess
import os

class WindowsEvasion:
    """Windows-specific evasion techniques"""
    
    @staticmethod
    def check_for_security_tools():
        """Detect security tools on Windows"""
        
        # Common security tools
        security_tools = [
            'MsMpEng.exe',      # Windows Defender
            'avnotify.exe',     # Antivirus
            'egui.exe',         # Kaspersky
            'avgui.exe',        # AVG
            'osql.exe',         # SQL injection monitor
            'ProcExp64.exe',    # Process Explorer
        ]
        
        print("[*] Checking for security tools...")
        
        result = subprocess.run(['tasklist'], capture_output=True, text=True)
        running_processes = result.stdout.lower()
        
        found = []
        for tool in security_tools:
            if tool.lower() in running_processes:
                found.append(tool)
                print(f"[!] Found: {tool}")
        
        return found
    
    @staticmethod
    def encode_payload_windows(payload):
        """Encode payload for Windows AV evasion"""
        
        import base64
        import random
        
        # Base64 encoding
        encoded = base64.b64encode(payload)
        
        # XOR encoding
        key = random.randint(1, 255)
        xor_encoded = bytes([b ^ key for b in payload])
        
        return {
            'base64': encoded,
            'xor': (xor_encoded, key),
            'hex': payload.hex()
        }
    
    @staticmethod
    def windows_persistence():
        """Windows persistence techniques (for authorized testing only)"""
        
        persistence_methods = {
            'Registry Run': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            'Scheduled Task': 'TaskScheduler (schtasks)',
            'Startup Folder': f'C:\\Users\\[USER]\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
            'WMI': 'Windows Management Instrumentation event subscription',
        }
        
        print("[!] Windows Persistence Methods (AUTHORIZED ONLY):")
        for method, details in persistence_methods.items():
            print(f"  {method}: {details}")
        
        return persistence_methods
```

---

## Windows-Specific Tools & Alternatives

### Built-in Windows Tools (No Installation)

```powershell
# Network analysis
ipconfig /all              # Network configuration
netstat -ano               # Network connections and processes
tracert example.com        # Traceroute
nslookup example.com       # DNS lookup
ping example.com           # ICMP echo

# Process management
tasklist                   # List processes
tasklist /v                # Detailed process info
taskkill /PID [pid]        # Kill process
Get-Process | Format-List  # PowerShell equivalent

# System information
systeminfo                 # System information
wmic OS get Caption        # Windows version
wmic service get name      # List services
sc query                   # Query services

# File analysis
dir /s                     # List files recursively
findstr /R "pattern" file  # Search for patterns
certutil -hashfile file MD5 # Calculate file hash

# Registry (Advanced)
reg query HKCU             # Query registry
regedit                    # Registry editor (GUI)
```

### Recommended Free Tools for Windows

```
1. Wireshark
   - Download: https://www.wireshark.org/
   - Purpose: Packet capture and analysis
   - Use: Network reconnaissance

2. Notepad++
   - Download: https://notepad-plus-plus.org/
   - Purpose: Advanced text editor
   - Use: Code editing, hex analysis

3. 7-Zip
   - Download: https://www.7-zip.org/
   - Purpose: File archive manager
   - Use: Extract and analyze archives

4. Git for Windows
   - Download: https://git-scm.com/download/win
   - Purpose: Version control
   - Use: Clone repositories

5. Visual Studio Code
   - Download: https://code.visualstudio.com/
   - Purpose: Code editor with Python support
   - Use: Write and test Python scripts

6. Python 3.9+
   - Download: https://www.python.org/
   - Purpose: Python interpreter
   - Use: Execute all course code

7. Docker Desktop (Optional)
   - Download: https://www.docker.com/products/docker-desktop
   - Purpose: Containerization
   - Use: Run vulnerable web apps locally
```

---

## Windows-Only Practice Exercises

### Exercise 1: Basic Network Scanning on Windows

```python
import socket
import subprocess

def windows_network_scan():
    """Simple network scan using Windows tools"""
    
    # Method 1: Using Python sockets
    def scan_ports_python(host, ports):
        print(f"[*] Scanning {host}...")
        open_ports = []
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            
            if result == 0:
                open_ports.append(port)
                print(f"[+] Port {port}: OPEN")
            
            sock.close()
        
        return open_ports
    
    # Method 2: Using Windows netstat
    def scan_ports_netstat():
        result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
        print(result.stdout)
    
    # Test on localhost
    ports = [80, 443, 8080, 3306, 5432, 27017]
    open_ports = scan_ports_python('127.0.0.1', ports)
    print(f"\n[*] Open ports: {open_ports}")

# Run it
windows_network_scan()
```

### Exercise 2: Process Analysis on Windows

```python
import subprocess
import ctypes

def windows_process_analysis():
    """Analyze running processes on Windows"""
    
    # List all processes
    result = subprocess.run(['tasklist', '/v'], capture_output=True, text=True)
    lines = result.stdout.split('\n')
    
    print("[*] Running Processes:")
    print("-" * 80)
    
    # Parse output
    for line in lines[:20]:  # First 20 processes
        if line.strip():
            print(line)
    
    # Find specific process
    def find_process(name):
        result = subprocess.run(['tasklist'], capture_output=True, text=True)
        if name.lower() in result.stdout.lower():
            print(f"[+] Found: {name}")
            return True
        else:
            print(f"[-] Not found: {name}")
            return False
    
    # Check for Python
    find_process('python.exe')
    find_process('notepad.exe')

# Run it
windows_process_analysis()
```

### Exercise 3: File Analysis on Windows

```python
import os
import hashlib

def windows_file_analysis(file_path):
    """Analyze files on Windows"""
    
    if not os.path.exists(file_path):
        print(f"[-] File not found: {file_path}")
        return
    
    print(f"[*] Analyzing: {file_path}")
    
    # File info
    size = os.path.getsize(file_path)
    print(f"[*] Size: {size} bytes")
    
    # File creation time
    import time
    mtime = os.path.getmtime(file_path)
    print(f"[*] Modified: {time.ctime(mtime)}")
    
    # Calculate hashes
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            md5_hash.update(chunk)
            sha256_hash.update(chunk)
    
    print(f"[*] MD5: {md5_hash.hexdigest()}")
    print(f"[*] SHA256: {sha256_hash.hexdigest()}")
    
    # Check if executable
    if file_path.lower().endswith(('.exe', '.dll', '.sys')):
        print("[!] This is a Windows executable/library")
        
        # Try to extract version info
        import subprocess
        result = subprocess.run(['wmic', 'datafile', 'where', f'name="{file_path}"', 
                               'get', 'Version'], 
                              capture_output=True, text=True)
        if result.stdout.strip():
            print(f"[*] Version: {result.stdout.strip()}")

# Example usage:
# windows_file_analysis(r"C:\Windows\System32\calc.exe")
```

### Exercise 4: Windows Registry Analysis

```python
import subprocess
import winreg

def windows_registry_analysis():
    """Analyze Windows registry"""
    
    print("[*] Windows Registry Analysis")
    
    # Method 1: Using reg.exe (no admin needed)
    result = subprocess.run(['reg', 'query', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'],
                          capture_output=True, text=True)
    
    print("[*] Startup programs in Registry:")
    print(result.stdout)
    
    # Method 2: Using Python winreg (requires admin for some keys)
    try:
        reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                 r'Software\Microsoft\Windows\CurrentVersion\Run')
        
        print("\n[*] Registry Run Keys:")
        i = 0
        while True:
            try:
                name, value, reg_type = winreg.EnumValue(reg_key, i)
                print(f"  {name}: {value}")
                i += 1
            except OSError:
                break
        
        winreg.CloseKey(reg_key)
    except Exception as e:
        print(f"[-] Error: {e}")

# Run it
windows_registry_analysis()
```

### Exercise 5: Windows Credential Analysis

```python
import subprocess

def windows_credential_analysis():
    """Find cached credentials on Windows (for authorized testing only)"""
    
    print("[!] Windows Credential Analysis (AUTHORIZED ONLY)")
    
    # Cached credentials location
    print("[*] Cached credentials locations:")
    print("  1. HKLM\\SECURITY\\Cache - Password hashes (requires SYSTEM)")
    print("  2. SAM database - User password hashes (requires SYSTEM)")
    print("  3. LSASS.exe - In-memory credentials (requires SYSTEM)")
    print("  4. Credential Manager - Saved passwords")
    print("  5. Browser cookies - Stored credentials")
    
    # List saved WiFi networks (no admin needed)
    print("\n[*] Saved WiFi Networks:")
    result = subprocess.run(['netsh', 'wlan', 'show', 'profile'],
                          capture_output=True, text=True)
    print(result.stdout)
    
    # Get stored passwords info (no credentials, just locations)
    print("\n[*] Credential storage locations:")
    locations = {
        'Browser Profiles': r'C:\Users\[USER]\AppData\Local\[Browser]\User Data\Default',
        'Credential Manager': r'Control Panel\All Control Panel Items\Credential Manager',
        'RDP Sessions': r'C:\Users\[USER]\AppData\Local\Microsoft\Terminal Server Client',
        'SSH Keys': r'C:\Users\[USER]\.ssh',
    }
    
    for location, path in locations.items():
        print(f"  {location}: {path}")

# Run it
# windows_credential_analysis()
```

---

## Windows-Only CTF & Practice

### Local Testing Without VMs

```python
import http.server
import socketserver
import os

class WindowsVulnerableLab:
    """Run a simple vulnerable web server locally on Windows"""
    
    @staticmethod
    def create_vulnerable_server():
        """Create a simple vulnerable web application"""
        
        vulnerable_html = """
<!DOCTYPE html>
<html>
<head><title>Vulnerable Lab</title></head>
<body>
    <h1>Windows Hacking Lab</h1>
    
    <h2>SQL Injection Test</h2>
    <form action="/sqli" method="GET">
        Username: <input type="text" name="user"><br>
        <input type="submit" value="Login">
    </form>
    
    <h2>XSS Test</h2>
    <form action="/xss" method="GET">
        Comment: <input type="text" name="comment"><br>
        <input type="submit" value="Post">
    </form>
    
    <h2>Command Injection Test</h2>
    <form action="/cmd" method="GET">
        Filename: <input type="text" name="file"><br>
        <input type="submit" value="View">
    </form>
</body>
</html>
"""
        
        return vulnerable_html
    
    @staticmethod
    def run_lab_server():
        """Run the lab server"""
        
        PORT = 8080
        
        class VulnerableHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(WindowsVulnerableLab.create_vulnerable_server().encode())
                else:
                    super().do_GET()
        
        with socketserver.TCPServer(("", PORT), VulnerableHandler) as httpd:
            print(f"[*] Lab running at http://localhost:{PORT}")
            print("[*] Press Ctrl+C to stop")
            httpd.serve_forever()

# Run lab:
# WindowsVulnerableLab.run_lab_server()
```

### Online CTF Platforms (No Installation)

```python
"""
Windows users can practice on these online platforms:

1. HackTheBox (Web-based)
   - https://www.hackthebox.eu/
   - No installation needed
   - Practice boxes online
   
2. TryHackMe
   - https://www.tryhackme.com/
   - Guided rooms
   - Beginner-friendly
   
3. PicoCTF
   - https://picoctf.org/
   - Web-based CTF
   - Annual competition
   
4. OverTheWire
   - https://overthewire.org/wargames/
   - Bandit (Linux basics)
   - Natas (web security)
   - Leviathan (binary exploitation)
   
5. OWASP WebGoat
   - Can run on Windows with Python
   - Web security lessons
   
6. Exploit Education
   - https://exploit.education/
   - Binary exploitation
   - Online protolab
"""
```

---

## Windows Course Completion Checklist

- [ ] Python 3.9+ installed and working
- [ ] Virtual environment created
- [ ] Required packages installed
- [ ] VS Code configured for Python
- [ ] Module 1 exercises completed
- [ ] Module 2 exercises completed
- [ ] Module 3 exercises completed
- [ ] Module 4 exercises completed
- [ ] Module 5 exercises completed
- [ ] Module 6 exercises completed
- [ ] Module 7 exercises completed
- [ ] Module 8 exercises completed
- [ ] 5 online CTF challenges completed
- [ ] All practice exercises working

---

## Important Notes for Windows Users

### What Works Identically
- ✅ All Python socket code
- ✅ All cryptography code
- ✅ All hashing code
- ✅ All encoding/decoding
- ✅ HTTP requests
- ✅ JSON parsing
- ✅ File operations

### What's Different
- 🔄 Process manipulation (use Windows APIs instead)
- 🔄 Memory analysis (use Windows tools like WMIC)
- 🔄 Packet capture (use Wireshark instead of Scapy filters)
- 🔄 System calls (use Windows APIs via ctypes)
- 🔄 File permissions (NTFS instead of Unix)

### What You CAN'T Do Without Linux/VM
- ❌ Actual buffer overflow exploitation (needs Linux binary)
- ❌ Kernel exploitation (needs Linux kernel)
- ❌ Low-level system hacking (needs Linux kernel)
- ❌ Actual shellcode execution (but can simulate)
- **BUT**: You can learn all theory and create exploits to USE against Linux systems

---

## Next Steps for Windows Users

1. Install Python and required packages
2. Start with Module 1 (all works on Windows)
3. Practice socket programming on Windows
4. Use online CTF platforms for hands-on practice
5. When ready for exploits, use online resources or VPS servers
6. Consider AWS free tier or HackTheBox labs for real targets

---

## Summary

This **Windows-Only Edition** allows you to:
- ✅ Learn all hacking theory
- ✅ Practice Python security programming
- ✅ Understand networking and web security
- ✅ Learn cryptanalysis
- ✅ Analyze and reverse engineer files
- ✅ Participate in online CTFs
- ✅ Build exploitation skills
- ✅ Practice on real targets via online labs

**You don't need Linux to learn hacking - you need it to practice exploitation on real systems. But all theory and most techniques work fine on Windows!**

Start now with Python installed on Windows - that's all you need! 🚀
