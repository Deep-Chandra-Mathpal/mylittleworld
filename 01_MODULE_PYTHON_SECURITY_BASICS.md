# Module 1: Python Basics for Security

## 1.1 Why Python for Hacking?

### Advantages
- **Rapid Development**: Write security tools 5x faster than C++
- **Rich Libraries**: `socket`, `paramiko`, `requests`, `cryptography`
- **Cross-Platform**: Works on Linux, Windows, macOS
- **Community**: Largest security tool ecosystem
- **Readability**: Code is documentation, easier to debug exploits
- **Dynamic**: Allows runtime manipulation (monkey patching)

### Real-World Usage
- Metasploit modules are often Python
- Burp Suite extensions
- OWASP tools: SQLmap, w3af
- Security frameworks: Scrapy (web scraping), Scapy (packet manipulation)

---

## 1.2 Binary & Hexadecimal Fundamentals

### Why This Matters
- Exploit writing uses raw bytes
- Memory addresses in hex
- Network packets as binary
- Shellcode is pure bytes

### Python Binary Operations

```python
# Decimal to Binary/Hex
decimal = 255
print(f"Binary: {bin(decimal)}")        # 0b11111111
print(f"Hex: {hex(decimal)}")           # 0xff
print(f"Octal: {oct(decimal)}")         # 0o377

# Bitwise Operations
a = 0b1010  # 10
b = 0b1100  # 12

print(f"AND: {a & b:04b}")              # 0b1000 (8)
print(f"OR:  {a | b:04b}")              # 0b1110 (14)
print(f"XOR: {a ^ b:04b}")              # 0b0110 (6)
print(f"NOT: {~a}")                     # -11 (two's complement)
print(f"Left Shift: {a << 2}")           # 0b101000 (40)
print(f"Right Shift: {a >> 1}")          # 0b0101 (5)

# Why XOR is used in encryption
key = 0b10101010
plaintext = 0b11110000
ciphertext = plaintext ^ key
decrypted = ciphertext ^ key
assert decrypted == plaintext  # XOR is reversible!

# Byte operations
data = b'\x41\x42\x43'  # ASCII: ABC
print(data.hex())                       # 414243
print(int.from_bytes(data, 'big'))      # 4276803
print(len(data))                        # 3
```

### Exercise 1.1: Byte Packing for Exploit Writing
```python
import struct

# Common in exploit writing: pack integers into bytes
# For a buffer overflow, you need to overwrite a 32-bit address

def pack_exploit_payload(target_address, nop_count=100):
    """
    Pack exploit payload:
    - NOP instructions (0x90 in x86)
    - Shellcode (hypothetical)
    - Return address
    """
    payload = b'\x90' * nop_count                    # NOP sled
    payload += b'\xcc' * 50                          # INT3 (breakpoint)
    payload += struct.pack('<I', target_address)    # Little-endian 32-bit
    return payload

# Unpack for analysis
address = 0xdeadbeef
packed = struct.pack('<Q', address)                 # 64-bit, little-endian
print(f"Packed: {packed.hex()}")                     # efbeadde00000000
unpacked = struct.unpack('<Q', packed)[0]
assert unpacked == address
```

---

## 1.3 Working with Sockets & Network Data

### What is a Socket?
- **Endpoint of network communication**
- Think of it as a virtual "pipe" between two programs
- Can be TCP (reliable), UDP (fast), or raw sockets
- Foundation for all network hacking

### Socket Programming Fundamentals

```python
import socket

# TCP Client Connection
def simple_tcp_client(host, port, data):
    """
    Creates TCP connection and sends data
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        sock.sendall(data.encode())
        response = sock.recv(4096)  # Receive up to 4KB
        return response.decode()
    finally:
        sock.close()

# TCP Server
def simple_tcp_server(host, port):
    """
    Basic TCP server for testing/exploitation
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)
    
    print(f"Listening on {host}:{port}")
    
    while True:
        conn, addr = server.accept()
        print(f"Connection from {addr}")
        
        data = conn.recv(1024)
        print(f"Received: {data}")
        
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello")
        conn.close()

# UDP for faster/unreliable communication
def udp_scan_port(host, port, timeout=2):
    """
    UDP port scanning (faster than TCP but unreliable)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    
    try:
        sock.sendto(b"PING", (host, port))
        response, _ = sock.recvfrom(1024)
        return True
    except:
        return False
    finally:
        sock.close()

# Raw Socket for Custom Protocols
def raw_socket_example():
    """
    Raw sockets allow complete control over packets
    WARNING: Requires root/admin privileges
    """
    try:
        # Create raw TCP socket (only on Linux)
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        # Can now craft custom IP/TCP headers
    except PermissionError:
        print("Raw sockets require root privileges")
```

---

## 1.4 File & Process Handling for Exploitation

### File Operations for Exploit Development

```python
import os
import subprocess

# Reading binary files (e.g., executables, firmware)
def read_binary_file(filename):
    """
    Read binary file in chunks (important for large files)
    """
    with open(filename, 'rb') as f:
        data = f.read()
    return data

# Writing exploit payloads to files
def write_payload(payload, filename):
    """
    Write binary payload to file
    Used in creating malware, shellcode, or exploit files
    """
    with open(filename, 'wb') as f:
        f.write(payload)

# Executing system commands (dangerous!)
def execute_command(cmd, shell=False):
    """
    Execute system command and capture output
    WARNING: Never use shell=True with untrusted input (command injection!)
    """
    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            capture_output=True,
            timeout=5
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        print("Command timed out")
        return None, None, -1

# Process spawning for reverse shells
def spawn_reverse_shell(attacker_ip, attacker_port):
    """
    Spawn a reverse shell (common payload)
    This gives attacker remote command execution
    """
    # In real exploitation, this would be part of shellcode
    # or injected into a running process
    pass

# Working with /proc filesystem (Linux)
def read_process_memory(pid, address, size):
    """
    Read process memory on Linux
    Used in exploitation and process injection
    """
    try:
        with open(f'/proc/{pid}/mem', 'rb') as f:
            f.seek(address)
            return f.read(size)
    except PermissionError:
        print("Need elevated privileges")
        return None
```

---

## 1.5 String Encoding & Format Strings

### Why Encoding Matters
- **UTF-8**: Unicode text encoding
- **Base64**: Encoding binary as text (AV evasion)
- **Hex**: Convenient representation (0x41 = 'A')
- **URL encoding**: Web exploitation

### Common Encodings in Hacking

```python
import base64
import urllib.parse

# Base64 Encoding (for AV evasion, binary over text protocols)
plaintext = "This is secret shellcode"
encoded = base64.b64encode(plaintext.encode())
print(f"Encoded: {encoded}")
decoded = base64.b64decode(encoded).decode()
assert decoded == plaintext

# Hex Encoding
hex_string = plaintext.encode().hex()
print(f"Hex: {hex_string}")
decoded_hex = bytes.fromhex(hex_string).decode()

# URL Encoding (web exploitation)
payload = "'; DROP TABLE users; --"
url_encoded = urllib.parse.quote(payload)
print(f"URL Encoded: {url_encoded}")

# ROT13 (simple cipher for AV evasion)
def rot13(text):
    result = []
    for char in text:
        if 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(char)
    return ''.join(result)

# Format String Vulnerabilities
def vulnerable_format_string(user_input):
    """
    VULNERABLE CODE (for educational purposes)
    Format string attack allows reading/writing memory
    """
    # DON'T DO THIS:
    # print(user_input)  # If user_input = "%x.%x.%x", leaks stack!
    
    # SAFE:
    print(user_input)  # Python prevents this, but C doesn't!

# Detecting format string exploits
def find_format_strings(data):
    """
    Look for %x, %s, %n patterns in network data
    These indicate format string attack attempts
    """
    if b'%x' in data or b'%s' in data or b'%n' in data:
        return True
    return False
```

---

## 1.6 Exception Handling & Error Analysis

### Why Error Handling Matters in Hacking

```python
# Catching exceptions tells us about target system
def probe_for_info(host, port):
    """
    Different errors reveal different info about target
    """
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((host, port))
        sock.close()
        return "Port open"
    except socket.timeout:
        return "Port filtered (firewall)"
    except ConnectionRefusedError:
        return "Port closed"
    except socket.gaierror:
        return "DNS resolution failed"
    except Exception as e:
        return f"Unknown error: {type(e).__name__}"

# Try-finally for cleanup (important for sockets!)
def safe_socket_operation():
    """
    Always clean up resources, even if error occurs
    """
    sock = None
    try:
        sock = socket.socket()
        # ... operations ...
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if sock:
            sock.close()  # Ensures cleanup happens
```

---

## 1.7 Practice Exercises

### Exercise 1: Build a Port Scanner
```python
import socket
import threading

def tcp_port_scanner(host, port):
    """Scan single port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            print(f"Port {port}: OPEN")
        return result
    except Exception as e:
        print(f"Error scanning {port}: {e}")

def multi_threaded_scan(host, start_port, end_port, threads=50):
    """Fast multi-threaded port scan"""
    thread_list = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=tcp_port_scanner, args=(host, port))
        thread_list.append(t)
        t.start()
        
        if len(thread_list) == threads:
            for t in thread_list:
                t.join()
            thread_list = []

# Usage: multi_threaded_scan("127.0.0.1", 1, 1000)
```

### Exercise 2: Encode Payload for AV Evasion
```python
def encode_payload_for_evasion(shellcode):
    """
    Multi-layer encoding to evade antivirus
    """
    # Layer 1: Base64
    layer1 = base64.b64encode(shellcode)
    
    # Layer 2: XOR with random key
    key = os.urandom(1)
    layer2 = bytes([b ^ key[0] for b in layer1])
    
    # Layer 3: Insert junk bytes
    import random
    junk = [random.randint(0, 255) for _ in range(50)]
    
    return layer2, key, junk
```

---

## Summary
- Python is ideal for rapid security tool development
- Binary/hex operations are fundamental to exploit writing
- Sockets are the foundation of network hacking
- Proper file/process handling prevents exploitation
- Understanding encoding helps with AV evasion
- Exception handling reveals target system information

## Next Steps
- Practice socket programming
- Build a simple port scanner
- Study binary number systems
- Set up a home lab with vulnerable VMs
