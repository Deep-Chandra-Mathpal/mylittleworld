# Module 7: Reverse Engineering & Binary Analysis

## 7.1 Binary File Analysis

```python
import struct
import os

class BinaryAnalyzer:
    """
    Analyze executable files for vulnerabilities
    """
    
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.elf_header = None
        self.sections = []
        self.symbols = []
    
    def parse_elf_header(self):
        """
        Parse ELF header (Linux executables)
        """
        
        elf_header_format = """
        e_ident[0-3]:       Magic number (0x7F, 'E', 'L', 'F')
        e_ident[4]:         Class (32-bit or 64-bit)
        e_ident[5]:         Data (little-endian or big-endian)
        e_ident[6]:         Version
        e_ident[7]:         OS/ABI
        e_type:             File type (EXEC, DYN, etc.)
        e_machine:          Machine type (x86, x86-64, ARM, etc.)
        e_version:          Version
        e_entry:            Entry point address
        e_phoff:            Program header offset
        e_shoff:            Section header offset
        e_flags:            Architecture flags
        e_ehsize:           ELF header size
        e_phentsize:        Program header entry size
        e_phnum:            Program header count
        e_shentsize:        Section header entry size
        e_shnum:            Section header count
        e_shstrndx:         Section name string table index
        """
        
        with open(self.binary_path, 'rb') as f:
            magic = f.read(4)
            
            if magic != b'\x7fELF':
                print("[-] Not an ELF file")
                return False
            
            # Read rest of header
            ei_class = struct.unpack('B', f.read(1))[0]
            is_64bit = ei_class == 2
            
            # Continue parsing...
            return is_64bit
    
    def find_strings(self):
        """
        Extract all strings from binary
        Reveals configuration, paths, error messages
        """
        strings = []
        
        with open(self.binary_path, 'rb') as f:
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
    
    def identify_functions(self):
        """
        Extract function symbols and their addresses
        """
        
        import subprocess
        
        try:
            result = subprocess.run(['objdump', '-t', self.binary_path],
                                  capture_output=True, text=True)
            
            functions = {}
            for line in result.stdout.split('\n'):
                if 'F' in line and '.text' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        address = parts[0]
                        name = parts[-1]
                        functions[name] = address
            
            return functions
        except:
            return {}
    
    def check_security_features(self):
        """
        Check what security protections binary has
        """
        
        import subprocess
        
        result = subprocess.run(['readelf', '-l', self.binary_path],
                              capture_output=True, text=True)
        
        features = {
            'PIE': 'Position Independent Executable' in result.stdout,
            'ASLR': 'Dynamic' in result.stdout,
            'Full RELRO': 'RELRO' in result.stdout and 'FULL' in result.stdout,
            'NX/DEP': 'GNU_STACK' in result.stdout and 'RWE' not in result.stdout,
            'Canary': False,  # Need to disassemble to check
            'FORTIFY': False,  # Check symbol table
        }
        
        return features
    
    def analyze_imports(self):
        """
        Show imported functions (library calls)
        """
        
        import subprocess
        
        result = subprocess.run(['readelf', '-d', self.binary_path],
                              capture_output=True, text=True)
        
        # Parse dynamic imports
        imports = []
        for line in result.stdout.split('\n'):
            if 'NEEDED' in line:
                lib = line.split('[')[1].split(']')[0] if '[' in line else ""
                if lib:
                    imports.append(lib)
        
        return imports
```

## 7.2 Disassembly & Decompilation

```python
from capstone import *

class Disassembler:
    """
    Disassemble binary code to understand functionality
    """
    
    def __init__(self, binary_data, arch='x86_64'):
        self.binary_data = binary_data
        self.arch = arch
        self.instructions = []
    
    def disassemble_section(self, data, address=0x0):
        """
        Disassemble raw code section
        """
        
        if self.arch == 'x86_64':
            md = Cs(CS_ARCH_X86, CS_MODE_64)
        elif self.arch == 'x86':
            md = Cs(CS_ARCH_X86, CS_MODE_32)
        elif self.arch == 'arm':
            md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        else:
            return []
        
        instructions = []
        for instr in md.disasm(data, address):
            instructions.append({
                'address': instr.address,
                'mnemonic': instr.mnemonic,
                'op_str': instr.op_str,
                'bytes': instr.bytes.hex()
            })
        
        return instructions
    
    def find_function_prologue(self, binary_data):
        """
        Identify function boundaries by prologue pattern
        """
        
        # x86-64 prologue patterns:
        # push rbp; mov rbp, rsp
        # sub rsp, <value>
        
        prologue_signatures = [
            b'\x55\x48\x89\xe5',      # push rbp; mov rbp, rsp
            b'\x55\x89\xe5',           # push ebp; mov ebp, esp
            b'\x48\x83\xec',           # sub rsp, ...
        ]
        
        functions = []
        for sig in prologue_signatures:
            offset = 0
            while True:
                offset = binary_data.find(sig, offset)
                if offset == -1:
                    break
                functions.append(offset)
                offset += 1
        
        return sorted(set(functions))
    
    def analyze_control_flow(self, instructions):
        """
        Map control flow (jumps, calls, returns)
        """
        
        basic_blocks = []
        current_block = []
        
        for instr in instructions:
            current_block.append(instr)
            
            # Block ends at jumps, calls, returns
            if any(x in instr['mnemonic'] for x in ['jmp', 'je', 'jne', 'call', 'ret']):
                basic_blocks.append(current_block)
                current_block = []
        
        return basic_blocks
```

## 7.3 Patching Binaries

```python
class BinaryPatcher:
    """
    Modify binary to change behavior
    """
    
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.patches = []
        self.original_data = None
    
    def load_binary(self):
        """Read binary file"""
        with open(self.binary_path, 'rb') as f:
            self.original_data = bytearray(f.read())
    
    def nop_out_code(self, offset, length):
        """
        Replace code with NOP instructions
        Used to disable protections or behavior
        """
        
        # NOP instruction:
        # x86: 0x90
        # x86-64: 0x90
        # ARM: 0x00 0x00 0xa0 0xe1
        
        nops = b'\x90' * length
        self.original_data[offset:offset+length] = nops
        self.patches.append(('nop_out', offset, length))
    
    def replace_code(self, offset, new_bytes):
        """
        Replace code with custom bytes
        """
        length = len(new_bytes)
        self.original_data[offset:offset+length] = new_bytes
        self.patches.append(('replace', offset, new_bytes))
    
    def patch_jmp_to_unconditional(self, offset):
        """
        Change conditional jump to unconditional
        jz (0x74) -> jmp (0xeb)
        """
        self.original_data[offset] = 0xeb
        self.patches.append(('patch_jump', offset))
    
    def save_patched_binary(self, output_path):
        """
        Write patched binary to file
        """
        with open(output_path, 'wb') as f:
            f.write(self.original_data)
        
        # Make executable
        import stat
        st = os.stat(output_path)
        os.chmod(output_path, st.st_mode | stat.S_IEXEC)
        
        print(f"[+] Patched binary saved: {output_path}")
    
    def bypass_license_check(self):
        """
        Example: Disable license validation
        """
        
        # Find: "License invalid" string
        # Find: Where it's printed
        # Patch: Jump over error handling
        
        # find_string("License invalid")
        # find_jz_after_check()
        # change_jz_to_jmp()
        pass
    
    def disable_anti_debug(self):
        """
        Disable debugger detection
        """
        
        # Common anti-debug checks:
        # - ptrace(PTRACE_TRACEME)
        # - isDebuggerPresent()
        # - CheckRemoteDebuggerPresent()
        
        # Solution: Patch the check to always fail
        pass

def reverse_engineer_license_key(binary_path):
    """
    Example: Recover license key from binary
    """
    
    # 1. Analyze license check function
    # 2. Understand validation algorithm
    # 3. Reverse the algorithm
    # 4. Generate valid keys
    
    pass
```

## 7.4 Malware Analysis

```python
class MalwareAnalyzer:
    """
    Analyze malicious binaries safely
    """
    
    def __init__(self, sample_path, sandbox_mode=True):
        self.sample_path = sample_path
        self.sandbox_mode = sandbox_mode
        self.artifacts = []
    
    def static_analysis(self):
        """
        Analyze without executing
        """
        
        analysis = {
            'file_type': self._get_file_type(),
            'strings': self._extract_strings(),
            'imports': self._get_imports(),
            'sections': self._get_sections(),
            'hashes': self._calculate_hashes(),
            'entropy': self._calculate_entropy(),
        }
        
        return analysis
    
    def _calculate_entropy(self):
        """
        High entropy suggests encryption/compression
        Possible packer
        """
        
        with open(self.sample_path, 'rb') as f:
            data = f.read()
        
        import math
        
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        
        entropy = 0
        for count in freq.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
        
        return entropy
    
    def _get_file_type(self):
        """Identify file type"""
        import subprocess
        result = subprocess.run(['file', self.sample_path],
                              capture_output=True, text=True)
        return result.stdout.strip()
    
    def _extract_strings(self):
        """Get strings from binary"""
        import subprocess
        result = subprocess.run(['strings', self.sample_path],
                              capture_output=True, text=True)
        return result.stdout.split('\n')
    
    def _get_imports(self):
        """Get library/function imports"""
        import subprocess
        result = subprocess.run(['objdump', '-t', self.sample_path],
                              capture_output=True, text=True)
        return result.stdout
    
    def _get_sections(self):
        """Analyze sections"""
        import subprocess
        result = subprocess.run(['readelf', '-S', self.sample_path],
                              capture_output=True, text=True)
        return result.stdout
    
    def _calculate_hashes(self):
        """Calculate cryptographic hashes"""
        import hashlib
        
        with open(self.sample_path, 'rb') as f:
            data = f.read()
        
        return {
            'md5': hashlib.md5(data).hexdigest(),
            'sha1': hashlib.sha1(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest(),
        }
    
    def dynamic_analysis(self):
        """
        Execute in sandbox and monitor behavior
        """
        
        if not self.sandbox_mode:
            print("[-] Dynamic analysis disabled (not in sandbox)")
            return None
        
        # Run in isolated environment
        # Monitor: File access, network, registry, etc.
        
        behaviors = {
            'processes': self._monitor_processes(),
            'files': self._monitor_files(),
            'network': self._monitor_network(),
            'registry': self._monitor_registry(),
        }
        
        return behaviors
    
    def _monitor_processes(self):
        pass
    
    def _monitor_files(self):
        pass
    
    def _monitor_network(self):
        pass
    
    def _monitor_registry(self):
        pass
    
    def identify_known_malware(self):
        """
        Check against malware databases (VirusTotal, etc.)
        """
        
        hashes = self._calculate_hashes()
        
        # Query VirusTotal API
        import requests
        
        vt_url = "https://www.virustotal.com/api/v3/files"
        
        # Would need API key
        pass
    
    def identify_packer(self):
        """
        Detect if binary is packed/compressed
        """
        
        packers = {
            'UPX': b'UPX!',
            'ASPack': b'$ASPACK',
            'PEtite': b'$PEiD',
            'Visual C++': b'Microsoft',
        }
        
        with open(self.sample_path, 'rb') as f:
            data = f.read()
        
        detected = []
        for packer, signature in packers.items():
            if signature in data:
                detected.append(packer)
        
        return detected
```

## 7.5 Practice: Crack a Simple Challenge

```python
def binary_challenge_example():
    """
    Example reverse engineering challenge
    """
    
    challenge = """
    A binary accepts a password
    You need to:
    1. Find the password check function
    2. Understand the validation algorithm
    3. Generate or guess the correct password
    4. OR patch the binary to skip check
    """
    
    steps = [
        "1. Run strings to find error messages",
        "2. Use GDB to debug password check",
        "3. Find comparing against stored value",
        "4. Patch binary or brute force",
        "5. Execute with correct password"
    ]
    
    return challenge, steps
```

---

## Summary
- Binary analysis reveals functionality and vulnerabilities
- Disassembly converts machine code to readable instructions
- Patching modifies binary behavior
- Malware analysis requires careful sandboxing
- Reverse engineering defeats obfuscation

## Next Steps
- Set up IDA Pro or Ghidra
- Practice with CTF challenges
- Learn exploit development
- Study malware samples (safely)
