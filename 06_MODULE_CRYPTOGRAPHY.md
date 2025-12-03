# Module 6: Cryptography & Attacks

## 6.1 Symmetric Encryption Attacks

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def symmetric_encryption_overview():
    """
    Symmetric: Same key for encryption and decryption
    Advantages: Fast, suitable for large data
    Disadvantages: Key distribution problem
    """
    
    algorithms_overview = {
        "DES": {
            "key_size": 56,
            "block_size": 64,
            "status": "DEPRECATED - Broken"
        },
        "3DES": {
            "key_size": 168,
            "block_size": 64,
            "status": "Legacy - Avoid"
        },
        "AES": {
            "key_size": 128/192/256,
            "block_size": 128,
            "status": "Recommended",
            "strength": "Unbroken (as of 2024)"
        },
        "ChaCha20": {
            "key_size": 256,
            "status": "Modern alternative to AES"
        }
    }

class EncryptionAttacks:
    """
    Common attacks on encryption systems
    """
    
    @staticmethod
    def ecb_penguin_attack():
        """
        ECB (Electronic Codebook) mode vulnerability:
        - Same plaintext block encrypts to same ciphertext block
        - Reveals patterns in data
        - Can reconstruct images from ciphertext
        """
        
        # ECB Vulnerability:
        # 1. Divide plaintext into blocks
        # 2. Encrypt each block separately
        # 3. Same plaintext = same ciphertext (reveals patterns!)
        
        # Example: Encrypting an image
        # Original image blocks: [RED, RED, BLUE, RED]
        # ECB ciphertext:        [0xFF, 0xFF, 0x42, 0xFF]
        # Attacker sees pattern and reconstructs image!
        
        # Solution: Use CBC, CTR, or authenticated encryption
        pass
    
    @staticmethod
    def padding_oracle_attack():
        """
        Padding oracle: If server tells you padding is invalid,
        you can decrypt any message without key
        """
        
        # Vulnerable: Server returns "Invalid padding" error
        # Attack: Change last byte, check response
        #         If invalid padding error gone, found correct byte!
        
        def padding_oracle_decrypt(ciphertext, oracle_function):
            """
            Decrypt one block using padding oracle
            """
            block_size = 16  # AES
            plaintext = b''
            
            # Work backwards from last byte
            for byte_position in range(1, block_size + 1):
                for guess in range(256):
                    # Modify ciphertext to test guess
                    modified = bytearray(ciphertext)
                    modified[-byte_position] ^= guess
                    
                    # Ask oracle if padding is valid
                    if oracle_function(bytes(modified)):
                        plaintext = bytes([guess]) + plaintext
                        break
            
            return plaintext
    
    @staticmethod
    def cbc_mode_attacks():
        """
        CBC mode vulnerabilities
        """
        
        # IV reuse: If same IV used with different messages/key
        #          Attacker can recover plaintext
        
        # Bitflip attack: Flipping bit in ciphertext
        #                 Flips corresponding bit in plaintext
        #                 Can modify messages!
        
        def bitflip_attack():
            """
            Modify ciphertext to modify plaintext
            """
            # Original: C1 = E(P1 ^ IV)
            # Modified: C1' = C1 ^ (desired_change)
            # Result: P1' = D(C1') ^ IV = P1 ^ desired_change
            pass
    
    @staticmethod
    def weak_key_detection():
        """
        Some keys have special properties making encryption weak
        """
        
        des_weak_keys = [
            0x0101010101010101,  # All zeros
            0xFEFEFEFEFEFEFEFE,  # All ones
            0xE0E0E0E0F1F1F1F1,  # Alternating
            0x1F1F1F1F0E0E0E0E,  # Alternating inverse
        ]
        
        # These keys encrypt to predictable values
        # Drastically weaken security
```

## 6.2 Asymmetric Encryption & RSA Attacks

```python
from math import gcd
from sympy import factorint, isprime

class RSAAttacks:
    """
    Attacks on RSA encryption
    """
    
    @staticmethod
    def small_exponent_attack():
        """
        RSA with small public exponent (e=3) vulnerable
        
        Attack: If message m^3 < N, no modular reduction
        Therefore: c = m^3 (not modular)
        Solution: m = cbrt(c)
        """
        
        def attack_e3(ciphertext, n):
            # Try to find cube root
            m = int(round(ciphertext ** (1/3)))
            if pow(m, 3, n) == ciphertext:
                return m
            return None
    
    @staticmethod
    def common_modulus_attack():
        """
        Using same N with different exponents
        
        If same plaintext encrypted with (e1, N) and (e2, N),
        attacker can decrypt without key
        """
        
        def recover_plaintext(c1, c2, e1, e2, n):
            # Extended GCD
            # e1 * x + e2 * y = gcd(e1, e2)
            gcd_val, x, y = extended_gcd(e1, e2)
            
            if gcd_val != 1:
                return None
            
            # m = c1^x * c2^y mod n
            plaintext = pow(c1, x, n) * pow(c2, y, n) % n
            return plaintext
    
    @staticmethod
    def weak_rsa_modulus():
        """
        If RSA modulus N = p * q where p, q are close,
        N can be factored efficiently
        """
        
        def factor_rsa_modulus(n):
            """
            Fermat's factorization for close primes
            """
            # If p ≈ q, then p and q ≈ sqrt(n)
            # Try x = ceil(sqrt(n))
            
            x = int(n ** 0.5) + 1
            
            while True:
                y_squared = x * x - n
                y = int(y_squared ** 0.5)
                
                if y * y == y_squared:
                    p = x + y
                    q = x - y
                    return p, q
                
                x += 1
    
    @staticmethod
    def timing_attack():
        """
        RSA decryption time varies based on plaintext
        Attacker can recover key through timing analysis
        """
        
        # Vulnerable: Time to compute m = c^d mod n
        # varies depending on bits of d
        
        # Attack:
        # 1. Time multiple decryptions
        # 2. Find which bits are 0/1 by comparing times
        # 3. Recover private exponent d
        
        def measure_decryption_time():
            """In real attack, run multiple times and average"""
            pass
    
    @staticmethod
    def low_private_exponent():
        """
        RSA with very small private exponent (d)
        Vulnerable to Wiener's attack
        """
        
        def wiener_attack(e, n):
            """
            Recover private exponent d from e and n
            """
            # Uses continued fractions
            # Beyond scope here, but devastating attack
            pass

def extended_gcd(a, b):
    """Extended GCD for RSA attacks"""
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y
```

## 6.3 Hash Function Attacks

```python
import hashlib

class HashAttacks:
    """
    Attacks on hash functions
    """
    
    @staticmethod
    def collision_attack():
        """
        Find two different messages with same hash
        Breaks hash function completely
        """
        
        # MD5: Fully broken (practical collisions)
        # SHA-1: Broken (used 9 million CPU years)
        # SHA-256: Not broken (continue using)
        
        def birthday_paradox():
            """
            By birthday paradox, collision exists after sqrt(2^n) hashes
            For SHA-256 (256-bit output):
            - Need ~2^128 hashes (impossible with current tech)
            
            For MD5 (128-bit):
            - Need ~2^64 hashes (feasible)
            """
            pass
    
    @staticmethod
    def preimage_attack():
        """
        Given hash, find message that produces it
        Harder than collision
        """
        
        # Brute force: Try all possible messages
        # For n-bit hash: Need ~2^n attempts
        
        def brute_force_hash(target_hash, max_length=8):
            """Try all strings up to length"""
            import itertools
            import string
            
            for length in range(1, max_length + 1):
                for attempt in itertools.product(string.ascii_letters, repeat=length):
                    message = ''.join(attempt).encode()
                    if hashlib.sha256(message).hexdigest() == target_hash:
                        return message
            
            return None
    
    @staticmethod
    def length_extension_attack():
        """
        Given: hash(secret + message)
        Find: hash(secret + message + extra_data)
        WITHOUT knowing secret!
        """
        
        # Vulnerable hash functions: MD5, SHA-1, SHA-256 (with Merkle-Damgård)
        # Solution: HMAC instead of plain hash
        
        # Attack: 
        # 1. Attacker knows message
        # 2. Attacker knows hash output
        # 3. Attacker can compute hash of extended message
        # 4. Bypasses authentication!
        
        def length_extension():
            """
            If API uses: hash(secret + user_input) for auth
            Attacker can add data and compute new valid hash
            """
            pass
    
    @staticmethod
    def rainbow_table_attack():
        """
        Pre-computed table of hash -> plaintext
        """
        
        # Small hashes or weak functions: Rainbow tables defeat them
        # Solution: Use salt + strong hash function
        
        def build_rainbow_table(wordlist, output_file):
            """Create hash -> password mapping"""
            table = {}
            for password in wordlist:
                h = hashlib.md5(password.encode()).hexdigest()
                table[h] = password
            return table
        
        def crack_with_rainbow_table(target_hash, table):
            """Look up hash in table"""
            return table.get(target_hash, None)

def password_hashing_best_practices():
    """
    Secure password hashing
    """
    
    from hashlib import pbkdf2_hmac
    import os
    
    def hash_password_secure(password):
        """
        Proper password hashing
        """
        # 1. Generate random salt
        salt = os.urandom(32)
        
        # 2. Use PBKDF2 (or bcrypt, Argon2)
        key = pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt,
            100000  # iterations - more = slower
        )
        
        # 3. Store salt + hash
        return salt + key
    
    def verify_password(stored, provided):
        """Verify password against stored hash"""
        salt = stored[:32]
        stored_hash = stored[32:]
        
        provided_key = pbkdf2_hmac(
            'sha256',
            provided.encode(),
            salt,
            100000
        )
        
        # Compare safely (constant time)
        import hmac
        return hmac.compare_digest(stored_hash, provided_key)
```

## 6.4 Side-Channel Attacks

```python
def side_channel_attacks():
    """
    Extract key from physical properties, not algorithm
    """
    
    attacks = {
        "Timing": "Decryption time varies, reveals key info",
        "Power": "Power consumption varies, reveals operations",
        "Electromagnetic": "EM emissions leak key",
        "Acoustic": "CPU noise leaks key",
        "Cache": "CPU cache hits/misses leak info",
        "Spectre/Meltdown": "CPU speculative execution leaks memory",
    }
    
    return attacks

def cache_timing_attack():
    """
    Measure cache access time to determine key
    """
    
    # AES implementation using lookup tables
    # Different key bytes cause different cache hits
    # Attacker times decryption to recover key
    
    def measure_decryption_time(key, ciphertext):
        """
        In real attack: Measure CPU cycles or wall time
        Different key bytes -> different cache patterns -> different times
        """
        import time
        start = time.perf_counter()
        # Decrypt...
        end = time.perf_counter()
        return end - start
```

## 6.5 Practice: Build a Cryptanalysis Tool

```python
class CryptanalysisToolkit:
    """
    Tools for breaking weak cryptography
    """
    
    @staticmethod
    def frequency_analysis(ciphertext):
        """
        Analyze letter frequency in ciphertext
        Useful for substitution ciphers
        """
        freq = {}
        for char in ciphertext.lower():
            if char.isalpha():
                freq[char] = freq.get(char, 0) + 1
        
        # Sort by frequency
        return sorted(freq.items(), key=lambda x: x[1], reverse=True)
    
    @staticmethod
    def brute_force_caesar(ciphertext):
        """
        Try all 26 Caesar cipher shifts
        """
        for shift in range(26):
            plaintext = ""
            for char in ciphertext:
                if char.isalpha():
                    base = ord('A') if char.isupper() else ord('a')
                    plaintext += chr((ord(char) - base - shift) % 26 + base)
                else:
                    plaintext += char
            
            print(f"Shift {shift}: {plaintext}")
    
    @staticmethod
    def vigenere_key_recovery(ciphertext):
        """
        Recover Vigenere cipher key using Kasiski examination
        """
        # Find repeated sequences
        # Calculate distances between them
        # GCD of distances likely to be key length
        
        def kasiski_examination():
            # Find all repeated trigrams
            trigrams = {}
            for i in range(len(ciphertext) - 2):
                trigram = ciphertext[i:i+3]
                if trigram in trigrams:
                    trigrams[trigram].append(i)
                else:
                    trigrams[trigram] = [i]
            
            # Find distances
            distances = []
            for positions in trigrams.values():
                if len(positions) > 1:
                    for i in range(len(positions) - 1):
                        distances.append(positions[i+1] - positions[i])
            
            # Key length is likely a common divisor
            return distances

class EncodingChecker:
    """
    Identify encoding schemes in data
    """
    
    @staticmethod
    def detect_encoding(data):
        """Guess encoding of data"""
        
        # Check for common patterns
        if all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in data):
            return "Base64"
        
        if all(c in "0123456789abcdefABCDEF " for c in data):
            return "Hexadecimal"
        
        if all(c in "01 " for c in data):
            return "Binary"
        
        return "Unknown"
```

---

## Summary
- Symmetric encryption (AES) broken by poor modes (ECB)
- Padding oracle completely breaks CBC mode
- RSA vulnerable to various mathematical attacks
- Hash function collisions devastating for security
- Side-channel attacks beat strong algorithms
- Cryptanalysis tools can break weak encryption

## Next Steps
- Study cryptography papers
- Practice with CTF crypto challenges
- Learn implementation attacks
- Understand defense mechanisms
