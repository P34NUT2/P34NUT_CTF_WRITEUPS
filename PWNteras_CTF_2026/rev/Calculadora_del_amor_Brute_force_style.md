# PWNteras CTF 2026 First Edition

# Calculadora del Amor (Love Calculator)

## Reversing: BruteForce

**Tags:** `reversing` `brute-force` `linux` `python` `threading`

---

## Description

> I don't remember :(

---

## Files

> This challenge provides an ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter `/lib64/ld-linux-x86-64.so.2`, BuildID[sha1]=71551c360ec3ab64cdb387acac36e356d5d952de, for GNU/Linux 3.2.0, stripped.

**File name:** `calculadora`

---

## Analysis

We can see a program that, when executed, asks you to enter your name. If the name is correct, it will print "true love" along with the flag. If incorrect, it simply says "not compatible."

Running `strings` on the binary gives us a partial view of the program's logic. From the output, we can identify that this is a simple C or C++ program:

```bash
strings ./calculadora 
/lib64/ld-linux-x86-64.so.2
fgets
stdin
puts
strlen
strcspn
__libc_start_main
toupper
libc.so.6
GLIBC_2.2.5
GLIBC_2.34
__gmon_start__
PTE1
H=8@@
cd}gvar`H
|evh 
L'~#aL `H
Lcfa'L~rH
gv~rgzprH
Lp#ari#}H
 Calculadora de ROMANCE 
Escribe tu nombre:
 No compatible
 AMOR VERDADERO 
;*3$"
GCC: (Debian 14.2.0-19) 14.2.0
.shstrtab
...
```

After analyzing the binary, we notice that it calls `toupper` on every character of the input — meaning **the program converts names to uppercase before comparing**. This significantly reduces the search space, since all comparisons happen in uppercase regardless of the original casing.

Since we're dealing with names, statistically most names are between **3 and 9 characters long**, and since all comparisons are uppercase letters only, a brute-force attack is feasible.

![brute-force-infographic-680 png](https://github.com/user-attachments/assets/2df4848c-d4d2-4665-81c7-a05e664e9675)

In terms of hardware, results may vary. With a dedicated GPU (e.g., RTX 5090) it will be faster; with integrated graphics and ~8 GB VRAM, expect longer runtimes — but it's still very doable.

---

## Theory

To solve this challenge you need to understand:

- **Brute force** — trying all possible combinations until the correct one is found
- **Thread usage** — running multiple attempts in parallel to speed up the attack
- **Linux bash commands** — running and interacting with ELF binaries
- **Python `os` and `subprocess` modules** — automating program execution
- **Patience** ;)

---

## Solution

### Step 1: Choose your wordlist

Since brute force is viable here, we follow the **KISS principle** (Keep It Simple, Stupid).

The first approach is to use a **SecLists** wordlist of common usernames/names. A great starting point is:

```
xato-net-10-million-usernames-dup.txt
```

This list contains the most commonly used usernames. If the name is not found there, try another SecList wordlist. As a last resort, write a script that generates all possible combinations (aaa, aab, aac, ..., zzz, and so on) — this is guaranteed to work eventually.

### Step 2: Write the brute-force script

We need something that can feed thousands of combinations to the binary. Python with `subprocess` and `concurrent.futures` is perfect for this.

**Important:** Using threads (`ThreadPoolExecutor`) is key — it allows testing many names simultaneously and drastically cuts down the total time.

```python
import subprocess
import concurrent.futures
import sys
import os

# --- CONFIGURATION ---
# 1. Path to the binary
BINARY = "./calculadora"

# 2. Path to your wordlist (SecList)
WORDLIST = "./xato-net-10-million-usernames-dup.txt"
# WORDLIST = "names.txt"  # Uncomment if the file is in the same directory

# 3. Number of threads (speed)
NUM_THREADS = 200  # 200 simultaneous attempts

def try_word(word):
    """
    Test a single word against the binary.
    """
    try:
        process = subprocess.run(
            [BINARY],
            input=f"{word}\n",
            capture_output=True,
            text=True,
            timeout=1  # Avoid hanging if the binary doesn't respond
        )
        
        output = process.stdout
        
        # Check for the success message
        if "AMOR VERDADERO" in output or "compatible" in output:
            if "No compatible" not in output:
                return True, word
                
    except Exception:
        pass
        
    return False, word

def main():
    # Validate file paths
    if not os.path.exists(BINARY):
        print(f"[!] Error: Cannot find binary at {BINARY}")
        sys.exit(1)

    if not os.path.exists(WORDLIST):
        print(f"[!] Error: Cannot find wordlist at {WORDLIST}")
        print("    Download it or correct the path in the script.")
        sys.exit(1)

    print(f"[*] Reading wordlist: {WORDLIST}...")
    
    words = []
    try:
        with open(WORDLIST, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Error reading file: {e}")
        sys.exit(1)

    total = len(words)
    print(f"[*] Loaded {total} words.")
    print(f"[*] Starting attack with {NUM_THREADS} threads...")
    print("[*] Press Ctrl+C to cancel.\n")

    found = False
    with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
        results = executor.map(try_word, words)
        
        count = 0
        for success, word in results:
            count += 1
            if count % 1000 == 0:
                sys.stdout.write(f"\r[~] Progress: {count}/{total} ({((count/total)*100):.1f}%)")
                sys.stdout.flush()
            
            if success:
                print(f"\n\n{'='*40}")
                print(f"[!!!] PASSWORD FOUND! [!!!]")
                print(f"       >> {word} <<")
                print(f"{'='*40}")
                found = True
                os._exit(0)

    if not found:
        print("\n\n[-] Attack finished. Password not found in this wordlist.")

if __name__ == "__main__":
    main()
```

### Step 3: Run and get the flag

Whether using a SecList wordlist or a full combination generator, the script will eventually find the correct name. Enter it in the binary to get the flag.

```bash
python bruteforce.py
[*] Reading wordlist: ./xato-net-10-million-usernames-dup.txt...
[*] Loaded 624370 words.
[*] Starting attack with 200 threads...
[*] Press Ctrl+C to cancel.

[~] Progress: 39000/624370 (6.2%)

========================================
[!!!] PASSWORD FOUND! [!!!]
       >> neumann <<
========================================
```

```bash
$ ./calculadora
💘 Calculadora de ROMANCE 💘
Escribe tu nombre:
neumann
❤️ AMOR VERDADERO ❤️
pwnteras_love{3l_4m0r_3s_pur4_matematica_c0raz0n}
```

**MACHINE PWNED!** 🎉

---

## Flag

> **`pwnteras_love{3l_4m0r_3s_pur4_matematica_c0raz0n}`**

---

## How to avoid

While this is a CTF challenge, the underlying vulnerability reflects a real-world anti-pattern: **hardcoded secrets with no rate limiting**. Here is how developers should avoid this in production:

### 1. **Never hardcode secrets in binaries**

Embedding passwords, keys, or sensitive strings directly in a binary exposes them to `strings`, Ghidra, IDA, or any disassembler. Anyone can extract them without even running the program.

**Secure alternatives:**
- Store secrets in environment variables or a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager).
- Use challenge-response authentication instead of comparing against a static string.

### 2. **Implement rate limiting and lockout**

Even if a secret must exist, brute-force attacks only work when the attacker can make unlimited attempts. Implement:

- **Attempt limits:** Lock the account or add a delay after N failed attempts.
- **Exponential backoff:** Each failed attempt doubles the wait time.
- **Temporary lockouts:** After 10 failures, lock for 30 minutes.

```python
import time

MAX_ATTEMPTS = 5
attempts = 0
lockout_time = 30  # seconds

def check_name(name: str, correct_name: str) -> bool:
    global attempts
    
    if attempts >= MAX_ATTEMPTS:
        print(f"Too many failed attempts. Try again in {lockout_time} seconds.")
        time.sleep(lockout_time)
        attempts = 0
        return False
    
    if name.upper() == correct_name.upper():
        attempts = 0
        return True
    else:
        attempts += 1
        time.sleep(0.5 * attempts)  # Progressive delay
        return False
```

### 3. **Obfuscation is not security**

The binary used `toupper()` and obscured the comparison logic, but this is security through obscurity — it does not prevent a brute-force attack, it only mildly increases the search space. Proper authentication should rely on cryptographic strength, not on the attacker not knowing the algorithm.

### 4. **Use cryptographic hashing for stored credentials**

If you must compare against a stored value, never compare plaintext. Use a proper password hashing algorithm:

```python
import hashlib
import hmac
import os

def store_credential(name: str) -> tuple:
    """Store a salted hash instead of the plaintext name."""
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', name.upper().encode(), salt, 100_000)
    return salt, key

def verify_credential(name: str, salt: bytes, stored_hash: bytes) -> bool:
    """Verify without exposing the original value."""
    attempt_hash = hashlib.pbkdf2_hmac('sha256', name.upper().encode(), salt, 100_000)
    return hmac.compare_digest(attempt_hash, stored_hash)
```

### 5. **Strip binaries but don't rely on it**

The binary was stripped (`stripped` in the file header), which removes debug symbols. This helps against casual analysis but doesn't stop a skilled reverser. Combine stripping with the measures above for meaningful protection.

### References

- [OWASP Brute Force Attack](https://owasp.org/www-community/attacks/Brute_force_attack)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST SP 800-63B — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

---

> **Author:** Jose Antonio Villafaña Montes de Oca
