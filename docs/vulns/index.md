# Vulnerabilities

Methodology guides by vulnerability type. Each section follows the same structure:

1. **Overview** — What is it, why it matters
2. **Find** — Where and how to look
3. **Exploit** — Confirming and weaponizing
4. **Bypasses** — Evading protections
5. **Escalate** — Increasing impact

---

## Injection

| Vulnerability | Description | Typical Impact |
|---------------|-------------|----------------|
| [**XSS**](xss/index.md) | Execute JavaScript in victim's browser | Session hijacking, ATO, phishing |
| [**SQLi**](sqli/index.md) | Inject SQL queries | Data theft, auth bypass, RCE |
| [**Command Injection**](injection/command.md) | Execute OS commands | RCE |
| [**SSTI**](injection/ssti.md) | Server-side template injection | RCE |
| [**XXE**](injection/xxe.md) | XML external entity injection | File read, SSRF, DoS |
| [**NoSQL Injection**](injection/nosql.md) | NoSQL query manipulation | Auth bypass, data theft |
| [**Path Traversal**](injection/path-traversal.md) | Read arbitrary files | Source code, credentials |
| [**GraphQL**](injection/graphql.md) | GraphQL-specific attacks | Data exposure, DoS |
| [**File Upload**](injection/file-upload.md) | Malicious file upload | RCE, XSS |

## Server-Side

| Vulnerability | Description | Typical Impact |
|---------------|-------------|----------------|
| [**SSRF**](ssrf/index.md) | Make server send requests | Internal access, cloud compromise, RCE |
| [**API Attacks**](injection/api.md) | API-specific vulnerabilities | Data exposure, auth bypass |

## Access Control

| Vulnerability | Description | Typical Impact |
|---------------|-------------|----------------|
| [**IDOR**](idor/index.md) | Access objects via manipulated IDs | Data access, modification, ATO |
| [**CORS**](access-control/cors.md) | Cross-origin misconfigurations | Data theft |
| [**Mass Assignment**](access-control/mass-assignment.md) | Modify protected fields | Privilege escalation |

## Authentication

| Vulnerability | Description | Typical Impact |
|---------------|-------------|----------------|
| [**OAuth**](auth/oauth.md) | OAuth flow attacks | Account takeover |
| [**JWT**](auth/jwt.md) | JWT manipulation | Auth bypass, privilege escalation |
| [**2FA Bypass**](auth/2fa.md) | Two-factor bypasses | Account takeover |
| [**Session Attacks**](auth/session.md) | Session management flaws | Session hijacking |
| [**Password Reset**](auth/password-reset.md) | Reset flow vulnerabilities | Account takeover |
| [**SAML**](auth/saml.md) | SAML assertion attacks | Auth bypass, impersonation |

## Logic Flaws

| Vulnerability | Description | Typical Impact |
|---------------|-------------|----------------|
| [**Race Conditions**](logic/race-conditions.md) | TOCTOU, parallel requests | Limit bypass, double-spend |
| [**Rate Limiting**](logic/rate-limiting.md) | Rate limit bypasses | Brute force, enumeration |
| [**Payment Bypass**](logic/payment.md) | Payment flow manipulation | Financial fraud |
| [**Captcha Bypass**](logic/captcha-bypass.md) | Captcha evasion | Automation, spam |
| [**Open Redirect**](logic/open-redirect.md) | Unvalidated redirects | Phishing, token theft |

## Client-Side

| Vulnerability | Description | Typical Impact |
|---------------|-------------|----------------|
| [**CSRF**](client-side/csrf.md) | Cross-site request forgery | Unauthorized actions |
| [**Clickjacking**](client-side/clickjacking.md) | UI redressing | Unauthorized clicks |
| [**postMessage**](client-side/postmessage.md) | postMessage vulnerabilities | XSS, data theft |
| [**Prototype Pollution**](client-side/prototype-pollution.md) | JS prototype manipulation | XSS, RCE |
| [**Tab Nabbing**](client-side/tab-nabbing.md) | window.opener abuse | Phishing |
| [**WebSocket**](client-side/websocket.md) | WebSocket attacks | CSWSH, auth bypass |

## Infrastructure

| Vulnerability | Description | Typical Impact |
|---------------|-------------|----------------|
| [**Subdomain Takeover**](infrastructure/subdomain-takeover.md) | Dangling DNS records | Phishing, cookie theft |
| [**Cache Poisoning**](infrastructure/cache-poisoning.md) | Web cache attacks | XSS, defacement |
| [**Request Smuggling**](infrastructure/request-smuggling.md) | HTTP desync | Cache poisoning, bypass |
| [**Misconfigurations**](infrastructure/misconfig.md) | Server/cloud misconfig | Data exposure, access |

---

## Impact Quick Reference

| Severity | Examples |
|----------|----------|
| **Critical** | RCE, mass ATO, admin compromise, cloud takeover |
| **High** | ATO, sensitive data exposure, stored XSS on all users |
| **Medium** | Self-XSS chains, limited IDOR, reflected XSS |
| **Low** | Info disclosure, low-impact IDOR, verbose errors |
