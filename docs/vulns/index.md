# Vulnerabilities

Methodology guides by vulnerability type. Each section follows the same structure:

1. **Overview** — What is it, why it matters
2. **Find** — Where and how to look
3. **Exploit** — Confirming and weaponizing
4. **Bypasses** — Evading protections
5. **Escalate** — Increasing impact

## Web Application

| Vulnerability | Description | Impact |
|---------------|-------------|--------|
| [XSS](xss/index.md) | Cross-Site Scripting | Session hijacking, phishing, keylogging |
| [SSRF](ssrf/index.md) | Server-Side Request Forgery | Internal access, cloud metadata, RCE |
| [IDOR](idor/index.md) | Insecure Direct Object Reference | Data access, privilege escalation |

## Coming Soon

- SQL Injection
- Authentication Bypass
- Business Logic
- Race Conditions
- File Upload
- XXE
- Open Redirect
- CSRF

---

!!! tip "Just need payloads?"
    Check [Quick Reference](../quick/index.md) for copy-paste ready payloads.
