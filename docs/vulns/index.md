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
| **SQLi** *(coming soon)* | Inject SQL queries | Data theft, auth bypass, RCE |

## Access Control

| Vulnerability | Description | Typical Impact |
|---------------|-------------|----------------|
| [**IDOR**](idor/index.md) | Access objects via manipulated IDs | Data access, modification, deletion |
| **Broken Auth** *(coming soon)* | Authentication flaws | Account takeover |

## Server-Side

| Vulnerability | Description | Typical Impact |
|---------------|-------------|----------------|
| [**SSRF**](ssrf/index.md) | Make server send requests | Internal access, cloud compromise, RCE |
| **XXE** *(coming soon)* | XML external entity injection | File read, SSRF, DoS |

---

## Impact Quick Reference

| Severity | Examples |
|----------|----------|
| **Critical** | RCE, mass ATO, admin compromise, cloud takeover |
| **High** | ATO, sensitive data exposure, stored XSS on all users |
| **Medium** | Self-XSS chains, limited IDOR, reflected XSS |
| **Low** | Info disclosure, low-impact IDOR, verbose errors |

---

!!! tip "Just need payloads?"
    Check [Quick Reference](../quick/index.md) for copy-paste ready payloads.
