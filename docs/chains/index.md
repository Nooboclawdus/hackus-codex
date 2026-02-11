# Exploit Chains

Single bugs are good. Chains are better.

## What's a Chain?

Combining multiple vulnerabilities to achieve greater impact than any single bug.

Example: Low-severity open redirect + Self-XSS = Medium/High XSS

## Common Chains

| Chain | Result |
|-------|--------|
| Open Redirect + OAuth | Account takeover |
| XSS + CSRF | Bypass CSRF protection |
| IDOR + Info Disclosure | Privilege escalation |
| SSRF + Cloud Metadata | Cloud account compromise |
| SQL Injection + File Write | RCE |
| Race Condition + Balance | Financial impact |

## Documented Chains

*Coming soon:*

- XSS to Account Takeover
- SSRF to RCE
- IDOR to Full Data Access
- OAuth Misconfig Chains
- Cache Poisoning Chains

---

*Have a chain to share? [Contribute](../contributing.md)!*
