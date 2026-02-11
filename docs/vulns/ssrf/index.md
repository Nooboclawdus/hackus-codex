# SSRF - Server-Side Request Forgery

## TL;DR

Trick the server into making requests on your behalf. Access internal services, cloud metadata, or pivot to RCE.

**Types:**

- **Basic** — Full control of URL, see response
- **Blind** — Request made but no response visible
- **Partial** — Control part of URL (path, params)

## Quick Links

- [Finding SSRF](find.md) — Where to look
- [Exploitation](exploit.md) — From request to impact
- [Escalation](escalate.md) — Cloud metadata, internal services, RCE
- [Payloads](../../quick/ssrf.md) — Copy-paste ready

## Impact

| Scenario | Severity |
|----------|----------|
| Blind SSRF, no clear impact | Low |
| Read internal resources | Medium |
| Access cloud metadata | High |
| Internal service compromise | High-Critical |
| RCE via internal service | Critical |

## Quick Test

```
http://127.0.0.1
http://169.254.169.254/latest/meta-data/
http://[::1]
http://your-burp-collaborator.net
```

---

*Full methodology pages coming soon. See [payloads](../../quick/ssrf.md) for now.*
