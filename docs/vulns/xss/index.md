# XSS - Cross-Site Scripting

## TL;DR

Inject malicious scripts into web pages viewed by other users. Steal sessions, phish credentials, or take over accounts.

**Types:**

- **Reflected** — Payload in request, reflected in response
- **Stored** — Payload saved server-side, executed for all viewers
- **DOM-based** — Payload processed by client-side JavaScript

## Quick Links

- [Finding XSS](find.md) — Where to look, how to test
- [Exploitation](exploit.md) — From alert() to impact
- [Bypasses](bypasses.md) — Filter and WAF evasion
- [Escalation](escalate.md) — Maximize impact
- [Payloads](../../quick/xss.md) — Copy-paste ready

## Impact

| Scenario | Severity |
|----------|----------|
| Self-XSS only | Informational |
| Reflected, requires interaction | Low-Medium |
| Reflected in sensitive context | Medium-High |
| Stored, affects other users | High |
| Stored + admin/privileged users | Critical |
| Account takeover chain | Critical |

## Quick Test

```html
<script>alert(document.domain)</script>
"><img src=x onerror=alert(1)>
'-alert(1)-'
${alert(1)}
javascript:alert(1)
```

If basic payloads fail, check [Bypasses](bypasses.md).
