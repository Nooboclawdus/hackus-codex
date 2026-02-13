# Exploit Chains

Single bugs are good. Chains are better.

## What's a Chain?

Combining multiple vulnerabilities (or techniques) to achieve greater impact than any single bug.

| Single Bug | Impact | Chained | Impact |
|------------|--------|---------|--------|
| Self-XSS | None | Self-XSS + CSRF | Medium |
| Low IDOR | Low | IDOR + Info Disclosure | High |
| Blind SSRF | Low | SSRF + Redis | Critical |
| Open Redirect | Low | OAuth + Open Redirect | High |

## Documented Chains

### [XSS → Account Takeover](xss-to-ato.md)

Turn XSS into full account compromise:

- Cookie/token theft
- Password change via XSS
- Email change + password reset
- OAuth token exfiltration
- Prototype pollution → XSS → ATO
- Admin XSS → mass compromise

### [SSRF → RCE](ssrf-to-rce.md)

From internal requests to code execution:

- SSRF → Redis → webshell/SSH key
- SSRF → Docker API → host compromise
- SSRF → FastCGI → PHP execution
- SSRF → AWS metadata → cloud takeover
- SSRF → Jenkins → CI/CD compromise
- XXE → SSRF → RCE

### [OAuth → Account Takeover](oauth-to-ato.md)

From OAuth misconfigs to full account access:

- redirect_uri bypass → token theft
- Missing state → CSRF account linking
- response_mode=web_message → postMessage theft
- XSS on callback domain → code exfil
- Pre-account takeover (classic-federated merge)
- SSRF → cloud metadata → OAuth secrets

### [Cache Poisoning → XSS](cache-poison-to-xss.md)

From cache manipulation to persistent XSS:

- Unkeyed header → cached XSS
- Request smuggling → cache poison
- CSPT + cache deception
- Cookie poisoning → cached XSS
- Fat GET → cache poison
- Static extension abuse

## Quick Chain Ideas

### Authentication Chains

| Start | Chain With | Result |
|-------|------------|--------|
| Open Redirect | OAuth callback | Token theft |
| XSS | Password change endpoint | ATO |
| IDOR on email | Password reset | ATO |
| Info disclosure | Brute force | Account access |
| postMessage | OAuth tokens | ATO |

### Escalation Chains

| Start | Chain With | Result |
|-------|------------|--------|
| Low SSRF | Cloud metadata | IAM creds |
| Read SSRF | Internal Redis | RCE |
| XSS on user | Admin views report | Admin compromise |
| Low IDOR | Sensitive endpoint | Critical data |
| Cache poison | Static resources | Mass XSS |

### Logic Chains

| Start | Chain With | Result |
|-------|------------|--------|
| Race condition | 2FA verification | Auth bypass |
| Race condition | Payment flow | Financial impact |
| IDOR | Invite system | Org takeover |
| Prototype pollution | XSS gadget | DOM XSS |

## Chain Methodology

### 1. Map Impact Potential

For each bug, ask:
- What can I **read**?
- What can I **write**?
- What can I **trigger**?

### 2. Identify Trust Boundaries

- User → Admin
- External → Internal
- Unauthenticated → Authenticated
- Client → Server
- Cache → Origin

### 3. Connect the Dots

```
Bug A allows X
X gives access to Y
Y contains credentials for Z
Z has permissions for RCE
```

### 4. Document the Full Chain

Always show:
1. Starting vulnerability
2. Each step in chain
3. Final impact
4. Why each step is necessary

---

## Cross-Signal Connections

Key chains from technique analysis:

| Chain | Files Involved |
|-------|---------------|
| SSRF → Cloud → OAuth | ssrf/bypass + cloud-metadata + auth/oauth |
| Prototype Pollution → XSS | client-side/prototype-pollution + xss/dom |
| Race → 2FA Bypass | logic/race-conditions + auth/2fa-bypass |
| Cache → CSPT → ATO | cache-poisoning + auth/session |
| CORS + Subdomain → Theft | cors + subdomain-takeover + session |
| Request Smuggling → Cache → XSS | request-smuggling + cache-poisoning + xss |

---
*See [Quick Payloads](../quick/index.md) for copy-paste ready exploits.*
