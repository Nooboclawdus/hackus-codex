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

- Cookie theft
- Password change via XSS
- Email change + password reset
- OAuth token theft
- Admin XSS → mass compromise

### [SSRF → RCE](ssrf-to-rce.md)

From internal requests to code execution:

- SSRF → Redis → webshell
- SSRF → Docker API → host compromise
- SSRF → FastCGI → PHP execution
- SSRF → AWS metadata → cloud takeover
- SSRF → Jenkins → CI/CD compromise

## Quick Chain Ideas

### Authentication Chains

| Start | Chain With | Result |
|-------|------------|--------|
| Open Redirect | OAuth callback | Token theft |
| XSS | Password change endpoint | ATO |
| IDOR on email | Password reset | ATO |
| Info disclosure | Brute force | Account access |

### Escalation Chains

| Start | Chain With | Result |
|-------|------------|--------|
| Low SSRF | Cloud metadata | IAM creds |
| Read SSRF | Internal services | Data/RCE |
| XSS on user | Admin views report | Admin compromise |
| Low IDOR | Sensitive endpoint | Critical data |

### Logic Chains

| Start | Chain With | Result |
|-------|------------|--------|
| Race condition | Payment flow | Financial impact |
| IDOR | Invite system | Org takeover |
| Parameter tampering | Discount codes | Financial impact |

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

## Coming Soon

- IDOR → Full Account Takeover
- CORS Misconfiguration Chains
- Cache Poisoning → XSS
- OAuth Misconfig Chains
- Race Condition Exploits
