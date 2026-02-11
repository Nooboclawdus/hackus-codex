# Impact Wording

How you describe impact directly affects severity rating and payout.

## Principles

1. **Be specific** — Not "steal data" but "access any user's email and phone number"
2. **Quantify when possible** — "affects all 50k users" vs "affects users"
3. **Describe attacker capability** — What can they DO, not just what's wrong
4. **Connect to business impact** — Data breach, financial loss, reputation

## By Vulnerability Type

### XSS

| Weak | Strong |
|------|--------|
| "Can execute JavaScript" | "Can hijack any user's session by stealing their session cookie" |
| "XSS in search" | "Stored XSS in comments allows attacker to steal credentials of any user who views the page, including admins" |

### SSRF

| Weak | Strong |
|------|--------|
| "Can make internal requests" | "Can access AWS metadata endpoint and retrieve IAM credentials, potentially compromising the entire AWS infrastructure" |
| "Server makes request to attacker URL" | "Blind SSRF allows port scanning of internal network and accessing internal admin panels" |

### IDOR

| Weak | Strong |
|------|--------|
| "Can access other users' data" | "Can access any user's private messages, financial records, and personal information including SSN" |
| "Authorization bypass" | "Can delete any user's account by changing the user_id parameter" |

### SQL Injection

| Weak | Strong |
|------|--------|
| "Database can be accessed" | "Full read access to database including user credentials, payment information, and admin secrets" |
| "SQL injection exists" | "SQL injection allows extraction of all user passwords and enables login as any user including administrators" |

### Authentication Bypass

| Weak | Strong |
|------|--------|
| "Can bypass login" | "Can authenticate as any user, including admin accounts, without knowing their password" |

## Impact Categories

### Confidentiality

- Personal Identifiable Information (PII)
- Financial data (credit cards, bank accounts)
- Credentials (passwords, API keys, tokens)
- Business secrets (source code, internal docs)
- Health information (HIPAA)

### Integrity

- Modify user data
- Tamper with transactions
- Change configurations
- Inject malicious content
- Corrupt data

### Availability

- Denial of service
- Resource exhaustion
- Account lockout
- Data deletion

## Severity Mapping

| Impact | Typical Severity |
|--------|------------------|
| Self-only, no real impact | Informational |
| Limited data exposure, requires unlikely conditions | Low |
| Sensitive data of other users | Medium |
| Mass data exposure, account takeover | High |
| Admin compromise, RCE, financial impact | Critical |

## Templates

### Generic High Impact

> An attacker can exploit this vulnerability to [ACTION] any [TARGET]'s [ASSET], leading to [CONSEQUENCE]. This affects all [NUMBER] users of the platform.

### Account Takeover

> This vulnerability allows an attacker to take complete control of any user account without authentication. The attacker can access all private data, perform actions as the victim, and lock the legitimate user out of their account.

### Data Breach

> An attacker can extract the complete database containing [NUMBER] user records including [SPECIFIC DATA TYPES]. This data can be used for identity theft, credential stuffing on other platforms, and targeted phishing.

---

See [Templates](templates.md) for full report structures.
