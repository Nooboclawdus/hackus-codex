# IDOR Escalation

## Impact Levels

| Access | Impact | Severity |
|--------|--------|----------|
| Read other's data | Info disclosure | Medium-High |
| Modify other's data | Data tampering | High |
| Delete other's data | DoS/Data loss | High |
| Account takeover | Full compromise | Critical |
| Access admin functions | Privilege escalation | Critical |

## Escalation Chains

### IDOR → Account Takeover

```
1. Find IDOR on /api/users/{id}/settings
2. Change victim's email to yours
3. Trigger password reset
4. Own the account
```

### IDOR → Financial Fraud

```
1. Access /api/invoices/{id}
2. Find payment method IDs
3. Modify payment destination
4. Redirect funds
```

### IDOR → Full Database Dump

```python
# If sequential IDs, dump everything
for i in range(1, 1000000):
    data = get_user(i)
    if data:
        save_to_file(data)
```

## Maximizing Impact

### 1. Enumerate Everything

Don't stop at one ID - show the scale:

```bash
# Count accessible records
total=0
for id in $(seq 1 10000); do
  if curl -s "https://target/api/users/$id" | grep -q "email"; then
    ((total++))
  fi
done
echo "Exposed users: $total"
```

### 2. Find Sensitive Data

Prioritize endpoints with:
- PII (emails, phones, addresses)
- Financial data (cards, bank accounts)
- Credentials (API keys, tokens)
- Health/legal data (HIPAA, GDPR)

### 3. Demonstrate Actions

```http
# Read → show data
# Write → change something recoverable
# Delete → use test account only

# Always: Screenshot before/after
```

## Report Writing Tips

### Show Scale
> "This vulnerability affects all 50,000 users in the database."

### Show Sensitivity
> "Exposed data includes: full names, email addresses, phone numbers, and hashed passwords."

### Show Chain
> "By chaining this IDOR with the password reset flow, an attacker can take over any account."

### CVSS Considerations

- **Confidentiality**: What data is exposed?
- **Integrity**: Can data be modified?
- **Availability**: Can data be deleted?
- **Scope**: Does it affect other components?

## Real-World Examples

### Facebook (2019)
- IDOR exposed phone numbers of 419M users
- Impact: Mass data scraping

### Bumble (2020)
- API IDOR leaked user data globally
- Impact: 95M accounts exposed

### Instagram (2019)
- IDOR in business accounts
- Impact: Contact info of millions

## Prevention Notes

For report recommendations:
```
1. Implement object-level authorization
2. Use unpredictable identifiers (UUIDs)
3. Validate ownership on every request
4. Log and monitor access patterns
```
