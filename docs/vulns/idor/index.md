# IDOR - Insecure Direct Object Reference

## TL;DR

Access or modify objects belonging to other users by changing identifiers (IDs, filenames, etc.). Simple but often critical.

## Quick Test

```
GET /api/user/123/profile → Change to /api/user/124/profile
GET /documents/invoice_001.pdf → Try invoice_002.pdf
POST /api/delete?id=100 → Try id=101
```

## Impact

| Scenario | Severity |
|----------|----------|
| Read own data with different ID | Informational |
| Read other user's non-sensitive data | Low |
| Read other user's sensitive data (PII) | Medium-High |
| Modify other user's data | High |
| Delete other user's data | High |
| Access admin resources | Critical |
| Financial data / transactions | Critical |

## Where to Look

### Common IDOR Locations

- [ ] User profile endpoints (`/user/ID/profile`)
- [ ] Document/file access (`/documents/ID`)
- [ ] API endpoints with IDs (`/api/orders/ID`)
- [ ] Download endpoints (`/download?file=ID`)
- [ ] Message/inbox endpoints
- [ ] Transaction/payment history
- [ ] Settings/preferences

### Parameter Names to Target

```
id, user_id, account_id
uid, uuid, guid
doc_id, document_id, file_id
order_id, transaction_id
ref, reference
number, num, no
handle, username, email
```

### Hidden IDORs

- [ ] UUIDs in API responses (not in URL)
- [ ] Base64 encoded IDs
- [ ] Hashed/encrypted IDs (predictable?)
- [ ] GraphQL node IDs
- [ ] Nested objects in JSON

## Methodology

### 1. Create Two Test Accounts

- **Account A** (attacker) — your main test account
- **Account B** (victim) — secondary account with different data

### 2. Map Object References

Identify all IDs/references in:

```
URL path:       /user/123/orders
Query params:   ?user_id=123&order_id=456
POST body:      {"user_id": 123, "action": "delete"}
Headers:        X-User-ID: 123
Cookies:        user=123
```

### 3. Cross-Account Testing

1. Login as Account A
2. Capture request containing Account B's ID
3. Send request with Account A's session
4. Check if access granted

### 4. Document What You Can Do

| Action | Test |
|--------|------|
| **Read** | Can you view others' data? |
| **Create** | Can you create on behalf of others? |
| **Update** | Can you modify others' data? |
| **Delete** | Can you delete others' data? |

## ID Types & Bypass

### Sequential IDs

```
123 → 124, 122, 125
```

Just increment/decrement.

### UUIDs

```
550e8400-e29b-41d4-a716-446655440000
```

Harvest UUIDs from:
- API responses
- WebSocket messages
- HTML/JS source
- Error messages

### Encoded IDs

```bash
# Base64
MTIz → base64 -d → 123
# Try: MTI0 (124)

# Hex
7b → 123
# Try: 7c (124)
```

### Hashed IDs

If IDs look hashed:
```
a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3
```

Try common patterns:
```bash
echo -n "123" | sha256sum
echo -n "user_123" | md5sum
```

### Signed IDs

If IDs have signatures/MACs:
```
123.HMAC_SIGNATURE
```

Try:
- Removing signature
- Using signature from another valid ID
- Signature confusion attacks

## Bypass Techniques

### Parameter Pollution

```bash
# Multiple params
?id=123&id=124

# Array syntax
?id[]=123&id[]=124

# JSON array
{"id": [123, 124]}
```

### HTTP Method Change

```bash
GET /api/user/124 → 403
POST /api/user/124 → 200?
PUT /api/user/124 → 200?
```

### Wrap in Object

```json
// Original
{"id": "123"}

// Try wrapping
{"id": {"value": "123"}}
{"id": ["123"]}
{"user": {"id": "123"}}
```

### Change Content-Type

```bash
# From JSON to form
Content-Type: application/json
{"user_id": 123}

# To
Content-Type: application/x-www-form-urlencoded
user_id=123
```

### Add Your ID

```json
{"victim_id": 124, "my_id": 123}
```

Sometimes having both IDs bypasses checks.

### Version Rollback

```bash
/api/v2/user/124 → 403
/api/v1/user/124 → 200?
/api/user/124 → 200?
```

### Path Traversal in ID

```bash
/api/user/124 → 403
/api/user/./124 → 200?
/api/user/123/../124 → 200?
```

## GraphQL IDOR

```graphql
# Query with node ID
query {
  node(id: "VXNlcjoxMjM=") {  # base64: User:123
    ... on User {
      email
      privateData
    }
  }
}

# Try changing the ID
query {
  node(id: "VXNlcjoxMjQ=") {  # base64: User:124
    ... on User {
      email
      privateData
    }
  }
}
```

## Automation

### Burp Extension: Autorize

1. Login as low-priv user
2. Browse as high-priv user
3. Autorize replays requests with low-priv cookies
4. Highlights access control issues

### Manual with ffuf

```bash
# Enumerate user IDs
ffuf -u "https://target.com/api/user/FUZZ/profile" \
     -w <(seq 1 1000) \
     -H "Cookie: session=YOUR_SESSION" \
     -fc 403,404
```

---

## PoC Template

```markdown
## Summary
IDOR in [endpoint] allows accessing/modifying other users' [resource].

## Steps
1. Login as User A (attacker)
2. Navigate to [resource] and capture request
3. Change [parameter] from A's ID to B's ID
4. Observe: B's data is returned/modified

## Impact
Attacker can [read/modify/delete] any user's [data type]:
- Personal information (name, email, address)
- [Other sensitive data]
- Affects all [NUMBER] users

## Proof
[Screenshot showing different user's data]
```
