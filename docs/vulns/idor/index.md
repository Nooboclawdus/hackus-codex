# IDOR - Insecure Direct Object Reference

## TL;DR

Access or modify objects belonging to other users by changing identifiers (IDs, filenames, etc.).

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

## Where to Look

- [ ] User profile endpoints
- [ ] Document/file access
- [ ] API endpoints with numeric IDs
- [ ] UUID/GUID parameters
- [ ] Order/transaction references
- [ ] Message/notification endpoints

## Methodology

### 1. Create Two Test Accounts

- Account A (attacker)
- Account B (victim)

### 2. Identify Object References

Look for IDs in:
- URL paths (`/user/123`)
- Query params (`?id=123`)
- POST body (`{"user_id": 123}`)
- Headers
- Cookies

### 3. Cross-Account Testing

1. Login as Account A
2. Capture request with Account B's ID
3. Check if access granted

### 4. ID Types to Try

| Type | Example | Test |
|------|---------|------|
| Sequential | `123` | `124`, `122` |
| UUID | `550e8400-e29b-41d4-a716-446655440000` | Other user's UUID |
| Encoded | `base64(123)` | `base64(124)` |
| Hashed | `md5(123)` | Predict/bruteforce |

## Bypasses

### Parameter Pollution

```
?id=123&id=124
?id[]=123&id[]=124
```

### HTTP Method Change

```
GET /api/user/123 → 403
POST /api/user/123 → 200?
```

### Wrap ID in Array/Object

```json
{"id": "123"}
{"id": ["123"]}
{"id": {"value": "123"}}
```

### Add Your ID Too

```json
{"victim_id": "123", "my_id": "456"}
```

---

*Full methodology coming soon.*
