# Client-Side Vulnerabilities

Attacks that execute in the victim's browser, exploiting trust relationships and client-side security mechanisms.

## Categories

| Vulnerability | Description | Impact |
|--------------|-------------|--------|
| [CSRF](csrf.md) | Force authenticated actions | State changes, data modification |
| [Clickjacking](clickjacking.md) | UI redressing attacks | Unintended clicks, actions |
| [PostMessage](postmessage.md) | Cross-origin messaging flaws | XSS, data theft |
| [Prototype Pollution](prototype-pollution.md) | Object prototype injection | XSS, auth bypass |

## Quick Detection

### CSRF
```bash
# Check for missing tokens
curl -X POST https://target/action -d 'param=value'
# Look for missing: csrf, token, nonce parameters
# Check SameSite cookie attribute
```

### Clickjacking
```bash
# Check framing headers
curl -sI https://target | grep -iE "x-frame|frame-ancestors"
```

### PostMessage
```javascript
// DevTools console
getEventListeners(window).message
// Search JS for: addEventListener("message"
```

### Prototype Pollution
```
https://target/?__proto__[test]=polluted
// Console: console.log({}.test)
```

## Common Patterns

### Trust Boundaries

| Attack | Exploits Trust In |
|--------|------------------|
| CSRF | Session cookies sent automatically |
| Clickjacking | UI appearance vs reality |
| PostMessage | Origin validation |
| Prototype Pollution | Object property chains |

### Browser Security Features

| Feature | Protects Against |
|---------|-----------------|
| SameSite cookies | CSRF |
| X-Frame-Options | Clickjacking |
| CSP frame-ancestors | Clickjacking |
| Object.freeze() | Prototype pollution |

## Testing Approach

1. **Identify sensitive actions** - Password change, email change, transfers
2. **Check protections** - Tokens, headers, origin validation
3. **Test bypasses** - Method switching, token removal, origin tricks
4. **Chain vulnerabilities** - CSRF + XSS, Clickjacking + Self-XSS

## Tools

| Tool | Purpose |
|------|---------|
| Caido | Generate CSRF PoC, intercept messages |
| DOM Invader | Automated client-side testing |
| Browser DevTools | Event listeners, postMessage inspection |
