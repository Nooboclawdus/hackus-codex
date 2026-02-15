---
title: JavaScript Analysis
description: Techniques for analyzing JavaScript to find endpoints, secrets, and vulnerabilities
tags:
  - client-side
  - recon
  - secrets
  - xss
---

# JavaScript Analysis

## Overview

JavaScript analysis is essential for modern bug bounty hunting. JS files contain endpoints, API keys, authentication logic, and potential vulnerabilities that aren't visible in the HTML.

**Goals:** Find hidden endpoints, secrets, XSS sinks, business logic, and authentication flows.

## Quick Wins

```bash
# Extract all JS URLs from a page
curl -s https://target.com | grep -oP 'src="[^"]*\.js"' | cut -d'"' -f2

# Download all JS files
cat js_urls.txt | xargs -I{} wget {}

# Quick secret scan
grep -rEi "(api[_-]?key|secret|token|password|auth)" *.js

# Find endpoints
grep -rEoP '["'"'"'](/[a-zA-Z0-9/_-]+)["'"'"']' *.js | sort -u
```

## Methodology

### 1. Collection

**Passive:**
```bash
# Wayback Machine
waybackurls target.com | grep "\.js$" | sort -u

# Common Crawl
echo target.com | gau --subs | grep "\.js$"

# AlienVault OTX
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/target.com/url_list" | jq -r '.url_list[].url' | grep "\.js$"
```

**Active:**
```bash
# Crawl with all resources
gospider -s https://target.com -c 10 -d 3 --js | grep "\.js$"

# Headless browser (captures dynamically loaded JS)
playwright-crawler https://target.com --extract-js

# Burp Suite passive scan (captures all loaded resources)
```

### 2. Beautification

```bash
# js-beautify
js-beautify -f bundle.min.js -o bundle.js

# Prettier (better for modern JS)
prettier --write bundle.min.js

# Online: beautifier.io, de4js (also deobfuscates)
```

### 3. Source Maps

```bash
# Check for source maps
curl -s https://target.com/bundle.js | grep -i "sourceMappingURL"

# Download source map
curl -s https://target.com/bundle.js.map -o bundle.js.map

# Extract original source
source-map-explorer bundle.js.map
# or
npm install -g source-map-visualize
```

**Common paths:**
```
/static/js/main.chunk.js.map
/static/js/vendors~main.chunk.js.map
/_next/static/chunks/main.js.map
/assets/index.js.map
```

### 4. Secret Detection

**Patterns:**
```javascript
// API Keys
['"](AKIA[0-9A-Z]{16})['"]
['"](AIza[0-9A-Za-z\-_]{35})['"]  // Google API
['"](sk_live_[0-9a-zA-Z]{24})['"] // Stripe
['"](ghp_[0-9a-zA-Z]{36})['"]     // GitHub PAT

// AWS
['"]([A-Za-z0-9/+=]{40})['"]      // AWS Secret Key
['"](ASIA[0-9A-Z]{16})['"]        // AWS Session Token

// JWT
['"]eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*['"]

// Generic
['"][0-9a-f]{32,64}['"]           // Hex tokens
['"][A-Za-z0-9+/]{40,}={0,2}['"]  // Base64 secrets
```

**Tools:**
```bash
# TruffleHog
trufflehog filesystem ./js-files/

# Gitleaks (also works on files)
gitleaks detect --source ./js-files/

# Custom nuclei template
nuclei -t js-secrets.yaml -l js_urls.txt
```

### 5. Endpoint Extraction

**Regex patterns:**
```javascript
// API endpoints
['"](\/api\/[^'"]+)['"]
['"](\/v[0-9]+\/[^'"]+)['"]
['"](https?:\/\/[^'"]+)['"]

// GraphQL
query\s+\w+\s*\{
mutation\s+\w+\s*\{
__schema

// Fetch/axios calls
fetch\(['"](/[^'"]+)['"]
axios\.(get|post|put|delete)\(['"](/[^'"]+)['"]
\.request\(\{[^}]*url:\s*['"]([^'"]+)['"]
```

**Tools:**
```bash
# LinkFinder
python3 linkfinder.py -i https://target.com/bundle.js -o cli

# JSParser
python3 JSParser.py -u https://target.com/bundle.js

# getJS + regex
getJS --url https://target.com | xargs -I{} curl -s {} | grep -oP '["'"'"'](/[a-zA-Z0-9/_-]+)["'"'"']'
```

### 6. XSS Sink Analysis

**Dangerous sinks:**
```javascript
// DOM manipulation
element.innerHTML = userInput;
element.outerHTML = userInput;
document.write(userInput);
document.writeln(userInput);

// JavaScript execution
eval(userInput);
Function(userInput);
setTimeout(userInput);
setInterval(userInput);

// URL manipulation
location = userInput;
location.href = userInput;
location.assign(userInput);
location.replace(userInput);

// jQuery specific
$(userInput);
$(element).html(userInput);
$(element).append(userInput);
$.globalEval(userInput);
```

**Source tracking:**
```javascript
// User-controlled sources
location.hash
location.search
location.href
document.URL
document.documentURI
document.referrer
window.name
postMessage data
localStorage/sessionStorage
document.cookie
```

**Tool:**
```bash
# DOM Invader (Burp extension)
# Retire.js (vulnerable libraries)
retire --js --path ./js-files/
```

### 7. Authentication Logic

**Look for:**
```javascript
// Token handling
localStorage.setItem("token", ...)
sessionStorage.setItem("auth", ...)
document.cookie = "session=..."

// Auth checks
if (isAuthenticated) { ... }
if (user.role === "admin") { ... }
if (token.exp > Date.now()) { ... }

// API headers
headers: { "Authorization": "Bearer " + token }
headers: { "X-API-Key": apiKey }

// Login/logout flows
function login(credentials) { ... }
function logout() { ... }
function refreshToken() { ... }
```

### 8. Business Logic

**Interesting patterns:**
```javascript
// Discount/pricing logic
if (couponCode === "SPECIAL") { discount = 0.5; }
calculatePrice(items, discount)

// Feature flags
if (featureFlags.newCheckout) { ... }
if (user.plan === "enterprise") { ... }

// Admin functionality
if (isAdmin) { showAdminPanel(); }
adminEndpoints = ["/admin/users", "/admin/config"]

// Hidden parameters
params = { debug: true, internal: true }
```

## Automation

### bbjs (Custom Tool)
```bash
# Full scan
bbjs https://target.com --sourcemaps --secrets --stealth

# Batch mode
bbjs --targets-file urls.txt --out ./results/
```

### Nuclei JS Templates
```yaml
# js-secrets.yaml
id: js-secrets
info:
  name: JavaScript Secrets
  severity: high

requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: or
    matchers:
      - type: regex
        regex:
          - "AKIA[0-9A-Z]{16}"
          - "AIza[0-9A-Za-z\\-_]{35}"
          - "sk_live_[0-9a-zA-Z]{24}"
```

## Real-World Examples

### Exposed AWS Keys (Uber)
```javascript
// Found in vendor.js
const awsConfig = {
  accessKeyId: "AKIAIOSFODNN7EXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
};
```
**Impact:** Full AWS access, $10,000+ bounty

### Hidden Admin Endpoint (Shopify)
```javascript
// Found in main.js
const adminRoutes = [
  "/admin/internal/users",
  "/admin/internal/debug"
];
```
**Impact:** Access to internal admin panel

### Client-Side Auth Bypass (HackerOne Program)
```javascript
// Found in auth.js
if (user.role === "admin" || debugMode) {
  showAdminPanel();
}
// debugMode controllable via URL param
```
**Impact:** Admin access by setting `?debug=true`

## Tools Summary

| Tool | Purpose |
|------|---------|
| [LinkFinder](https://github.com/GerbenJavado/LinkFinder) | Endpoint extraction |
| [JSParser](https://github.com/nicholascwm/JSParser) | Endpoint extraction |
| [getJS](https://github.com/003random/getJS) | JS file collection |
| [retire.js](https://retirejs.github.io/retire.js/) | Vulnerable library detection |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Secret detection |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Secret detection |
| [source-map-explorer](https://github.com/danvk/source-map-explorer) | Source map analysis |
| [bbjs](private) | Full JS recon suite |

## References

- [Bug Bounty Bootcamp - JS Analysis](https://nostarch.com/bug-bounty-bootcamp)
- [PortSwigger - DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)
- [OWASP - Reviewing Code for OS Injection](https://owasp.org/www-project-code-review-guide/)

---

**Severity:** Varies (Info → Critical depending on findings)  
**CWE:** CWE-200 (Exposure of Sensitive Information)
