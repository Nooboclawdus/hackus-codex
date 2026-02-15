---
title: Recon Methodology
description: Quick reference for bug bounty reconnaissance
tags:
  - recon
  - methodology
  - quick-ref
---

# Recon Methodology

## Quick Checklist

```
[ ] Scope review
[ ] Subdomain enumeration
[ ] Port scanning
[ ] Technology fingerprinting
[ ] Content discovery
[ ] JavaScript analysis
[ ] Parameter discovery
[ ] API enumeration
```

## Phase 1: Passive Recon

### Subdomain Enumeration

```bash
# Subfinder (recommended)
subfinder -d target.com -o subs.txt

# Amass (comprehensive but slow)
amass enum -passive -d target.com -o amass.txt

# Historical subdomains
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Combine sources
cat subs.txt amass.txt | sort -u > all_subs.txt
```

### DNS Records

```bash
# All record types
dig target.com ANY +noall +answer

# Specific records
dig target.com MX TXT NS CNAME A AAAA

# Zone transfer (rare but worth trying)
dig axfr @ns1.target.com target.com
```

### Historical Data

```bash
# Wayback Machine
waybackurls target.com | tee wayback.txt

# Common Crawl
echo target.com | gau --subs | tee gau.txt

# Combine
cat wayback.txt gau.txt | sort -u > historical.txt
```

## Phase 2: Active Recon

### HTTP Probing

```bash
# httpx (fast, feature-rich)
cat all_subs.txt | httpx -status-code -title -tech-detect -o live.txt

# Filter interesting
cat live.txt | grep -E "200|301|302|403" > interesting.txt
```

### Port Scanning

```bash
# Quick top ports
nmap -sS -Pn --top-ports 1000 -T4 target.com

# Full port scan (slow)
nmap -sS -Pn -p- -T4 target.com -oG full.gnmap

# Service detection
nmap -sV -sC -p80,443,8080,8443 target.com
```

### Content Discovery

```bash
# ffuf (fast)
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -u https://target.com/FUZZ -mc 200,301,302,403 -o ffuf.json

# Common paths
feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt

# API endpoints
ffuf -w api_wordlist.txt -u https://target.com/api/FUZZ -mc 200
```

### Technology Fingerprinting

```bash
# whatweb
whatweb -a 3 https://target.com

# wappalyzer CLI
wappalyzer https://target.com

# Manual checks
curl -I https://target.com  # Headers
curl -s https://target.com | grep -i "generator\|framework\|powered"
```

## Phase 3: Deep Analysis

### JavaScript Analysis

```bash
# Collect JS files
cat live.txt | getJS --complete | tee js_urls.txt

# Extract endpoints
cat js_urls.txt | xargs -I{} curl -s {} | grep -oP '["'"'"'](/[a-zA-Z0-9/_-]+)["'"'"']' | sort -u

# Secret scanning
trufflehog filesystem ./js-files/

# Source maps
for url in $(cat js_urls.txt); do curl -sf "$url.map" > /dev/null && echo "$url.map"; done
```

### Parameter Discovery

```bash
# Arjun
arjun -u https://target.com/endpoint -m GET POST

# ParamSpider
python3 paramspider.py -d target.com

# From historical
cat historical.txt | grep -oP '\?[^&]+' | cut -d'=' -f1 | sort -u
```

### API Enumeration

```bash
# OpenAPI/Swagger
curl -s https://target.com/swagger.json
curl -s https://target.com/openapi.json
curl -s https://target.com/api-docs

# GraphQL
curl -s https://target.com/graphql -d '{"query":"{ __schema { types { name } } }"}'

# Common API paths
ffuf -w api-endpoints.txt -u https://target.com/FUZZ -mc 200,401,403
```

## Automation

### One-liner Recon

```bash
# Quick subdomain → live hosts → screenshots
subfinder -d target.com -silent | httpx -silent | gowitness file -f - -P screenshots/
```

### Nuclei Integration

```bash
# After collecting live hosts
nuclei -l live.txt -t ~/nuclei-templates/ -severity critical,high -o nuclei.txt
```

### Custom Workflow

```bash
#!/bin/bash
TARGET=$1
mkdir -p recon/$TARGET && cd recon/$TARGET

# Subdomains
subfinder -d $TARGET -o subs.txt
amass enum -passive -d $TARGET -o amass.txt
cat subs.txt amass.txt | sort -u > all_subs.txt

# Live hosts
cat all_subs.txt | httpx -silent -o live.txt

# Screenshots
gowitness file -f live.txt -P screenshots/

# Content discovery (parallel)
cat live.txt | xargs -P 10 -I{} ffuf -w common.txt -u {}/FUZZ -mc 200 -o {}.json

# JS analysis
cat live.txt | getJS --complete | sort -u > js.txt

echo "[+] Recon complete: $(wc -l < all_subs.txt) subs, $(wc -l < live.txt) live"
```

## Tool Summary

| Phase | Tool | Purpose |
|-------|------|---------|
| Passive | subfinder, amass | Subdomain enum |
| Passive | waybackurls, gau | Historical data |
| Active | httpx | HTTP probing |
| Active | nmap | Port scanning |
| Active | ffuf, feroxbuster | Content discovery |
| Active | whatweb, wappalyzer | Tech fingerprinting |
| Deep | getJS, linkfinder | JS analysis |
| Deep | arjun | Parameter discovery |
| Auto | nuclei | Vulnerability scanning |

## Output Organization

```
recon/target.com/
├── subs.txt          # All subdomains
├── live.txt          # Live HTTP hosts
├── screenshots/      # Visual recon
├── js/               # JavaScript files
├── ffuf/             # Content discovery results
├── nuclei.txt        # Vuln scan results
└── notes.md          # Manual findings
```

## Priority Targets

After recon, prioritize:

1. **Admin panels** — `/admin`, `/wp-admin`, `/dashboard`
2. **API endpoints** — `/api/`, `/v1/`, `/graphql`
3. **Auth pages** — `/login`, `/register`, `/reset`
4. **File uploads** — `/upload`, `/import`
5. **User input** — Search, comments, profiles
6. **Old/dev instances** — `dev.`, `staging.`, `old.`

---

**Tip:** Quality over quantity. Deep analysis of 10 interesting endpoints beats shallow scan of 1000 boring ones.
