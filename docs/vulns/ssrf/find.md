# Finding SSRF

## Where to Look

### High-Value Targets

- [ ] URL parameters (`url=`, `link=`, `src=`, `dest=`, `redirect=`)
- [ ] Webhook configurations
- [ ] File import from URL
- [ ] PDF generators
- [ ] Image/avatar from URL
- [ ] API integrations
- [ ] URL preview/unfurl features
- [ ] Proxy endpoints

### Headers to Test

- [ ] `X-Forwarded-For`
- [ ] `X-Forwarded-Host`
- [ ] `Referer`
- [ ] `Host` (for routing)

## Methodology

### 1. Identify URL Input Points

Look for any parameter accepting URLs:

```
?url=https://example.com
?src=https://example.com/image.png
?redirect=https://...
```

### 2. Test with External Server

```
?url=https://your-collaborator.net
```

Check for incoming requests.

### 3. Test Internal Targets

```
?url=http://127.0.0.1
?url=http://localhost
?url=http://169.254.169.254
```

### 4. Bypass Filters

If blocked, try [SSRF payloads](../../quick/ssrf.md#localhost-variations).

---

*More detailed methodology coming soon.*
