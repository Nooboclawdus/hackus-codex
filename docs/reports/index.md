# Reports

Write reports that get paid.

## Sections

- [Impact Wording](impact.md) — How to describe impact effectively
- [Templates](templates.md) — Report structures by vuln type

## Report Principles

### 1. Clear Summary

One paragraph explaining:
- What the vulnerability is
- Where it exists  
- What an attacker can do

### 2. Reproducible Steps

Numbered steps that anyone can follow:

1. Go to X
2. Do Y
3. Observe Z

### 3. Proof of Concept

- Working payload/request
- Screenshot or video
- Burp request/response if relevant

### 4. Impact

Be specific. Not "attacker can do bad things" but "attacker can access any user's payment information including full credit card numbers."

### 5. Remediation

Optional but appreciated:
- What should be fixed
- How to fix it

## Common Mistakes

- ❌ Vague impact statements
- ❌ Steps that only work in your environment
- ❌ No PoC, just description
- ❌ Overstating severity
- ❌ Wall of text, no structure

---

See [Impact Wording](impact.md) and [Templates](templates.md) for specifics.
