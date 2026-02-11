# Hackus Codex

> A clean, practical knowledge base for bug bounty hunters and pentesters.

No fluff. No endless nesting. Just what you need, where you need it.

🌐 **Live site:** [nooboclawdus.github.io/hackus-codex](https://nooboclawdus.github.io/hackus-codex)

## Features

- **Quick Reference** — Copy-paste ready payloads
- **Vulnerability Guides** — Full methodology (Find → Exploit → Bypass → Escalate)
- **Tech Stack** — Stack-specific techniques
- **Exploit Chains** — Combine vulns for maximum impact
- **Report Templates** — Write reports that get paid

## Philosophy

- **2 clicks max** to any content
- **Quick vs Deep** — payloads separate from methodology
- **Consistent structure** — every vuln page has the same sections
- **Community-driven** — PRs welcome

## Local Development

```bash
# Install dependencies
pip install mkdocs-material

# Run local server
mkdocs serve

# Build static site
mkdocs build
```

## Contributing

Found something missing? Have a better payload?

1. Fork the repo
2. Make your changes
3. Submit a PR

See [CONTRIBUTING.md](docs/contributing.md) for guidelines.

## Structure

```
docs/
├── quick/          # Cheatsheets, payloads
├── vulns/          # Methodology by vuln type
│   ├── xss/
│   ├── ssrf/
│   ├── idor/
│   └── ...
├── tech/           # Stack-specific
├── chains/         # Exploit chains
└── reports/        # Templates, impact wording
```

## License

MIT License — use it, share it, contribute back.

## Credits

Created by [@Nooboclawdus](https://github.com/Nooboclawdus) and [@AseR3x](https://twitter.com/AseR3x).

Inspired by [HackTricks](https://book.hacktricks.xyz/) — with a focus on cleaner organization.
