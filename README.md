# 🔎 Recon Pipeline

An automated reconnaissance pipeline that chains together the core [ProjectDiscovery](https://github.com/projectdiscovery) tools into a single, hands-off workflow: **subdomain discovery → live probing → crawling → JavaScript analysis → Nuclei scanning**.

Point it at a domain, walk away, and come back to a tidy `recon/` directory with everything organized and a human-readable summary waiting for you.

```bash
./recon.sh example.com
```

---

## ✨ Features

- **Subdomain enumeration** with `subfinder` (all sources)
- **Live host probing** with `httpx` — status codes, titles, tech detection, favicons, websockets
- **Deep crawling** with `katana` — JS crawling, known-files, depth 3
- **JavaScript harvesting** — collects `.js` URLs from crawl output *and* inline `src=` references, downloads them, then extracts relative paths, API endpoints, and potential secrets
- **Nuclei scanning** in four focused passes: technology, exposures, vulnerabilities (critical/high/medium), and misconfigurations/default-logins
- **Clean output structure** + auto-generated `summary.txt`
- **Fail-soft design** — if one stage returns nothing, the pipeline warns and keeps going instead of dying

---

## 📦 Prerequisites

All four tools must be installed and available in your `$PATH`:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

You'll also need `curl`, `awk`, and `grep` with PCRE support (`grep -P`) — standard on most Linux distributions.

> **Tip:** Run `nuclei -update-templates` at least once before your first scan so you have the latest detection templates.

---

## 🚀 Usage

```bash
# Make it executable (first time only)
chmod +x recon.sh

# Run against a target
./recon.sh <target-domain>

# Example
./recon.sh example.com
```

That's it — the script creates the full directory tree, runs each stage, and prints a summary at the end.

---

## 📁 Output Structure

```
recon/
├── subdomains/
│   ├── all.txt              # raw subfinder output
│   ├── live.txt             # httpx results (with metadata)
│   └── live_urls.txt        # bare live URLs for crawling
├── urls/
│   └── all.txt              # all crawled URLs
├── js/
│   ├── urls.txt             # discovered JavaScript file URLs
│   ├── responses/           # raw downloaded JS files
│   └── endpoints.txt        # extracted paths / API URLs / secrets
├── nuclei/
│   ├── tech-detect.txt      # technology fingerprints
│   ├── exposures.txt        # exposed configs, backups, panels, tokens
│   ├── vulnerabilities.txt  # critical / high / medium findings
│   └── misconfigs.txt       # misconfigurations + default logins
└── summary.txt              # human-readable summary
```

---

## 🔧 Pipeline Stages

| # | Stage | Tool | What it does |
|---|-------|------|--------------|
| 1 | Subdomain discovery | `subfinder` | Enumerates subdomains from all available sources |
| 2 | Live probing | `httpx` | Filters to live hosts, grabs titles/status/tech |
| 3 | Crawling | `katana` | Crawls live hosts to depth 3, including JS |
| 4 | JS analysis | `curl` + `grep` | Downloads JS, extracts endpoints & secrets |
| 5 | Scanning | `nuclei` | Tech, exposure, vuln, and misconfig scans |

---

## ⚙️ Customization

A few things you may want to tweak in the script:

- **Crawl depth** change `-depth 3` in the katana stage
- **Severity filter** adjust `-severity critical,high,medium` in the vulnerability scan
- **Download timeout** the JS download uses `curl -m 10`; raise it for slow targets
- **Nuclei tags** swap the `-tags` values to target different template categories

---

## ⚠️ Legal & Ethical Notice

This tool is intended for **authorized security testing only** — your own assets, systems you have **explicit written permission** to test, or targets that are in scope of an active bug bounty program.

Running reconnaissance or vulnerability scans against systems you do not own or have permission to test may be **illegal** in your jurisdiction and can violate computer-misuse laws (e.g. the CFAA, the UK Computer Misuse Act, and equivalents worldwide). **You are solely responsible for how you use this tool.** The author accepts no liability for misuse or damage.

Always:
- Confirm the target is in scope before running.
- Respect program rules, rate limits, and out-of-scope lists.
- Never test third-party infrastructure without authorization.

---

## 📄 License

Released under the MIT License see `LICENSE` for details. *(Add a `LICENSE` file to your repo if you haven't yet.)*

---

## 🙌 Credits

Built on the excellent open-source tooling from [ProjectDiscovery](https://github.com/projectdiscovery): `subfinder`, `httpx`, `katana`, and `nuclei`.
