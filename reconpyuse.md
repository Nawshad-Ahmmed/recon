# recon.py

Conservative recon and URL-analysis CLI for **authorized** bug-bounty targets.

```
Input domain(s) → Subfinder + Assetfinder → HTTPX → Wayback + Katana + GAU
→ merge & dedupe → extensions.txt / keywords.txt analysis → results/
```

Every domain runs through the whole pipeline independently. Only the supplied domain and its subdomains are kept (all tool output is scope-filtered). No exploitation, brute forcing or credential testing.

## Installation

Requirements: Linux, Python 3.8+ (standard library only), Go (to install the tools).

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest

export PATH="$PATH:$HOME/go/bin"     # add to ~/.bashrc / ~/.zshrc
```

> The `httpx` binary must be ProjectDiscovery's, not the Python `httpx` CLI (same name). Verify with `httpx -version`.

Copy `recon.py`, `extensions.txt` and `keywords.txt` into your workspace directory (the tool always works in the directory you launch it from).

## Usage

```bash
cd ~/bugbounty/company
python3 recon.py -u example.com            # one domain
python3 recon.py -dl domains.txt           # many domains (one per line)
python3 recon.py -dl domains.txt --resume  # continue an interrupted run
```

Run individual stages (they can be combined):

```bash
python3 recon.py -u example.com --subs
python3 recon.py -u example.com --httpx
python3 recon.py -u example.com --urls
python3 recon.py -u example.com --analyze   # e.g. after editing extensions.txt
```

Tuning (conservative defaults): `--timeout 3600`, `--threads 25`, `--rate 50`, `--depth 2`, `--keyword-in-host`.

## Configuration files (current directory)

* `extensions.txt` – one extension per line; leading `.`, case and duplicates are normalized. Add as many as you like, no code change needed. Multi-part entries such as `tar.gz` work too.
* `keywords.txt` – optional; one keyword per line, matched case-insensitively against the URL **path + query** (add `--keyword-in-host` to include hostnames).

Lines starting with `#` are ignored in all input files.

## Extension matching

URLs are parsed with `urllib.parse`; only the **path's last segment** is checked.

| URL | `php` match? |
|---|---|
| `https://x.com/test.php` | yes |
| `https://x.com/test.PHP?id=1` | yes |
| `https://x.com/a.php;jsessionid=1` | yes |
| `https://x.com/page?type=php` | **no** |

## Output layout

Raw working files go in the current directory (prefixed with the domain in `-dl` mode so domains never collide):

```
subfinder.txt assetfinder.txt subdomains.txt httpx.txt
wayback.txt katana.txt gau.txt all_urls.txt
# -dl mode: example.com-subfinder.txt, example.com-httpx.txt, ...
```

Data flow between the URL stages (no extra intermediate copies):

```
subdomains.txt --httpx--> httpx.txt (raw: status/title/tech/length/redirect)
                              |  live URLs = first column of httpx.txt (in-scope, unique; kept in memory)
                              +--> waybackurls, gau : unique live hostnames on stdin
                              +--> katana           : live URLs on stdin
wayback.txt + katana.txt + gau.txt --merge/dedupe--> all_urls.txt --> analysis --> results/
```

Every source's output is scope-filtered (only the target and its subdomains) before it is saved.

**Isolation rule:** `-dl` always uses domain-prefixed raw files and `results/<domain>/`. Every raw file is named `<prefix>-<stage>.txt`, where the prefix is the domain itself for ordinary hostnames; a domain with anything unsafe for filenames (or an over-long name) gets a sanitized prefix plus a short hash of the original, so two different domains can never share a prefix. In `-u` mode the unprefixed files and `results/` belong to the first domain used in that directory; if you later run `-u` with a *different* domain there, the tool automatically switches that run to prefixed files and `results/<domain>/` (and tells you) instead of overwriting the first domain's data.

Analysis results (files are only created when there are matches):

```
# -u example.com                # -dl domains.txt
results/                        results/
├── php.txt                     ├── example.com/
├── js.txt                      │   ├── php.txt
├── parameters.txt              │   ├── parameters.txt
├── emails.txt                  │   ├── emails.txt
└── keyword-admin.txt           │   └── keyword-admin.txt
                                └── example.org/ ...
```

Other files: `recon.log` (details/errors), `.recon_state.json` (per-stage state), `results/.../.recon_manifest.json` (lets a re-run delete stale result files it generated earlier).

## Resume and stage state

`.recon_state.json` tracks every stage per domain: `subfinder`, `assetfinder`, `subdomains` (the merge), `httpx`, `wayback`, `katana`, `gau` and `analyze`. Each entry is `done` (with its file and count) or `failed` (with the exact reason). A stage is only ever marked `done` after it completed successfully.

With `--resume` the tool prints a plan first, e.g.:

```
[*] Resume plan:
      subfinder    done     skip
      katana       failed   RERUN (exit code 2: ...)
      analyze      failed   RERUN (analysed incomplete input, failed: katana)
```

* `done` stages whose output file exists are skipped.
* `failed`, missing (`stale`) or never-run stages are re-run.
* Re-running a stage re-runs the stages that depend on it (`subfinder/assetfinder -> subdomains -> httpx -> wayback/katana/gau -> analyze`), and only those.
* `analyze` is skipped when its inputs are unchanged **and** `extensions.txt`, `keywords.txt` and `--keyword-in-host` are unchanged; edit those files and `--resume` re-runs only the analysis.
* Without `--resume`, everything selected is re-run and raw files are overwritten.

## Error handling

Missing tools are detected up front with `shutil.which` (install commands are printed). If an external tool fails or times out, the exact stage and reason are printed (`STAGE FAILED [katana] target=example.com: exit code 2: ...`), listed again in that domain's summary, and stored in the state file. Partial output is kept, the failed stage is **not** marked complete, and the workflow continues with the remaining sources/domains (a merge or analysis built from incomplete input is marked failed too). Fix the cause and run the same command with `--resume` to retry only what failed. The exit code is 1 if any stage or domain failed, 2 for missing tools/bad input, 130 on Ctrl+C. Ctrl+C is safe: files are written atomically and state is only updated after a stage finishes.

External tools never inherit the terminal's stdin (they receive `/dev/null` or their exact input), so they cannot hang waiting for input.

## Notes

* Katana also crawls JS/links on live hosts, and Wayback/GAU query third-party archives. Keep rates conservative and follow each program's rules on automated scanning.
* Sub-second timing and exact tool flags can vary between tool versions; if a flag is rejected, the error appears in `recon.log`.
