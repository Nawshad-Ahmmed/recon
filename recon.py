#!/usr/bin/env python3
"""
recon.py - conservative recon + URL analysis orchestrator for AUTHORIZED
bug-bounty programs.

Pipeline (per domain, fully isolated):
    Subfinder + Assetfinder -> HTTPX -> Wayback + Katana + GAU
    -> merge/dedupe -> extension / keyword / parameter / email analysis

Only the supplied domain(s) and their subdomains are processed.
No exploitation, brute forcing or credential testing is performed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote, urlsplit

WORKDIR = Path.cwd()
SCRIPT_DIR = Path(__file__).resolve().parent
LOG = logging.getLogger("recon")

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
DOMAIN_RE = re.compile(rf"^(?:{LABEL}\.)+{LABEL}$")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
FILE_TLDS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js", "ico",
             "woff", "woff2", "ttf", "map", "bmp", "avif"}
EXT_RE = re.compile(r"^[a-z0-9][a-z0-9._+-]*$")
RESERVED_NAMES = {"parameters", "emails"}


# --------------------------------------------------------------------------
# Output / logging helpers
# --------------------------------------------------------------------------
def setup_logging() -> None:
    try:
        logging.basicConfig(filename=str(WORKDIR / "recon.log"), level=logging.INFO,
                            format="%(asctime)s %(levelname)s %(message)s")
    except OSError:
        LOG.addHandler(logging.NullHandler())


def out(msg: str = "") -> None:
    print(msg, flush=True)


def info(msg: str) -> None:
    print(f"[+] {msg}", flush=True)
    LOG.info(msg)


def warn(msg: str) -> None:
    print(f"[!] {msg}", file=sys.stderr, flush=True)
    LOG.warning(msg)


def err(msg: str) -> None:
    print(f"[-] {msg}", file=sys.stderr, flush=True)
    LOG.error(msg)


def report_failure(t, stage: str, reason: str) -> None:
    """Show exactly which stage failed and why (also collected for the summary)."""
    t.stats.failures[stage] = reason
    err(f"STAGE FAILED [{stage}] target={t.domain}: {reason}")


# --------------------------------------------------------------------------
# Generic helpers
# --------------------------------------------------------------------------
def normalize_domain(raw: str) -> str | None:
    """Return a clean lowercase hostname, or None if invalid."""
    d = raw.strip().lower()
    if not d or d.startswith("#"):
        return None
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)
    d = re.split(r"[/?#]", d, 1)[0]
    d = d.rsplit("@", 1)[-1]
    d = re.sub(r":\d+$", "", d)
    d = d.lstrip("*.").rstrip(".")
    try:
        d = d.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(d) > 253 or not DOMAIN_RE.match(d) or d.rsplit(".", 1)[-1].isdigit():
        return None
    return d


def in_scope(host: str, domain: str) -> bool:
    host = host.lower().rstrip(".")
    return host == domain or host.endswith("." + domain)


def safe_name(domain: str) -> str:
    """Filesystem-safe raw-file prefix for a domain.

    Unchanged for ordinary hostnames (so existing files/state stay valid). Anything
    unsafe (odd characters, uppercase, leading '.'/'-', over-long) is sanitized AND
    suffixed with a hash of the original, so two different domains can never map
    to the same prefix.
    """
    safe = re.sub(r"[^a-z0-9.-]", "_", domain.lower())
    if safe != domain or len(safe) > 150 or safe[:1] in (".", "-", ""):
        digest = hashlib.sha1(domain.encode("utf-8", "replace")).hexdigest()[:10]
        safe = (safe.lstrip(".-")[:150] or "domain") + "_" + digest
    return safe


def clean_url(raw: str, domain: str) -> str | None:
    u = raw.strip().split("#", 1)[0]
    if not u or len(u) > 4096 or re.search(r"\s", u):
        return None
    if not u[:8].lower().startswith(("http://", "https://")):
        return None
    try:
        host = urlsplit(u).hostname
    except ValueError:
        return None
    if not host or not in_scope(host, domain):
        return None
    return u


def parse_live(lines: list[str], domain: str) -> list[str]:
    """Live URLs = first token of each httpx line, in-scope, unique, sorted."""
    live: dict[str, None] = {}
    for line in lines:
        url = clean_url(line.split()[0], domain)
        if url:
            live.setdefault(url, None)
    return sorted(live)


def read_lines(path: Path) -> list[str]:
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            return [ln.strip() for ln in fh if ln.strip()]
    except OSError:
        return []


def count_lines(path: Path) -> int:
    return len(read_lines(path))


def write_lines(path: Path, lines) -> None:
    """Atomic write so Ctrl+C never leaves a half-written file behind."""
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        for ln in lines:
            fh.write(ln + "\n")
    os.replace(tmp, path)


def read_config_list(path: Path, kind: str) -> list[str] | None:
    """Read extensions.txt / keywords.txt: strip, skip blanks and #comments, dedupe."""
    if not path.is_file():
        return None
    seen: dict[str, None] = {}
    for line in read_lines(path):
        if line.startswith("#"):
            continue
        item = line.lower()
        if kind == "ext" and item.startswith("."):
            item = item[1:]
        if item:
            seen.setdefault(item, None)
    return list(seen)


@dataclass
class ToolResult:
    ok: bool
    lines: list[str]
    note: str = ""


def _to_text(x) -> str:
    if x is None:
        return ""
    return x.decode("utf-8", "replace") if isinstance(x, bytes) else x


def run_tool(cmd: list[str], timeout: int, stdin_text: str | None = None) -> ToolResult:
    """Run an external tool via subprocess (no shell, argument list only)."""
    LOG.info("exec: %s", " ".join(cmd))
    try:
        # tools that get no input must not inherit (and block on) our stdin
        feed = {"input": stdin_text} if stdin_text is not None else {"stdin": subprocess.DEVNULL}
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=timeout, check=False, **feed)
    except subprocess.TimeoutExpired as e:
        lines = [ANSI_RE.sub("", l).strip() for l in _to_text(e.stdout).splitlines()]
        return ToolResult(False, [l for l in lines if l], f"timed out after {timeout}s")
    except OSError as e:
        return ToolResult(False, [], f"could not execute: {e}")
    lines = [ANSI_RE.sub("", l).strip() for l in (p.stdout or "").splitlines()]
    lines = [l for l in lines if l]
    note = ""
    if p.returncode != 0:
        tail = (p.stderr or "").strip().splitlines()[-1:] or [""]
        note = f"exit code {p.returncode}: {tail[0][:300]}"
    return ToolResult(p.returncode == 0, lines, note)


# --------------------------------------------------------------------------
# Data holders
# --------------------------------------------------------------------------
@dataclass
class Stats:
    subfinder: int = 0
    assetfinder: int = 0
    subdomains: int = 0
    live: int = 0
    wayback: int = 0
    katana: int = 0
    gau: int = 0
    urls: int = 0
    ext: dict = field(default_factory=dict)
    keywords: dict = field(default_factory=dict)
    params: int = 0
    emails: int = 0
    analyzed: bool = False
    failed: bool = False
    files_written: bool = False
    failures: dict = field(default_factory=dict)   # stage -> reason (this run)


class Target:
    KEYS = ("subfinder", "assetfinder", "subdomains", "httpx",
            "wayback", "katana", "gau", "all_urls")

    def __init__(self, domain: str, multi: bool):
        # multi=True -> domain-prefixed raw files and results/<domain>/ (never shared)
        self.domain, self.multi = domain, multi
        prefix = f"{safe_name(domain)}-" if multi else ""
        self.f = {k: f"{prefix}{k}.txt" for k in self.KEYS}
        self.stats = Stats()
        self.cache: dict = {}        # in-memory copies so files are not re-read
        self.stage: str | None = None  # stage currently running (for error reporting)

    def path(self, key: str) -> Path:
        return WORKDIR / self.f[key]

    def lines(self, key: str) -> list[str]:
        if key not in self.cache:
            self.cache[key] = read_lines(self.path(key))
        return self.cache[key]

    def save(self, key: str, lines: list[str]) -> None:
        write_lines(self.path(key), lines)
        self.cache[key] = lines

    def live_urls(self) -> list[str]:
        """The live-URL dataset: derived from httpx.txt (no separate copy on disk)."""
        if "live" not in self.cache:
            self.cache["live"] = parse_live(read_lines(self.path("httpx")), self.domain)
        return self.cache["live"]

    @property
    def results_dir(self) -> Path:
        base = WORKDIR / "results"
        return base / self.domain if self.multi else base

    @property
    def results_label(self) -> str:
        return f"./results/{self.domain}/" if self.multi else "./results/"

    def load_counts(self, rm) -> None:
        """Fill stats from the state file (falls back to reading a file only if needed)."""
        s = self.stats
        for key, attr in (("subfinder", "subfinder"), ("assetfinder", "assetfinder"),
                          ("subdomains", "subdomains"), ("httpx", "live"),
                          ("wayback", "wayback"), ("katana", "katana"), ("gau", "gau")):
            if not self.path(key).exists():
                continue
            e = rm.entry(self.domain, key)
            if e and e.get("count") is not None:
                n = e["count"]
            else:
                n = len(self.live_urls()) if key == "httpx" else len(self.lines(key))
            setattr(s, attr, n)
        if self.path("all_urls").exists():
            st = ((rm.entry(self.domain, "analyze") or {}).get("stats")) or {}
            s.urls = st["urls"] if "urls" in st else count_lines(self.path("all_urls"))


@dataclass
class Config:
    stages: set
    resume: bool
    timeout: int
    threads: int
    rate: int
    depth: int
    keyword_in_host: bool
    exts: list | None
    keywords: list | None
    sig: str = ""   # fingerprint of analysis config (extensions/keywords/options)


# --------------------------------------------------------------------------
# Dependency checking
# --------------------------------------------------------------------------
class DependencyChecker:
    HINTS = {
        "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "assetfinder": "go install github.com/tomnomnom/assetfinder@latest",
        "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
        "katana": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
        "gau": "go install github.com/lc/gau/v2/cmd/gau@latest",
    }
    STAGE_TOOLS = {"subs": ["subfinder", "assetfinder"], "httpx": ["httpx"],
                   "urls": ["waybackurls", "katana", "gau"]}

    def __init__(self):
        self.bins: dict[str, str] = {}

    def check(self, stages: set) -> list[str]:
        missing = []
        for stage, names in self.STAGE_TOOLS.items():
            if stage not in stages:
                continue
            for n in names:
                p = shutil.which(n)
                if p:
                    self.bins[n] = p
                else:
                    missing.append(n)
        return missing

    def report_missing(self, missing: list[str]) -> None:
        err("Missing required tools: " + ", ".join(missing))
        out("    Install (requires Go, then make sure ~/go/bin is in PATH):")
        for n in missing:
            out(f"      {self.HINTS[n]}")

    def check_httpx_flavor(self) -> None:
        """The Python 'httpx' CLI has the same name as ProjectDiscovery's httpx."""
        if "httpx" not in self.bins:
            return
        try:
            r = subprocess.run([self.bins["httpx"], "-version"], capture_output=True,
                               text=True, errors="replace", timeout=20)
            if "projectdiscovery" not in (r.stdout + r.stderr).lower():
                warn("'httpx' in PATH may not be ProjectDiscovery's httpx "
                     "(the Python httpx CLI has the same name). Check `which httpx`.")
        except Exception:
            pass


# --------------------------------------------------------------------------
# Resume handling
# --------------------------------------------------------------------------
class ResumeManager:
    """Per-domain, per-stage state in .recon_state.json.

    entry = {"status": "done" | "failed", "file", "count", "reason", "at", ...}
    A stage is only 'done' after it completed successfully. Failed stages keep
    their reason and are retried by --resume. Re-running a stage invalidates
    everything that depends on it (DEPENDENTS).
    """
    FILE = ".recon_state.json"
    ORDER = ["subfinder", "assetfinder", "subdomains", "httpx",
             "wayback", "katana", "gau", "analyze"]
    DEPENDENTS = {"subfinder": ["subdomains"], "assetfinder": ["subdomains"],
                  "subdomains": ["httpx"], "httpx": ["wayback", "katana", "gau"],
                  "wayback": ["analyze"], "katana": ["analyze"], "gau": ["analyze"]}

    def __init__(self):
        self.path = WORKDIR / self.FILE
        self.data: dict = {}
        if self.path.is_file():
            try:
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    self.data = loaded
            except (OSError, ValueError):
                warn(f"{self.FILE} unreadable; starting with a clean state")

    def _save(self) -> None:
        try:
            tmp = self.path.with_name(self.FILE + ".tmp")
            tmp.write_text(json.dumps(self.data, indent=1), encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError as e:
            warn(f"could not save state: {e}")

    def entry(self, domain: str, stage: str) -> dict | None:
        dom = self.data.get(domain)
        e = dom.get(stage) if isinstance(dom, dict) else None
        if isinstance(e, str):            # state written by the previous version
            return {"status": "done", "file": e, "count": None}
        return e if isinstance(e, dict) else None

    def status(self, domain: str, stage: str, fname: str | None = None) -> str:
        """'done' | 'failed' | 'stale' (done but output missing) | 'pending'."""
        e = self.entry(domain, stage)
        if not e:
            return "pending"
        if e.get("status") == "failed":
            return "failed"
        if e.get("status") == "done":
            if fname and (e.get("file") != fname or not (WORKDIR / fname).exists()):
                return "stale"
            return "done"
        return "pending"

    def valid(self, domain: str, stage: str, fname: str | None = None) -> bool:
        return self.status(domain, stage, fname) == "done"

    def count(self, domain: str, stage: str, path: Path) -> int:
        e = self.entry(domain, stage)
        return e["count"] if e and e.get("count") is not None else count_lines(path)

    def upstream(self, stage: str) -> list[str]:
        return [s for s, deps in self.DEPENDENTS.items() if stage in deps]

    def _drop(self, domain: str, stage: str) -> None:
        dom = self.data.get(domain)
        if isinstance(dom, dict):
            dom.pop(stage, None)
        for dep in self.DEPENDENTS.get(stage, []):
            self._drop(domain, dep)

    def invalidate(self, domain: str, stage: str) -> None:
        self._drop(domain, stage)
        self._save()

    def _set(self, domain: str, stage: str, entry: dict) -> None:
        self._drop(domain, stage)         # dependents are no longer trustworthy
        entry["at"] = datetime.now().isoformat(timespec="seconds")
        self.data.setdefault(domain, {})[stage] = entry
        self._save()

    def mark(self, domain: str, stage: str, fname: str | None = None,
             count: int | None = None, **extra) -> None:
        self._set(domain, stage, {"status": "done", "file": fname, "count": count, **extra})

    def fail(self, domain: str, stage: str, reason: str, fname: str | None = None,
             count: int | None = None) -> None:
        self._set(domain, stage, {"status": "failed", "reason": reason[:300],
                                  "file": fname, "count": count})

    # In single-domain (-u) mode the unprefixed files belong to one domain only.
    def single_owner(self) -> str | None:
        v = self.data.get("_single_owner")
        return v if isinstance(v, str) else None

    def set_single_owner(self, domain: str) -> None:
        self.data["_single_owner"] = domain
        self._save()


# --------------------------------------------------------------------------
# Stage 1-2: subdomain enumeration
# --------------------------------------------------------------------------
class SubdomainEnumerator:
    def __init__(self, cfg: Config, deps: DependencyChecker, rm: ResumeManager):
        self.cfg, self.deps, self.rm = cfg, deps, rm

    @staticmethod
    def _clean(lines: list[str], domain: str) -> list[str]:
        hosts = set()
        for ln in lines:
            h = normalize_domain(ln)
            if h and in_scope(h, domain):
                hosts.add(h)
        return sorted(hosts)

    def _collect(self, t: Target, key: str, cmd: list[str]) -> int:
        fname = t.f[key]
        t.stage = key
        if self.cfg.resume and self.rm.valid(t.domain, key, fname):
            n = self.rm.count(t.domain, key, t.path(key))
            out(f"      {n} hosts (resumed from {fname})")
            return n
        res = run_tool(cmd, self.cfg.timeout)
        hosts = self._clean(res.lines, t.domain)
        self.rm.invalidate(t.domain, key)          # state says 'pending' while the file changes
        t.save(key, hosts)
        if res.ok:
            self.rm.mark(t.domain, key, fname, len(hosts))
        else:
            self.rm.fail(t.domain, key, res.note, fname, len(hosts))
            report_failure(t, key, f"{res.note} (partial output kept in {fname})")
        out(f"      {len(hosts)} in-scope hosts -> {fname}")
        return len(hosts)

    def run_subfinder(self, t: Target) -> None:
        t.stats.subfinder = self._collect(
            t, "subfinder", [self.deps.bins["subfinder"], "-d", t.domain, "-all", "-silent"])

    def run_assetfinder(self, t: Target) -> None:
        t.stats.assetfinder = self._collect(
            t, "assetfinder", [self.deps.bins["assetfinder"], "--subs-only", t.domain])

    def merge(self, t: Target) -> int:
        t.stage = "subdomains"
        hosts = {t.domain}
        for k in ("subfinder", "assetfinder"):
            hosts.update(t.lines(k))
        clean = sorted(h for h in (normalize_domain(x) for x in hosts) if h and in_scope(h, t.domain))
        self.rm.invalidate(t.domain, "subdomains")
        t.save("subdomains", clean)
        t.stats.subdomains = len(clean)
        failed = [k for k in ("subfinder", "assetfinder") if self.rm.status(t.domain, k) == "failed"]
        if failed:   # never mark a merge of incomplete data as completed
            reason = "built from incomplete input, failed: " + ", ".join(failed)
            self.rm.fail(t.domain, "subdomains", reason, t.f["subdomains"], len(clean))
            report_failure(t, "subdomains", reason)
        else:
            self.rm.mark(t.domain, "subdomains", t.f["subdomains"], len(clean))
        return len(clean)

    def build_subdomains(self, t: Target) -> int:
        """Resume-aware merge step (tracked as its own stage: 'subdomains')."""
        fname = t.f["subdomains"]
        t.stage = "subdomains"
        if self.cfg.resume and self.rm.valid(t.domain, "subdomains", fname):
            n = self.rm.count(t.domain, "subdomains", t.path("subdomains"))
            t.stats.subdomains = n
            out(f"      {n} unique in-scope hosts (resumed from {fname})")
            return n
        n = self.merge(t)
        out(f"      {n} unique in-scope hosts -> {fname}")
        return n


# --------------------------------------------------------------------------
# Stage 3: HTTPX
# --------------------------------------------------------------------------
class HTTPProber:
    def __init__(self, cfg: Config, deps: DependencyChecker, rm: ResumeManager):
        self.cfg, self.deps, self.rm = cfg, deps, rm

    def run(self, t: Target) -> None:
        fname = t.f["httpx"]
        t.stage = "httpx"
        if self.cfg.resume and self.rm.valid(t.domain, "httpx", fname):
            t.stats.live = self.rm.count(t.domain, "httpx", t.path("httpx"))
            out(f"      {t.stats.live} live URLs (resumed from {fname})")
            return
        cmd = [self.deps.bins["httpx"], "-l", str(t.path("subdomains")), "-silent", "-no-color",
               "-status-code", "-title", "-tech-detect", "-content-length", "-location",
               "-threads", str(self.cfg.threads), "-rate-limit", str(self.cfg.rate),
               "-timeout", "10", "-retries", "1"]
        res = run_tool(cmd, self.cfg.timeout)
        live = parse_live(res.lines, t.domain)
        self.rm.invalidate(t.domain, "httpx")
        write_lines(t.path("httpx"), res.lines)     # raw httpx output (status/title/tech/...)
        t.cache["live"] = live                      # live URL dataset used by the URL stage
        t.stats.live = len(live)
        if res.ok:
            self.rm.mark(t.domain, "httpx", fname, len(live))
        else:
            self.rm.fail(t.domain, "httpx", res.note, fname, len(live))
            report_failure(t, "httpx", f"{res.note} (partial output kept in {fname})")
        out(f"      {len(live)} live URLs -> {fname}")


# --------------------------------------------------------------------------
# Stage 4: URL collection
# --------------------------------------------------------------------------
class URLCollector:
    """Data flow:
        httpx.txt -> live URLs (unique, in-scope; kept in memory, no extra file)
          -> waybackurls, gau : unique live *hostnames* on stdin
          -> katana           : the live URLs on stdin
        each source is scope-filtered + deduped into its own file, then all
        three are merged into all_urls.txt, which is the analysis input.
    """

    def __init__(self, cfg: Config, deps: DependencyChecker, rm: ResumeManager):
        self.cfg, self.deps, self.rm = cfg, deps, rm

    def _source(self, t: Target, key: str, cmd: list[str], stdin_text: str) -> bool:
        """Returns True if the tool actually ran (False if resumed)."""
        fname = t.f[key]
        t.stage = key
        if self.cfg.resume and self.rm.valid(t.domain, key, fname):
            n = self.rm.count(t.domain, key, t.path(key))
            setattr(t.stats, key, n)
            out(f"      {key}: {n} URLs (resumed)")
            return False
        res = run_tool(cmd, self.cfg.timeout, stdin_text)
        urls = sorted({u for u in (clean_url(l, t.domain) for l in res.lines) if u})
        self.rm.invalidate(t.domain, key)
        t.save(key, urls)
        setattr(t.stats, key, len(urls))
        if res.ok:
            self.rm.mark(t.domain, key, fname, len(urls))
        else:
            self.rm.fail(t.domain, key, res.note, fname, len(urls))
            report_failure(t, key, f"{res.note} (partial output kept; other sources continue)")
        out(f"      {key}: {len(urls)} URLs")
        return True

    def merge_all(self, t: Target) -> int:
        merged: set[str] = set()
        for k in ("wayback", "katana", "gau"):
            merged.update(t.lines(k))
        t.save("all_urls", sorted(merged))
        t.stats.urls = len(merged)
        return len(merged)

    def run(self, t: Target) -> None:
        live = t.live_urls()
        if not live:
            warn(f"URL collection skipped for {t.domain}: no live URLs "
                 f"(httpx status: {self.rm.status(t.domain, 'httpx', t.f['httpx'])})")
            return
        hosts = sorted({(urlsplit(u).hostname or "").rstrip(".") for u in live} - {""})
        host_input = "\n".join(hosts) + "\n"
        live_input = "\n".join(live) + "\n"
        bins = self.deps.bins
        ran = self._source(t, "wayback", [bins["waybackurls"], "-no-subs"], host_input)
        ran |= self._source(t, "katana", [bins["katana"], "-silent", "-no-color",
                                          "-depth", str(self.cfg.depth), "-concurrency", "10",
                                          "-rate-limit", str(self.cfg.rate), "-timeout", "10"],
                            live_input)
        ran |= self._source(t, "gau", [bins["gau"], "--threads", "5"], host_input)
        if ran or not t.path("all_urls").exists():
            n = self.merge_all(t)
            out(f"      {n} unique URLs -> {t.f['all_urls']}")
        else:   # every source resumed: the existing merged file is still valid
            out(f"      {t.stats.urls} unique URLs (all sources resumed, {t.f['all_urls']} reused)")


# --------------------------------------------------------------------------
# Stage 5: analysis
# --------------------------------------------------------------------------
class ResultManager:
    MANIFEST = ".recon_manifest.json"

    def __init__(self, base: Path):
        self.base = base
        self.written: list[str] = []

    def begin(self) -> None:
        """Remove files generated by this tool on a previous run (stale results)."""
        mf = self.base / self.MANIFEST
        if not mf.is_file():
            return
        try:
            for name in json.loads(mf.read_text(encoding="utf-8")):
                if isinstance(name, str) and Path(name).name == name:
                    (self.base / name).unlink(missing_ok=True)
            mf.unlink(missing_ok=True)
        except (OSError, ValueError):
            pass

    def write(self, name: str, lines) -> bool:
        lines = list(lines)
        if not lines:
            return False          # never create empty result files
        self.base.mkdir(parents=True, exist_ok=True)
        write_lines(self.base / name, lines)
        self.written.append(name)
        return True

    def finish(self) -> None:
        if self.written:
            (self.base / self.MANIFEST).write_text(json.dumps(self.written), encoding="utf-8")
            return
        for d in (self.base, self.base.parent):   # drop empty leftovers
            if d.name in ("results", self.base.name):
                try:
                    d.rmdir()
                except OSError:
                    pass


class ExtensionAnalyzer:
    def __init__(self, exts: list[str]):
        self.exts = set(exts)

    @staticmethod
    def segment_of_path(path: str) -> str:
        """Last segment of an already URL-decoded path, lowercased, ;params removed."""
        return path.rsplit("/", 1)[-1].split(";", 1)[0].lower()

    @staticmethod
    def last_segment(url: str) -> str:
        try:
            path = unquote(urlsplit(url).path)
        except ValueError:
            return ""
        return ExtensionAnalyzer.segment_of_path(path)

    def match(self, seg: str) -> list[str]:
        found, i = [], seg.find(".")
        while i != -1:
            suffix = seg[i + 1:]
            if suffix in self.exts:
                found.append(suffix)
            i = seg.find(".", i + 1)
        return found

    def analyze(self, urls: list[str]) -> dict[str, list[str]]:
        res: dict[str, list[str]] = {}
        for u in urls:
            seg = self.last_segment(u)
            if "." in seg:
                for ext in self.match(seg):
                    res.setdefault(ext, []).append(u)
        return res


class KeywordAnalyzer:
    def __init__(self, keywords: list[str], include_host: bool):
        self.keywords, self.include_host = keywords, include_host

    def match(self, hay_lower: str) -> list[str]:
        return [kw for kw in self.keywords if kw in hay_lower]

    def analyze(self, urls: list[str]) -> dict[str, list[str]]:
        res: dict[str, list[str]] = {}
        for u in urls:
            try:
                sp = urlsplit(u)
                hay = unquote(sp.path) + ("?" + unquote(sp.query) if sp.query else "")
                if self.include_host:
                    hay = sp.netloc + hay
            except ValueError:
                continue
            for kw in self.match(hay.lower()):
                res.setdefault(kw, []).append(u)
        return res


class URLAnalyzer:
    def __init__(self, cfg: Config, rm: ResumeManager):
        self.cfg, self.rm = cfg, rm

    @staticmethod
    def has_params(url: str) -> bool:
        try:
            return bool(urlsplit(url).query)
        except ValueError:
            return False

    @staticmethod
    def emails_in(text: str, found: set) -> None:
        for m in EMAIL_RE.findall(text):
            m = m.strip(".").lower()
            if m.rsplit(".", 1)[-1] not in FILE_TLDS:
                found.add(m)

    @staticmethod
    def extract_emails(urls: list[str]) -> list[str]:
        found: set = set()
        for u in urls:
            try:
                sp = urlsplit(u)
                text = unquote(sp.path + "?" + sp.query)
            except ValueError:
                continue
            if "@" in text:
                URLAnalyzer.emails_in(text, found)
        return sorted(found)

    def _up_to_date(self, t: Target) -> bool:
        e = self.rm.entry(t.domain, "analyze")
        if not (self.cfg.resume and e and e.get("status") == "done" and e.get("sig") == self.cfg.sig):
            return False
        st = e.get("stats") or {}
        if st.get("files_written") and not (t.results_dir / ResultManager.MANIFEST).exists():
            return False                     # results were deleted -> regenerate
        s = t.stats
        s.ext, s.keywords = st.get("ext", {}), st.get("keywords", {})
        s.params, s.emails, s.urls = st.get("params", 0), st.get("emails", 0), st.get("urls", 0)
        s.files_written, s.analyzed = bool(st.get("files_written")), True
        return True

    def run(self, t: Target) -> None:
        t.stage = "analyze"
        s = t.stats
        if self._up_to_date(t):
            out("      analysis up to date (resumed)")
            return
        fresh = "all_urls" in t.cache        # produced by this run's merge: already sorted+unique
        urls = t.lines("all_urls")
        if not fresh:
            urls = t.cache["all_urls"] = sorted(set(urls))
        s.ext, s.keywords, s.params, s.emails, s.urls = {}, {}, 0, 0, len(urls)
        if not urls:
            warn(f"no URLs to analyze for {t.domain}")
            return

        # extension / keyword configuration
        ea = None
        if self.cfg.exts is None:
            warn(f"extensions.txt not found in {SCRIPT_DIR}; skipping extension analysis")
        else:
            valid = []
            for e in self.cfg.exts:
                if not EXT_RE.match(e) or e in RESERVED_NAMES or e.startswith("keyword-"):
                    warn(f"ignoring unusable extension entry: {e!r}")
                else:
                    valid.append(e)
            ea = ExtensionAnalyzer(valid)
        ka = KeywordAnalyzer(self.cfg.keywords, self.cfg.keyword_in_host) if self.cfg.keywords else None

        # single pass over the URLs: each URL is parsed/decoded once
        ext_res: dict[str, list[str]] = {}
        kw_res: dict[str, list[str]] = {}
        params: list[str] = []
        emails: set = set()
        for u in urls:
            try:
                sp = urlsplit(u)
            except ValueError:
                continue
            path = unquote(sp.path)
            query = unquote(sp.query) if sp.query else ""
            if ea:
                seg = ExtensionAnalyzer.segment_of_path(path)
                if "." in seg:
                    for ext in ea.match(seg):
                        ext_res.setdefault(ext, []).append(u)
            if query:
                params.append(u)
            if "@" in path or "@" in query:
                self.emails_in(path + "?" + query, emails)
            if ka:
                hay = ((sp.netloc if self.cfg.keyword_in_host else "") + path
                       + ("?" + query if query else "")).lower()
                for kw in ka.match(hay):
                    kw_res.setdefault(kw, []).append(u)

        # write results (never creates empty files)
        self.rm.invalidate(t.domain, "analyze")
        rmgr = ResultManager(t.results_dir)
        rmgr.begin()
        for ext, matched in sorted(ext_res.items()):
            if rmgr.write(f"{ext}.txt", matched):
                s.ext[ext] = len(matched)
        if rmgr.write("parameters.txt", params):
            s.params = len(params)
        if rmgr.write("emails.txt", sorted(emails)):
            s.emails = len(emails)
        for kw, matched in sorted(kw_res.items()):
            safe = re.sub(r"[^a-z0-9._-]+", "_", kw).strip("._-")
            if safe and rmgr.write(f"keyword-{safe}.txt", matched):
                s.keywords[kw] = len(matched)
        rmgr.finish()
        s.analyzed = True
        s.files_written = bool(rmgr.written)

        incomplete = [k for k in ("wayback", "katana", "gau") if self.rm.status(t.domain, k) == "failed"]
        if incomplete:   # results exist but are based on incomplete data -> not 'done'
            reason = "analysed incomplete input, failed: " + ", ".join(incomplete)
            self.rm.fail(t.domain, "analyze", reason)
            report_failure(t, "analyze", reason)
        else:
            self.rm.mark(t.domain, "analyze", None, len(urls), sig=self.cfg.sig,
                         stats={"ext": s.ext, "keywords": s.keywords, "params": s.params,
                                "emails": s.emails, "urls": s.urls, "files_written": s.files_written})
        out(f"      {len(s.ext)} extension files, {s.params} parameter URLs, "
            f"{s.emails} emails, {len(s.keywords)} keyword files")


# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
class SummaryManager:
    @staticmethod
    def _row(label: str, value) -> str:
        return f"{label:<18}{value:>7}"

    def domain(self, t: Target) -> None:
        s = t.stats
        out("\n========== SUMMARY ==========\n")
        out(f"Target: {t.domain}" + ("   [FAILED - see recon.log]" if s.failed else
                                    "   [INCOMPLETE - failed stages]" if s.failures else ""))
        out()
        out(self._row("Subfinder:", s.subfinder))
        out(self._row("Assetfinder:", s.assetfinder))
        out(self._row("Unique domains:", s.subdomains))
        out()
        out(self._row("Live URLs:", s.live))
        out()
        out(self._row("Wayback:", s.wayback))
        out(self._row("Katana:", s.katana))
        out(self._row("GAU:", s.gau))
        out(self._row("Unique URLs:", s.urls))
        if s.analyzed:
            out("\nExtension Results:")
            for ext, n in sorted(s.ext.items(), key=lambda kv: -kv[1]):
                out(f"  {ext + ':':<16}{n:>7}")
            if not s.ext:
                out("  (none)")
            if s.keywords:
                out("\nKeyword Results:")
                for kw, n in sorted(s.keywords.items(), key=lambda kv: -kv[1]):
                    out(f"  {kw + ':':<16}{n:>7}")
            out()
            out(self._row("Parameters:", s.params))
            out(self._row("Emails:", s.emails))
            out(f"\nResults:\n{t.results_label if s.files_written else '(no result files created)'}")
        if s.failures:
            out("\nFailed stages (fix the cause, then retry with --resume):")
            for stage, why in s.failures.items():
                out(f"  {stage}: {why}")
        out("\n=============================")

    def overall(self, targets: list[Target]) -> None:
        tot = Stats()
        ext_tot: dict[str, int] = {}
        for t in targets:
            s = t.stats
            for a in ("subdomains", "live", "urls", "params", "emails"):
                setattr(tot, a, getattr(tot, a) + getattr(s, a))
            for e, n in s.ext.items():
                ext_tot[e] = ext_tot.get(e, 0) + n
        out("\n========== OVERALL ==========\n")
        out(self._row("Domains:", len(targets)))
        out(self._row("Failed:", sum(bool(t.stats.failed or t.stats.failures) for t in targets)))
        out(self._row("Unique domains:", tot.subdomains))
        out(self._row("Live URLs:", tot.live))
        out(self._row("Unique URLs:", tot.urls))
        if ext_tot:
            out("\nExtension Results (all targets):")
            for e, n in sorted(ext_tot.items(), key=lambda kv: -kv[1]):
                out(f"  {e + ':':<16}{n:>7}")
        out()
        out(self._row("Parameters:", tot.params))
        out(self._row("Emails:", tot.emails))
        out("\nResults:\n./results/<domain>/")
        out("\n=============================")


# --------------------------------------------------------------------------
# Pipeline
# --------------------------------------------------------------------------
def resume_plan(t: Target, cfg: Config, rm: ResumeManager) -> None:
    """Print, per stage, whether --resume will skip or rerun it (and why)."""
    units: list[str] = []
    if "subs" in cfg.stages:
        units += ["subfinder", "assetfinder", "subdomains"]
    if "httpx" in cfg.stages:
        units.append("httpx")
    if "urls" in cfg.stages:
        units += ["wayback", "katana", "gau"]
    if "analyze" in cfg.stages:
        units.append("analyze")
    out("[*] Resume plan:")
    rerun: set[str] = set()
    for u in rm.ORDER:
        if u not in units:
            continue
        status = rm.status(t.domain, u, t.f.get(u))
        e = rm.entry(t.domain, u) or {}
        why = {"pending": "not completed yet", "stale": "output file missing",
               "failed": e.get("reason", "previous failure")}.get(status, "")
        if u == "analyze" and status == "done" and e.get("sig") != cfg.sig:
            status, why = "stale", "extensions/keywords/options changed"
        ups = [x for x in rm.upstream(u) if x in rerun]
        if status != "done":
            rerun.add(u)
            action = f"RERUN ({why})"
        elif ups:
            rerun.add(u)
            action = f"RERUN (upstream rerun: {', '.join(ups)})"
        else:
            action = "skip"
        out(f"      {u:<12} {status:<8} {action}")


def process_target(t: Target, cfg: Config, deps: DependencyChecker, rm: ResumeManager) -> None:
    enum = SubdomainEnumerator(cfg, deps, rm)
    prober = HTTPProber(cfg, deps, rm)
    collector = URLCollector(cfg, deps, rm)
    analyzer = URLAnalyzer(cfg, rm)

    info(f"Target: {t.domain}\n")
    t.load_counts(rm)
    if cfg.resume:
        resume_plan(t, cfg, rm)
    st = cfg.stages

    if "subs" in st:
        out("[1/5] Running Subfinder...")
        enum.run_subfinder(t)
        out("[2/5] Running Assetfinder...")
        enum.run_assetfinder(t)
        enum.build_subdomains(t)

    if "httpx" in st:
        out("[3/5] Probing hosts with HTTPX...")
        if not t.path("subdomains").exists():
            if t.path("subfinder").exists() or t.path("assetfinder").exists():
                out(f"      {enum.merge(t)} unique in-scope hosts -> {t.f['subdomains']}")
            else:
                err("no subdomain data found; run with --subs first")
        if t.path("subdomains").exists():
            prober.run(t)

    if "urls" in st:
        out("[4/5] Collecting URLs with Wayback/Katana/GAU...")
        if not t.path("httpx").exists():
            err("no HTTPX data found; run with --httpx first")
        else:
            collector.run(t)

    if "analyze" in st:
        out("[5/5] Analyzing URLs...")
        if not t.path("all_urls").exists():
            if any(t.path(k).exists() for k in ("wayback", "katana", "gau")):
                collector.merge_all(t)
            else:
                warn("no collected URLs found; run with --urls first")
        if t.path("all_urls").exists():
            analyzer.run(t)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="recon.py",
        description="Authorized bug-bounty recon: Subfinder+Assetfinder -> HTTPX -> "
                    "Wayback+Katana+GAU -> extension/keyword/parameter/email analysis. "
                    "Output is written to the current directory; config files "
                    "(extensions.txt, keywords.txt) are loaded from the script's own directory.",
        epilog="examples:\n"
               "  python3 recon.py -u example.com\n"
               "  python3 recon.py -dl domains.txt --resume\n"
               "  python3 recon.py -u example.com --analyze     # re-run analysis only\n"
               "  python3 recon.py -u example.com --subs --httpx\n\n"
               "Only use against targets you are authorized to test.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-u", "--url", metavar="DOMAIN", help="single target domain (e.g. example.com)")
    g.add_argument("-dl", "--domain-list", dest="dl", metavar="FILE",
                   help="file with one domain per line (blank lines/duplicates ignored)")
    p.add_argument("--resume", action="store_true", help="reuse valid existing data, skip completed stages; failed/incomplete stages are retried")
    st = p.add_argument_group("stages (default: run all; combine as needed)")
    st.add_argument("--subs", action="store_true", help="Subfinder + Assetfinder + merge")
    st.add_argument("--httpx", action="store_true", help="probe subdomains with HTTPX")
    st.add_argument("--urls", action="store_true", help="collect URLs with Wayback/Katana/GAU")
    st.add_argument("--analyze", action="store_true", help="analyze collected URLs")
    tune = p.add_argument_group("tuning (conservative defaults)")
    tune.add_argument("--timeout", type=int, default=3600, metavar="SEC", help="per-tool timeout (default 3600)")
    tune.add_argument("--threads", type=int, default=25, help="httpx threads (default 25)")
    tune.add_argument("--rate", type=int, default=50, help="requests/sec for httpx and katana (default 50)")
    tune.add_argument("--depth", type=int, default=2, help="katana crawl depth (default 2)")
    tune.add_argument("--keyword-in-host", action="store_true",
                      help="also match keywords in the hostname (default: path+query only)")
    return p.parse_args()


def load_targets(args: argparse.Namespace) -> tuple[list[str], bool]:
    if args.url:
        d = normalize_domain(args.url)
        if not d:
            err(f"invalid domain: {args.url!r}")
            sys.exit(2)
        return [d], False
    path = Path(args.dl)
    if not path.is_file():
        err(f"domain list not found: {path}")
        sys.exit(2)
    domains: dict[str, None] = {}
    for line in read_lines(path):
        if line.startswith("#"):
            continue
        d = normalize_domain(line)
        if d:
            domains.setdefault(d, None)
        else:
            warn(f"skipping invalid domain entry: {line!r}")
    if not domains:
        err(f"no valid domains in {path}")
        sys.exit(2)
    return list(domains), True


def main() -> int:
    args = parse_args()
    setup_logging()
    stages = {s for s in ("subs", "httpx", "urls", "analyze") if getattr(args, s)}
    if not stages:
        stages = {"subs", "httpx", "urls", "analyze"}

    domains, multi = load_targets(args)

    deps = DependencyChecker()
    missing = deps.check(stages)
    if missing:
        deps.report_missing(missing)
        return 2
    deps.check_httpx_flavor()

    exts = read_config_list(SCRIPT_DIR / "extensions.txt", "ext") if "analyze" in stages else None
    kws = read_config_list(SCRIPT_DIR / "keywords.txt", "kw") if "analyze" in stages else None
    if "analyze" in stages and kws is None:
        info(f"keywords.txt not found in {SCRIPT_DIR}; keyword analysis skipped")

    sig = hashlib.sha1(json.dumps([exts, kws, args.keyword_in_host]).encode()).hexdigest()
    cfg = Config(stages=stages, resume=args.resume, timeout=args.timeout, threads=args.threads,
                 rate=args.rate, depth=args.depth, keyword_in_host=args.keyword_in_host,
                 exts=exts, keywords=kws, sig=sig)
    rm = ResumeManager()

    # Single-domain mode uses unprefixed files. If this directory's unprefixed files
    # already belong to a different domain, isolate this domain instead of overwriting.
    prefixed = multi
    if not multi:
        owner = rm.single_owner()
        if owner and owner != domains[0]:
            warn(f"unprefixed files/results in this directory belong to {owner}; using "
                 f"{domains[0]}-*.txt and results/{domains[0]}/ for {domains[0]} so nothing is overwritten")
            prefixed = True
        elif not owner:
            rm.set_single_owner(domains[0])

    summary = SummaryManager()
    targets: list[Target] = []

    for i, dom in enumerate(domains, 1):
        if multi:
            out(f"\n[{i}/{len(domains)}] Processing {dom}")
        t = Target(dom, prefixed)
        targets.append(t)
        try:
            process_target(t, cfg, deps, rm)
        except KeyboardInterrupt:
            raise
        except Exception as e:  # one failing domain must not stop the others
            t.stats.failed = True
            if t.stage in ResumeManager.ORDER:
                rm.fail(t.domain, t.stage, f"unexpected error: {e}", t.f.get(t.stage))
            err(f"{dom} failed in stage '{t.stage}': {e} (details in recon.log)")
            LOG.error("traceback for %s:\n%s", dom, traceback.format_exc())
        summary.domain(t)

    if multi:
        summary.overall(targets)
    return 1 if any(t.stats.failed or t.stats.failures for t in targets) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Completed stages are saved; re-run with --resume to continue.",
              file=sys.stderr)
        sys.exit(130)
