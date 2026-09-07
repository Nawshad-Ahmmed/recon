#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  recon.sh — Automated subdomain + URL + JS + Nuclei pipeline
# ============================================================
#
#  Usage:
#    ./recon.sh <target-domain>
#    ./recon.sh example.com
#
#  Prerequisites:
#    subfinder, httpx, katana, nuclei — all in $PATH
#    (go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
#     go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
#     go install -v github.com/projectdiscovery/katana/cmd/katana@latest
#     go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)
#
#  Output structure:
#    recon/
#    ├── subdomains/
#    │   ├── all.txt              # raw subfinder output
#    │   └── live.txt             # httpx -live filtered
#    ├── urls/
#    │   ├── all.txt              # all crawled URLs
#    │   └── js-endpoints.txt     # URLs with .js extension
#    ├── js/
#    │   ├── urls.txt             # JavaScript file URLs
#    │   ├── responses/           # raw JS file downloads
#    │   └── endpoints.txt        # extracted relative paths / secrets
#    ├── nuclei/
#    │   ├── tech-detect.txt      # technology detection
#    │   ├── exposures.txt        # exposure templates
#    │   ├── vulnerabilities.txt  # vulnerability templates
#    │   └── misconfigs.txt       # misconfiguration templates
#    └── summary.txt              # human-readable summary
# ============================================================

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

banner() {
    echo -e "${CYAN}"
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║        RECON PIPELINE v1.0               ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

usage() {
    echo "Usage: $0 <target-domain>"
    echo "  $0 example.com"
    exit 1
}

# --- Args ---
TARGET="${1:-}"
[ -z "$TARGET" ] && usage

# --- Dir setup ---
BASE_DIR="recon"
SUB_D="$BASE_DIR/subdomains"
URL_D="$BASE_DIR/urls"
JS_D="$BASE_DIR/js"
JS_RESP="$JS_D/responses"
NUC_D="$BASE_DIR/nuclei"

mkdir -p "$SUB_D" "$URL_D" "$JS_RESP" "$NUC_D"

# --- Timestamped logging ---
log()   { echo -e "${GREEN}[$(date +%H:%M:%S)]${NC} $*"; }
warn()  { echo -e "${YELLOW}[$(date +%H:%M:%S)] [WARN]${NC} $*"; }
fail()  { echo -e "${RED}[$(date +%H:%M:%S)] [FAIL]${NC} $*"; }

banner
log "Target: ${CYAN}$TARGET${NC}"
log "Output: ${CYAN}$BASE_DIR/${NC}"
echo

# ============================================================
#  1. SUBDOMAIN DISCOVERY — subfinder
# ============================================================
log "[1/5] Running subfinder..."
if subfinder -d "$TARGET" -all -o "$SUB_D/all.txt" -silent 2>/dev/null; then
    COUNT=$(wc -l < "$SUB_D/all.txt" 2>/dev/null || echo 0)
    log "  → Found ${CYAN}$COUNT${NC} subdomains"
else
    warn "  subfinder failed or found nothing — continuing with target only"
    echo "$TARGET" > "$SUB_D/all.txt"
fi

# ============================================================
#  2. LIVE PROBE — httpx
# ============================================================
log "[2/5] Probing with httpx..."
if httpx -l "$SUB_D/all.txt" \
    -silent -no-color \
    -status-code -title -tech-detect \
    -websocket -favicon \
    -o "$SUB_D/live.txt" 2>/dev/null; then
    LIVE_COUNT=$(wc -l < "$SUB_D/live.txt" 2>/dev/null || echo 0)
    log "  → ${CYAN}$LIVE_COUNT${NC} live hosts"
else
    warn "  httpx failed"
    cp "$SUB_D/all.txt" "$SUB_D/live.txt"
fi

# Extract live URLs only (no metadata) for katana
awk '{print $1}' "$SUB_D/live.txt" > "$SUB_D/live_urls.txt" 2>/dev/null || true

# ============================================================
#  3. CRAWLING — katana
# ============================================================
log "[3/5] Crawling with katana..."
if [ -s "$SUB_D/live_urls.txt" ]; then
    katana -list "$SUB_D/live_urls.txt" \
        -silent -no-color \
        -js-crawl -known-files all \
        -depth 3 \
        -field url \
        -o "$URL_D/all.txt" 2>/dev/null || warn "  katana had errors"
else
    warn "  No live URLs to crawl"
    touch "$URL_D/all.txt"
fi

URL_COUNT=$(wc -l < "$URL_D/all.txt" 2>/dev/null || echo 0)
log "  → Crawled ${CYAN}$URL_COUNT${NC} URLs"

# ============================================================
#  4. JS EXTRACTION
# ============================================================
log "[4/5] Extracting JavaScript..."

# 4a. Filter .js URLs from katana output
grep -Ei '\.js(\?|$)' "$URL_D/all.txt" > "$JS_D/urls.txt" 2>/dev/null || touch "$JS_D/urls.txt"
JS_COUNT=$(wc -l < "$JS_D/urls.txt" 2>/dev/null || echo 0)
log "  → Found ${CYAN}$JS_COUNT${NC} JS file URLs"

# 4b. Also extract JS from httpx probe results (script src patterns)
grep -oP '(?<=src=")[^"]+\.js[^"]*' "$SUB_D/live.txt" >> "$JS_D/urls.txt" 2>/dev/null || true
# Deduplicate
sort -u "$JS_D/urls.txt" -o "$JS_D/urls.txt" 2>/dev/null || true
JS_COUNT=$(wc -l < "$JS_D/urls.txt" 2>/dev/null || echo 0)
log "  → ${CYAN}$JS_COUNT${NC} unique JS URLs after dedup"

# 4c. Download JS files
if [ -s "$JS_D/urls.txt" ]; then
    DOWNLOADED=0
    while IFS= read -r js_url; do
        [ -z "$js_url" ] && continue
        # Safe filename
        fname=$(echo "$js_url" | tr '/:?=&' '_' | cut -c1-200)
        curl -s -L -m 10 -H "User-Agent: Mozilla/5.0" \
            "$js_url" -o "$JS_RESP/$fname" 2>/dev/null && ((DOWNLOADED++)) || true
    done < "$JS_D/urls.txt"
    log "  → Downloaded ${CYAN}$DOWNLOADED${NC} JS files to ${JS_RESP}/"
else
    warn "  No JS URLs to download"
fi

# 4d. Extract endpoints/secrets from JS
log "  → Extracting endpoints and secrets..."
{
    echo "# Endpoints extracted from JS — $(date)"
    echo
    # Extract relative paths
    grep -roPhE \
        '(?:"|\x27)(\/[a-zA-Z0-9_\-\.\/]+)(?:"|\x27)' \
        "$JS_RESP/" 2>/dev/null | sort -u >> "$JS_D/endpoints.txt" || true
    # Extract full API URLs
    grep -roPhE \
        'https?://[a-zA-Z0-9_\-\.]+/[a-zA-Z0-9_\-\.\/]+' \
        "$JS_RESP/" 2>/dev/null | sort -u >> "$JS_D/endpoints.txt" || true
} 2>/dev/null || true
EP_COUNT=$(wc -l < "$JS_D/endpoints.txt" 2>/dev/null || echo 0)
log "  → Extracted ${CYAN}$EP_COUNT${NC} unique endpoints/URLs from JS"

# ============================================================
#  5. NUCLEI SCANS
# ============================================================
log "[5/5] Running nuclei..."

# We run nuclei on live URLs, using auto tech-detect + exposure + vuln templates

# 5a. Technology detection
log "  → Technology detection..."
nuclei -list "$SUB_D/live_urls.txt" \
    -silent -no-color \
    -tags tech \
    -o "$NUC_D/tech-detect.txt" 2>/dev/null || warn "  tech-detect: no results or failed"
TECH_COUNT=$(wc -l < "$NUC_D/tech-detect.txt" 2>/dev/null || echo 0)
log "     ${CYAN}$TECH_COUNT${NC} tech findings"

# 5b. Exposure templates (configs, backups, panels, tokens)
log "  → Exposure scan..."
nuclei -list "$SUB_D/live_urls.txt" \
    -silent -no-color \
    -tags exposure \
    -o "$NUC_D/exposures.txt" 2>/dev/null || warn "  exposures: no results or failed"
EXP_COUNT=$(wc -l < "$NUC_D/exposures.txt" 2>/dev/null || echo 0)
log "     ${CYAN}$EXP_COUNT${NC} exposure findings"

# 5c. Vulnerability templates
log "  → Vulnerability scan..."
nuclei -list "$SUB_D/live_urls.txt" \
    -silent -no-color \
    -severity critical,high,medium \
    -o "$NUC_D/vulnerabilities.txt" 2>/dev/null || warn "  vulns: no results or failed"
VULN_COUNT=$(wc -l < "$NUC_D/vulnerabilities.txt" 2>/dev/null || echo 0)
log "     ${CYAN}$VULN_COUNT${NC} vulnerability findings"

# 5d. Misconfiguration + default-login templates
log "  → Misconfiguration scan..."
nuclei -list "$SUB_D/live_urls.txt" \
    -silent -no-color \
    -tags misconfig,default-login \
    -o "$NUC_D/misconfigs.txt" 2>/dev/null || warn "  misconfigs: no results or failed"
MIS_COUNT=$(wc -l < "$NUC_D/misconfigs.txt" 2>/dev/null || echo 0)
log "     ${CYAN}$MIS_COUNT${NC} misconfiguration findings"

# ============================================================
#  SUMMARY
# ============================================================
SUMMARY="$BASE_DIR/summary.txt"
{
    echo "=============================================="
    echo "  RECON SUMMARY — $TARGET"
    echo "  $(date)"
    echo "=============================================="
    echo
    echo "Subdomains found:      $COUNT"
    echo "Live hosts:            $LIVE_COUNT"
    echo "URLs crawled:          $URL_COUNT"
    echo "JS files discovered:   $JS_COUNT"
    echo "JS endpoints extracted:$EP_COUNT"
    echo
    echo "--- Nuclei Findings ---"
    echo "Technology:            $TECH_COUNT"
    echo "Exposures:             $EXP_COUNT"
    echo "Vulnerabilities:       $VULN_COUNT"
    echo "Misconfigurations:     $MIS_COUNT"
    echo
    echo "--- Output Layout ---"
    echo "  $SUB_D/"
    echo "  $URL_D/"
    echo "  $JS_D/"
    echo "  $JS_RESP/"
    echo "  $NUC_D/"
    echo
    echo "TOP LIVE HOSTS:"
    head -20 "$SUB_D/live.txt" 2>/dev/null || echo "  (none)"
    echo
    echo "TOP NUCLEI VULNS:"
    head -20 "$NUC_D/vulnerabilities.txt" 2>/dev/null || echo "  (none)"
    echo
    echo "TOP NUCLEI EXPOSURES:"
    head -20 "$NUC_D/exposures.txt" 2>/dev/null || echo "  (none)"
} > "$SUMMARY"

echo
log "${GREEN}Done!${NC} Summary written to ${CYAN}$SUMMARY${NC}"
echo
cat "$SUMMARY"
