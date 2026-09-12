#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

VERSION="1.0.0"

# -----------------------------
# Tunables (override via env)
# -----------------------------
OUT_ROOT="${OUT_ROOT:-./recon-results}"
SUBFINDER_ALL="${SUBFINDER_ALL:-1}"
HTTPX_THREADS="${HTTPX_THREADS:-25}"
HTTPX_RPS="${HTTPX_RPS:-20}"
HTTPX_TIMEOUT="${HTTPX_TIMEOUT:-10}"
KATANA_DEPTH="${KATANA_DEPTH:-3}"
KATANA_RPS="${KATANA_RPS:-5}"
KATANA_CONCURRENCY="${KATANA_CONCURRENCY:-5}"
KATANA_PARALLELISM="${KATANA_PARALLELISM:-2}"
KATANA_TIMEOUT="${KATANA_TIMEOUT:-10}"
GAU_THREADS="${GAU_THREADS:-5}"
GAU_TIMEOUT="${GAU_TIMEOUT:-15}"
NUCLEI_RPS="${NUCLEI_RPS:-5}"
NUCLEI_CONCURRENCY="${NUCLEI_CONCURRENCY:-5}"
NUCLEI_BULK="${NUCLEI_BULK:-5}"
NUCLEI_TIMEOUT="${NUCLEI_TIMEOUT:-10}"
NUCLEI_MAX_HOST_ERRORS="${NUCLEI_MAX_HOST_ERRORS:-10}"
MAX_LIVE_HOSTS="${MAX_LIVE_HOSTS:-5000}"
ALLOW_LARGE_SCOPE="${ALLOW_LARGE_SCOPE:-0}"

DOMAIN=""
TELEGRAM_ENABLED=0
UPDATE_TEMPLATES=0

usage() {
  cat <<'USAGE'
Usage:
  bb-pipeline.sh -d example.com [options]

Options:
  -d, --domain DOMAIN       Root domain / wildcard scope root (required)
  -o, --out DIR             Output root (default: ./recon-results)
      --telegram            Send a compact summary to Telegram
      --update-templates    Update nuclei-templates before scanning
  -h, --help                Show help

Telegram environment variables:
  TELEGRAM_BOT_TOKEN
  TELEGRAM_CHAT_ID

Rate/concurrency can be overridden with environment variables, for example:
  NUCLEI_RPS=2 KATANA_RPS=2 ./bb-pipeline.sh -d example.com
USAGE
}

log()  { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
warn() { printf '[%s] [WARN] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
die()  { printf '[%s] [ERROR] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; exit 1; }

cleanup() {
  [[ -n "${TMP_DIR:-}" && -d "${TMP_DIR:-}" ]] && rm -rf -- "$TMP_DIR"
}
trap cleanup EXIT
trap 'rc=$?; warn "Pipeline failed at line ${LINENO} (exit ${rc})"; exit "${rc}"' ERR

count_lines() {
  local f="$1"
  if [[ -s "$f" ]]; then
    wc -l < "$f" | tr -d ' '
  else
    printf '0'
  fi
}

normalize_domain() {
  local d="${1,,}"
  d="${d#http://}"
  d="${d#https://}"
  d="${d#\*.}"
  d="${d%%/*}"
  d="${d%%:*}"
  d="${d%.}"

  [[ "$d" =~ ^([a-z0-9][a-z0-9-]{0,62}\.)+[a-z0-9-]{2,63}$ ]] \
    || die "Invalid domain: $1"
  printf '%s' "$d"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"
}

verify_tooling() {
  local required=(subfinder httpx katana gau uro nuclei awk grep sed sort head wc tee)
  local cmd
  for cmd in "${required[@]}"; do
    require_cmd "$cmd"
  done

  httpx -h 2>&1 | grep -q -- '-match-code' \
    || die "'httpx' does not look like ProjectDiscovery httpx"
  katana -h 2>&1 | grep -q -- '-js-crawl' \
    || die "'katana' does not look like ProjectDiscovery katana"
  subfinder -h 2>&1 | grep -q -- '-domain' \
    || die "'subfinder' does not look like ProjectDiscovery subfinder"
  nuclei -h 2>&1 | grep -q -- '-severity' \
    || die "'nuclei' does not look like ProjectDiscovery nuclei"
  gau -h 2>&1 | grep -q -- '--providers' \
    || die "'gau' CLI is not compatible with lc/gau"
  uro -h 2>&1 | grep -q -- 'hasparams' \
    || die "'uro' CLI is not compatible with s0md3v/uro"

  if (( TELEGRAM_ENABLED )); then
    require_cmd curl
    [[ -n "${TELEGRAM_BOT_TOKEN:-}" ]] || die "TELEGRAM_BOT_TOKEN is required with --telegram"
    [[ -n "${TELEGRAM_CHAT_ID:-}" ]] || die "TELEGRAM_CHAT_ID is required with --telegram"
  fi
}

send_telegram() {
  local message="$1"
  (( TELEGRAM_ENABLED )) || return 0

  if ! curl -fsS --max-time 15 \
      -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
      --data-urlencode "chat_id=${TELEGRAM_CHAT_ID}" \
      --data-urlencode "disable_web_page_preview=true" \
      --data-urlencode "text=${message}" >/dev/null; then
    warn "Telegram notification failed"
  fi
}

while (($#)); do
  case "$1" in
    -d|--domain)
      [[ $# -ge 2 ]] || die "$1 requires a value"
      DOMAIN="$2"
      shift 2
      ;;
    -o|--out)
      [[ $# -ge 2 ]] || die "$1 requires a value"
      OUT_ROOT="$2"
      shift 2
      ;;
    --telegram)
      TELEGRAM_ENABLED=1
      shift
      ;;
    --update-templates)
      UPDATE_TEMPLATES=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "Unknown option: $1"
      ;;
  esac
done

[[ -n "$DOMAIN" ]] || { usage; exit 2; }
DOMAIN="$(normalize_domain "$DOMAIN")"
verify_tooling

STAMP="$(date '+%Y%m%d_%H%M%S')"
RUN_DIR="${OUT_ROOT%/}/${DOMAIN}/${STAMP}"
RECON_DIR="$RUN_DIR/recon"
CRAWL_DIR="$RUN_DIR/crawl"
SCAN_DIR="$RUN_DIR/scan"
REPORT_DIR="$RUN_DIR/report"
TMP_DIR="$RUN_DIR/.tmp"
mkdir -p "$RECON_DIR" "$CRAWL_DIR" "$SCAN_DIR" "$REPORT_DIR" "$TMP_DIR"

LOG_FILE="$RUN_DIR/pipeline.log"
exec > >(tee -a "$LOG_FILE") 2>&1

DOMAIN_RX="${DOMAIN//./\\.}"
HOST_RX="^([A-Za-z0-9-]+\\.)*${DOMAIN_RX}$"
URL_SCOPE_RX="^https?://([A-Za-z0-9-]+\\.)*${DOMAIN_RX}(:[0-9]+)?([/?#]|$)"
KATANA_SCOPE_RX="^https?://([A-Za-z0-9-]+\\.)*${DOMAIN_RX}(:[0-9]+)?(/|$)"

SUB_RAW="$TMP_DIR/subfinder.raw"
SUBS="$RECON_DIR/subdomains.txt"
HTTPX_META="$RECON_DIR/alive_with_status.txt"
ALIVE="$RECON_DIR/alive_urls.txt"
KATANA_RAW="$CRAWL_DIR/katana.txt"
GAU_RAW="$CRAWL_DIR/gau.txt"
ALL_SCOPED="$CRAWL_DIR/all_scoped_urls.txt"
CLEAN_URLS="$CRAWL_DIR/clean_urls.txt"
PARAM_URLS="$CRAWL_DIR/parameter_urls.txt"
LOGIC_IDOR="$CRAWL_DIR/logic_idor_candidates.txt"
NUCLEI_TXT="$SCAN_DIR/nuclei_findings.txt"
NUCLEI_JSONL="$SCAN_DIR/nuclei_findings.jsonl"
SUMMARY="$REPORT_DIR/summary.md"
VERSIONS="$RUN_DIR/tool-versions.txt"

: > "$KATANA_RAW"
: > "$GAU_RAW"
: > "$NUCLEI_TXT"
: > "$NUCLEI_JSONL"

log "BARQ-style recon pipeline v${VERSION}"
log "Scope root: $DOMAIN"
log "Run directory: $RUN_DIR"

{
  printf 'Run: %s\n' "$STAMP"
  printf 'Domain: %s\n' "$DOMAIN"
  for tool in subfinder httpx katana gau uro nuclei; do
    printf '\n[%s]\n' "$tool"
    "$tool" -version 2>&1 || "$tool" --version 2>&1 || true
  done
} > "$VERSIONS"

# -----------------------------
# 1) Passive subdomain discovery
# -----------------------------
log "[1/5] Subdomain discovery with subfinder"
SUBFINDER_ARGS=(-d "$DOMAIN" -silent)
if [[ "$SUBFINDER_ALL" == "1" ]]; then
  SUBFINDER_ARGS+=(-all)
fi

if ! subfinder "${SUBFINDER_ARGS[@]}" > "$SUB_RAW"; then
  warn "subfinder returned non-zero; continuing with partial output and root domain"
fi

{
  printf '%s\n' "$DOMAIN"
  cat "$SUB_RAW"
} | tr -d '\r' \
  | grep -E "$HOST_RX" \
  | LC_ALL=C sort -u > "$SUBS"

log "Subdomains in scope: $(count_lines "$SUBS")"

# -----------------------------
# 2) Probe only 200/302/403
# -----------------------------
log "[2/5] Probing live HTTP targets with httpx"
if ! httpx \
    -l "$SUBS" \
    -silent \
    -nc \
    -mc 200,302,403 \
    -sc \
    -t "$HTTPX_THREADS" \
    -rl "$HTTPX_RPS" \
    -timeout "$HTTPX_TIMEOUT" \
    -retries 1 > "$HTTPX_META"; then
  warn "httpx returned non-zero; using any partial output"
fi

awk 'NF {print $1}' "$HTTPX_META" \
  | grep -E "$URL_SCOPE_RX" \
  | LC_ALL=C sort -u > "$ALIVE"

LIVE_COUNT="$(count_lines "$ALIVE")"
log "Live targets (200/302/403): $LIVE_COUNT"

if (( LIVE_COUNT == 0 )); then
  cat > "$SUMMARY" <<EOF_SUMMARY
# Recon Summary — $DOMAIN

- Run: $STAMP
- In-scope subdomains: $(count_lines "$SUBS")
- Live targets (200/302/403): 0
- Parameterized endpoints: 0
- Logic / IDOR candidates: 0
- Nuclei findings: 0

No live HTTP targets matched 200/302/403. Pipeline stopped cleanly.
EOF_SUMMARY
  send_telegram "Recon finished for ${DOMAIN}: no live 200/302/403 targets."
  log "Done: $SUMMARY"
  exit 0
fi

if (( LIVE_COUNT > MAX_LIVE_HOSTS )) && [[ "$ALLOW_LARGE_SCOPE" != "1" ]]; then
  die "Refusing to scan $LIVE_COUNT live hosts (MAX_LIVE_HOSTS=$MAX_LIVE_HOSTS). Set ALLOW_LARGE_SCOPE=1 only if the whole scope is authorized."
fi

# -----------------------------
# 3) Crawl + historical URL collection
# -----------------------------
log "[3/5] Crawling with katana and collecting historical URLs with gau"

if ! katana \
    -list "$ALIVE" \
    -silent \
    -nc \
    -d "$KATANA_DEPTH" \
    -jc \
    -kf all \
    -cs "$KATANA_SCOPE_RX" \
    -rl "$KATANA_RPS" \
    -c "$KATANA_CONCURRENCY" \
    -p "$KATANA_PARALLELISM" \
    -timeout "$KATANA_TIMEOUT" \
    -retry 1 \
    -ef png,jpg,jpeg,gif,webp,svg,ico,css,woff,woff2,ttf,eot,mp4,mp3,avi,mov,pdf,zip,rar,7z > "$KATANA_RAW"; then
  warn "katana returned non-zero; keeping partial crawl output"
fi

if ! gau "$DOMAIN" \
    --subs \
    --threads "$GAU_THREADS" \
    --timeout "$GAU_TIMEOUT" \
    --retries 2 \
    --blacklist png,jpg,jpeg,gif,webp,svg,ico,css,woff,woff2,ttf,eot,mp4,mp3,avi,mov,pdf,zip,rar,7z > "$GAU_RAW"; then
  warn "gau returned non-zero; keeping partial historical output"
fi

cat "$KATANA_RAW" "$GAU_RAW" \
  | tr -d '\r' \
  | sed 's/[[:space:]]*$//' \
  | grep -aE "$URL_SCOPE_RX" \
  | sed 's/#.*$//' \
  | LC_ALL=C sort -u > "$ALL_SCOPED"

# uro removes duplicate/noisy URLs. Keep both a general clean set and a
# parameter-only set for manual XSS/SQLi/SSRF/IDOR triage.
if [[ -s "$ALL_SCOPED" ]]; then
  uro < "$ALL_SCOPED" > "$CLEAN_URLS"
  uro --filters hasparams < "$CLEAN_URLS" > "$PARAM_URLS"
else
  : > "$CLEAN_URLS"
  : > "$PARAM_URLS"
fi

# Logic/IDOR prioritization: query identifiers + REST-style object references.
# This intentionally creates candidates, not vulnerability claims.
{
  grep -Eai '[?&](id|uid|user(_?id)?|account(_?id)?|profile(_?id)?|member(_?id)?|customer(_?id)?|order(_?id)?|invoice(_?id)?|payment(_?id)?|tenant(_?id)?|org(_?id)?|organization(_?id)?|project(_?id)?|team(_?id)?|document(_?id)?|doc(_?id)?|file(_?id)?|resource(_?id)?|object(_?id)?|role(_?id)?|owner(_?id)?)=' "$PARAM_URLS" || true
  grep -Eai '/(users?|accounts?|profiles?|members?|customers?|orders?|invoices?|payments?|tenants?|orgs?|organizations?|projects?|teams?|documents?|docs?|files?|resources?|objects?)/([0-9]+|[0-9a-f]{8,}(-[0-9a-f]{4,}){2,}|[A-Za-z0-9_-]{8,})([/?#]|$)' "$CLEAN_URLS" || true
} | LC_ALL=C sort -u > "$LOGIC_IDOR"

log "Scoped URLs: $(count_lines "$ALL_SCOPED")"
log "Clean URLs: $(count_lines "$CLEAN_URLS")"
log "Parameterized URLs: $(count_lines "$PARAM_URLS")"
log "Logic/IDOR candidates: $(count_lines "$LOGIC_IDOR")"

# -----------------------------
# 4) Targeted nuclei scan
# -----------------------------
log "[4/5] Targeted nuclei scan (high/critical + CVE/exposure/misconfiguration tags)"

if (( UPDATE_TEMPLATES )); then
  if ! nuclei -ut; then
    warn "nuclei template update failed; continuing with installed templates"
  fi
fi

# Intentionally scan base live URLs only. Feeding every historical parameter URL
# into CVE/exposure templates multiplies requests with little benefit and makes
# WAF/rate-limit problems worse.
if ! nuclei \
    -l "$ALIVE" \
    -severity high,critical \
    -tags cve,exposure,exposures,config,misconfig,misconfiguration \
    -etags dos,fuzz,bruteforce,intrusive \
    -pt http \
    -rl "$NUCLEI_RPS" \
    -c "$NUCLEI_CONCURRENCY" \
    -bs "$NUCLEI_BULK" \
    -timeout "$NUCLEI_TIMEOUT" \
    -retries 1 \
    -mhe "$NUCLEI_MAX_HOST_ERRORS" \
    -nc \
    -or \
    -ot \
    -o "$NUCLEI_TXT" \
    -jle "$NUCLEI_JSONL"; then
  warn "nuclei returned non-zero; keeping partial findings"
fi

# -----------------------------
# 5) Summary
# -----------------------------
log "[5/5] Building summary report"

SUB_COUNT="$(count_lines "$SUBS")"
PARAM_COUNT="$(count_lines "$PARAM_URLS")"
LOGIC_COUNT="$(count_lines "$LOGIC_IDOR")"
NUCLEI_COUNT="$(count_lines "$NUCLEI_TXT")"

{
  printf '# Recon & Vulnerability Triage Summary — %s\n\n' "$DOMAIN"
  printf -- '- Run: `%s`\n' "$STAMP"
  printf -- '- In-scope subdomains: **%s**\n' "$SUB_COUNT"
  printf -- '- Live targets (200/302/403): **%s**\n' "$LIVE_COUNT"
  printf -- '- Scoped URLs collected: **%s**\n' "$(count_lines "$ALL_SCOPED")"
  printf -- '- Parameterized endpoints: **%s**\n' "$PARAM_COUNT"
  printf -- '- Logic / IDOR candidates: **%s**\n' "$LOGIC_COUNT"
  printf -- '- Nuclei high/critical findings: **%s**\n\n' "$NUCLEI_COUNT"

  printf '## Logic / IDOR candidates\n\n'
  if [[ -s "$LOGIC_IDOR" ]]; then
    head -n 100 "$LOGIC_IDOR" | sed 's/^/- /'
  else
    printf '_No candidates matched the prioritization heuristics._\n'
  fi

  printf '\n## Nuclei findings\n\n'
  if [[ -s "$NUCLEI_TXT" ]]; then
    head -n 100 "$NUCLEI_TXT" | sed 's/^/- /'
  else
    printf '_No matching high/critical nuclei findings._\n'
  fi

  printf '\n## Files\n\n'
  printf -- '- Alive targets: `%s`\n' "$ALIVE"
  printf -- '- Parameter URLs: `%s`\n' "$PARAM_URLS"
  printf -- '- Logic / IDOR candidates: `%s`\n' "$LOGIC_IDOR"
  printf -- '- Nuclei JSONL: `%s`\n' "$NUCLEI_JSONL"
  printf -- '- Tool versions: `%s`\n' "$VERSIONS"
  printf -- '- Full log: `%s`\n' "$LOG_FILE"
} > "$SUMMARY"

TELEGRAM_TEXT="Recon finished: ${DOMAIN}
Subdomains: ${SUB_COUNT}
Live 200/302/403: ${LIVE_COUNT}
Parameterized URLs: ${PARAM_COUNT}
Logic/IDOR candidates: ${LOGIC_COUNT}
Nuclei high/critical: ${NUCLEI_COUNT}"

if [[ -s "$NUCLEI_TXT" ]]; then
  TELEGRAM_TEXT+=$'\n\nTop nuclei findings:\n'
  TELEGRAM_TEXT+="$(head -n 5 "$NUCLEI_TXT")"
fi
send_telegram "${TELEGRAM_TEXT:0:3900}"

log "Completed successfully"
log "Summary: $SUMMARY"
