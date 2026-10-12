#!/usr/bin/env bash
# =============================================================================
# recon.sh — modular recon pipeline for authorized security assessments
#
# Chains a set of well-known open-source recon tools (subdomain enumeration,
# HTTP probing, crawling/URL discovery, parameter mining, nuclei scanning) and
# writes everything into one timestamped output folder with a summary report.
#
# Every external command is optional: a missing tool is skipped with a
# warning instead of aborting the run. See scripts/install_tools.sh to install
# the Go-based tools, and README.md for the full list and manual-install ones.
# =============================================================================
set -euo pipefail

VERSION="1.0.0"

# -- colors -----------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; PURPLE='\033[0;35m'; CYAN='\033[0;36m'; NC='\033[0m'

# -- defaults -----------------------------------------------------------------
THREADS_HTTPX=100
THREADS_NUCLEI=25
THREADS_KATANA=50
THREADS_GAU=25
NUCLEI_RATE_LIMIT=150          # requests/sec cap, kept conservative by default
MAX_CONCURRENT_NMAP=5
NMAP_PORTS=""                  # empty = nmap's own default top ports
HTTPX_PORTS="80,443,8080,8443,3000,8000,8001,8008,8083,8834,8888,591,2082,2087,2095,2096"
NUCLEI_SEVERITY="critical,high,medium"
NO_INSTALL=false
SKIP_NMAP=false
SKIP_NUCLEI=false
RECURSIVE_SUBS=false

print_banner() {
  echo -e "${BLUE}"
  cat <<'EOF'
==============================================================================
  recon.sh — recon pipeline (subdomains -> live hosts -> URLs -> nuclei)
==============================================================================
EOF
  echo -e "${NC}"
}

print_usage() {
  cat <<EOF
Usage: $0 -d <domain> [options]

Target selection
  -d, --domain DOMAIN     Target domain (e.g. example.com)
  -i, --input FILE        File with one domain/IP/CIDR per line instead of -d

Tuning
  -t, --threads N         httpx + katana threads (default: $THREADS_HTTPX)
  -n, --nuclei N          nuclei concurrency (default: $THREADS_NUCLEI)
  -c, --katana N          katana concurrency (default: $THREADS_KATANA)
  --rate-limit N          nuclei requests/sec cap (default: $NUCLEI_RATE_LIMIT)
  --severity LIST         nuclei severities, comma separated (default: $NUCLEI_SEVERITY)
  --recursive             Recursive subdomain enumeration (subfinder -recursive)

Skip stages
  --no-install            Skip the auto-install-missing-tools step
  --no-nmap               Skip the nmap stage
  --no-nuclei             Skip the nuclei stage

  -o, --output DIR        Output folder name (default: <target>_recon_<timestamp>)
  -h, --help              Show this help
  -v, --version           Show version

Only run this against targets you own or are explicitly authorized to test.
See README.md for the legal/scope notice.
EOF
  exit 1
}

command_exists() { command -v "$1" >/dev/null 2>&1; }

run_or_skip() {
  # run_or_skip <tool-name> <description> -- <command...>
  local tool="$1" desc="$2"
  shift 2
  if [[ "${1:-}" == "--" ]]; then shift; fi
  if ! command_exists "$tool"; then
    echo -e "${YELLOW}[skip]${NC} $desc — '$tool' not found"
    return 1
  fi
  echo -e "${CYAN}[run] ${NC}$desc"
  "$@"
}

# -- argument parsing ---------------------------------------------------------
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) TARGET="${2:?missing value for $1}"; shift 2 ;;
      -i|--input) INPUT_FILE="${2:?missing value for $1}"; shift 2 ;;
      -t|--threads) THREADS_HTTPX="${2:?}"; THREADS_KATANA="${2:?}"; shift 2 ;;
      -n|--nuclei) THREADS_NUCLEI="${2:?}"; shift 2 ;;
      -c|--katana) THREADS_KATANA="${2:?}"; shift 2 ;;
      --rate-limit) NUCLEI_RATE_LIMIT="${2:?}"; shift 2 ;;
      --severity) NUCLEI_SEVERITY="${2:?}"; shift 2 ;;
      --recursive) RECURSIVE_SUBS=true; shift ;;
      --no-install) NO_INSTALL=true; shift ;;
      --no-nmap) SKIP_NMAP=true; shift ;;
      --no-nuclei) SKIP_NUCLEI=true; shift ;;
      -o|--output) OUTPUT_FOLDER_OVERRIDE="${2:?}"; shift 2 ;;
      -v|--version) echo "recon.sh $VERSION"; exit 0 ;;
      -h|--help) print_usage ;;
      *) echo -e "${RED}[!] Unknown option: $1${NC}"; print_usage ;;
    esac
  done

  if [[ -n "${INPUT_FILE:-}" ]]; then
    [[ -f "$INPUT_FILE" ]] || { echo -e "${RED}[!] Input file not found: $INPUT_FILE${NC}"; exit 1; }
    mapfile -t TARGETS < "$INPUT_FILE"
    TARGET="${TARGET:-${TARGETS[0]:-}}"
  fi

  if [[ -z "${TARGET:-}" ]]; then
    echo -e "${RED}[!] A target is required: -d DOMAIN or -i FILE${NC}"
    print_usage
  fi

  echo -e "${GREEN}Target: $TARGET${NC}  (httpx threads: $THREADS_HTTPX, nuclei concurrency: $THREADS_NUCLEI)"
}

# -- environment setup ---------------------------------------------------------
install_system_tools() {
  if command_exists apt-get; then
    sudo apt-get update -qq >/dev/null 2>&1 || true
    sudo apt-get install -y -qq nmap curl wget unzip git >/dev/null 2>&1 || true
  fi
}

auto_setup_environment() {
  echo -e "${PURPLE}Checking tools...${NC}"
  if [[ "$NO_INSTALL" == true ]]; then
    echo -e "${GREEN}Skipping install check (--no-install)${NC}"
    return 0
  fi

  install_system_tools

  local required=(subfinder assetfinder httpx katana nuclei gau gf hakrawler urlfinder)
  local missing=()
  for tool in "${required[@]}"; do
    command_exists "$tool" || missing+=("$tool")
  done

  if [[ ${#missing[@]} -eq 0 ]]; then
    echo -e "${GREEN}All core tools are on PATH.${NC}"
  else
    echo -e "${YELLOW}Missing: ${missing[*]}${NC}"
    echo -e "${YELLOW}Run ./scripts/install_tools.sh to install them, or pass --no-install to continue anyway.${NC}"
    echo -e "${YELLOW}Continuing — each missing tool's stage will be skipped.${NC}"
  fi

  command_exists findomain || echo -e "${YELLOW}[info] findomain not found (optional, manual install — see README)${NC}"
  command_exists urldedupe || echo -e "${YELLOW}[info] urldedupe not found (optional, manual install — see README)${NC}"
  echo ""
}

setup_output() {
  local name="${OUTPUT_FOLDER_OVERRIDE:-${TARGET//[^a-zA-Z0-9._-]/_}_recon_$(date +%Y%m%d_%H%M%S)}"
  OUTPUT_FOLDER="$name"
  mkdir -p "$OUTPUT_FOLDER"/{nmap_results,web_apps,urls,params,reports}
  cd "$OUTPUT_FOLDER"
  echo -e "${GREEN}Output folder: $(pwd)${NC}"
}

# -- stages ---------------------------------------------------------------------
discover_subdomains() {
  echo -e "${YELLOW}== Subdomain enumeration ==${NC}"
  : > subdomains_raw.txt

  local pids=()
  if command_exists subfinder; then
    local rec_flag=(); [[ "$RECURSIVE_SUBS" == true ]] && rec_flag=(-recursive)
    (subfinder -d "$TARGET" -all "${rec_flag[@]}" -silent -o subfinder.txt 2>/dev/null) & pids+=($!)
  else
    echo -e "${YELLOW}[skip]${NC} subfinder not found"
  fi
  if command_exists assetfinder; then
    (assetfinder --subs-only "$TARGET" > assetfinder.txt 2>/dev/null) & pids+=($!)
  else
    echo -e "${YELLOW}[skip]${NC} assetfinder not found"
  fi
  if command_exists findomain; then
    (findomain -t "$TARGET" -u findomain.txt >/dev/null 2>&1) & pids+=($!)
  fi
  for pid in "${pids[@]:-}"; do [[ -n "$pid" ]] && wait "$pid" || true; done

  cat subfinder.txt assetfinder.txt findomain.txt 2>/dev/null | sort -u > subdomains_final.txt || true
  rm -f subfinder.txt assetfinder.txt findomain.txt subdomains_raw.txt 2>/dev/null
  echo -e "${GREEN}$(wc -l < subdomains_final.txt 2>/dev/null || echo 0) unique subdomains${NC}"
}

network_scan() {
  [[ "$SKIP_NMAP" == true ]] && { echo -e "${YELLOW}[skip] nmap (--no-nmap)${NC}"; return; }
  command_exists nmap || { echo -e "${YELLOW}[skip]${NC} nmap not found"; return; }
  echo -e "${YELLOW}== Network scan ==${NC}"

  local port_arg=(); [[ -n "$NMAP_PORTS" ]] && port_arg=(-p "$NMAP_PORTS")

  if [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]{1,2})?$ ]]; then
    nmap -sV -sC -T4 "${port_arg[@]}" -oA "nmap_results/${TARGET//\//_}_full" "$TARGET" 2>/dev/null || true
  elif [[ -s subdomains_final.txt ]]; then
    head -50 subdomains_final.txt | xargs -P "$MAX_CONCURRENT_NMAP" -I {} \
      sh -c "nmap -sV -Pn -T4 --min-rate 1000 ${port_arg[*]} -oA 'nmap_results/{}_quick' '{}' 2>/dev/null || true" || true
  fi
}

web_recon() {
  echo -e "${YELLOW}== Web reconnaissance ==${NC}"

  if [[ -s subdomains_final.txt ]] && command_exists httpx; then
    httpx -l subdomains_final.txt -ports "$HTTPX_PORTS" -threads "$THREADS_HTTPX" \
      -timeout 7 -silent -o web_apps/live_hosts.txt 2>/dev/null || true
  else
    echo -e "${YELLOW}[skip]${NC} httpx probing — no subdomains or httpx missing"
  fi

  [[ -s web_apps/live_hosts.txt ]] || { echo -e "${YELLOW}No live hosts; skipping crawling.${NC}"; return; }

  local pids=()
  if command_exists katana; then
    (katana -d 3 -c "$THREADS_KATANA" -silent -o urls/katana.txt < web_apps/live_hosts.txt 2>/dev/null) & pids+=($!)
  fi
  if command_exists gau; then
    (gau --threads "$THREADS_GAU" -o urls/gau.txt < web_apps/live_hosts.txt 2>/dev/null) & pids+=($!)
  fi
  if command_exists hakrawler; then
    (hakrawler -d 2 -u < web_apps/live_hosts.txt > urls/hakrawler.txt 2>/dev/null) & pids+=($!)
  fi
  if command_exists urlfinder; then
    (urlfinder -l subdomains_final.txt -silent -o urls/urlfinder.txt 2>/dev/null) & pids+=($!)
  fi
  for pid in "${pids[@]:-}"; do [[ -n "$pid" ]] && wait "$pid" || true; done

  cat urls/*.txt 2>/dev/null | sort -u > urls/all_urls.txt || true
  if command_exists urldedupe && [[ -s urls/all_urls.txt ]]; then
    urldedupe -u urls/all_urls.txt > urls/all_urls_deduped.txt 2>/dev/null \
      && mv urls/all_urls_deduped.txt urls/all_urls.txt || true
  fi
  echo -e "${GREEN}$(wc -l < urls/all_urls.txt 2>/dev/null || echo 0) unique URLs${NC}"

  mine_parameters
}

mine_parameters() {
  [[ -s urls/all_urls.txt ]] || return 0

  grep '?' urls/all_urls.txt > params/raw_params.txt 2>/dev/null || true
  # dedupe by parameter *names* (ignore values) so near-identical URLs collapse to one
  sed -E 's/=[^&]*/=/g' params/raw_params.txt 2>/dev/null | sort -u > params/params_by_name.txt || true

  command_exists gf || { echo -e "${YELLOW}[skip]${NC} gf not found (see README for pattern setup)"; return 0; }
  [[ -s params/raw_params.txt ]] || return 0

  for pattern in sqli xss lfi xxe ssrf; do
    gf "$pattern" < params/raw_params.txt > "params/${pattern}.txt" 2>/dev/null || true
  done
  echo -e "${GREEN}Parameter candidates written to params/*.txt${NC}"
}

nuclei_scan() {
  [[ "$SKIP_NUCLEI" == true ]] && { echo -e "${YELLOW}[skip] nuclei (--no-nuclei)${NC}"; return; }
  command_exists nuclei || { echo -e "${YELLOW}[skip]${NC} nuclei not found"; return; }
  echo -e "${YELLOW}== Nuclei scan (severity: $NUCLEI_SEVERITY) ==${NC}"

  local target_file="subdomains_final.txt"
  [[ -s web_apps/live_hosts.txt ]] && target_file="web_apps/live_hosts.txt"
  [[ -s "$target_file" ]] || { echo -e "${YELLOW}Nothing to scan.${NC}"; return; }

  nuclei -l "$target_file" -c "$THREADS_NUCLEI" -rl "$NUCLEI_RATE_LIMIT" \
    -severity "$NUCLEI_SEVERITY" -silent -o nuclei_results.txt 2>/dev/null || true

  if [[ -s nuclei_results.txt ]]; then
    echo -e "${GREEN}$(wc -l < nuclei_results.txt) findings — top 5:${NC}"
    head -5 nuclei_results.txt
  else
    echo -e "${GREEN}No findings at severity $NUCLEI_SEVERITY.${NC}"
  fi
}

generate_report() {
  echo -e "${YELLOW}== Report ==${NC}"
  {
    echo "=== Recon summary — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
    echo "Target: $TARGET"
    echo "recon.sh version: $VERSION"
    echo "Threads: httpx=$THREADS_HTTPX nuclei=$THREADS_NUCLEI katana=$THREADS_KATANA"
    echo ""
    echo "Counts:"
    echo "  Subdomains : $(wc -l < subdomains_final.txt 2>/dev/null || echo 0)"
    echo "  Live hosts : $(wc -l < web_apps/live_hosts.txt 2>/dev/null || echo 0)"
    echo "  URLs       : $(wc -l < urls/all_urls.txt 2>/dev/null || echo 0)"
    echo "  Nuclei hits: $(wc -l < nuclei_results.txt 2>/dev/null || echo 0)"
    echo ""
    echo "Key files:"
    ls -lh ./*.txt web_apps/*.txt urls/*.txt nuclei_results.txt 2>/dev/null | head -20 || true
  } > reports/summary.txt
  echo -e "${GREEN}reports/summary.txt written${NC}"
}

main() {
  print_banner
  parse_args "$@"
  auto_setup_environment
  setup_output

  discover_subdomains
  network_scan
  web_recon
  nuclei_scan
  generate_report

  echo -e "${GREEN}"
  echo "Done. Results: $(basename "$PWD")/"
  echo "Summary:  cat reports/summary.txt"
  echo -e "${NC}"
}

main "$@"
