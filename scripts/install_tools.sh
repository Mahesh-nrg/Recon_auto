#!/usr/bin/env bash
# Install (or update) the Go-based recon tools that recon.sh looks for.
# Safe to re-run: it only (re)installs what go install already handles idempotently.
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

command -v go >/dev/null 2>&1 || {
  echo -e "${RED}[!] Go is required (https://go.dev/doc/install), then re-run this script.${NC}"
  exit 1
}

declare -A TOOLS=(
  ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  ["assetfinder"]="github.com/tomnomnom/assetfinder@latest"
  ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
  ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
  ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  ["gau"]="github.com/lc/gau/v2/cmd/gau@latest"
  ["gf"]="github.com/tomnomnom/gf@latest"
  ["hakrawler"]="github.com/hakluke/hakrawler@latest"
  ["urlfinder"]="github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"
)

GOBIN="$(go env GOBIN 2>/dev/null || true)"
[ -z "$GOBIN" ] && GOBIN="$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin"

echo "Installing into $GOBIN (add it to PATH if it is not already):"
echo "  export PATH=\"$GOBIN:\$PATH\""
echo ""

for tool in "${!TOOLS[@]}"; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo -e "${GREEN}[ok]${NC} $tool already on PATH, skipping"
    continue
  fi
  echo -e "${YELLOW}[..]${NC} installing $tool"
  if go install "${TOOLS[$tool]}" >/dev/null 2>&1; then
    echo -e "${GREEN}[ok]${NC} $tool installed to $GOBIN"
  else
    echo -e "${RED}[!!]${NC} $tool failed to install (check your Go/network setup)"
  fi
done

echo ""
echo "Optional extra tools recon.sh will use automatically if present on PATH, but does not"
echo "install here (not Go modules — see README 'Optional tools'):"
echo "  - findomain   https://github.com/Findomain/Findomain"
echo "  - urldedupe   https://github.com/ameenmaali/urldedupe"
echo ""
echo "gf also needs pattern definitions to find anything:"
echo "  git clone https://github.com/tomnomnom/Gf-Patterns ~/.gf-patterns-tmp"
echo "  mkdir -p ~/.gf && cp ~/.gf-patterns-tmp/*.json ~/.gf && rm -rf ~/.gf-patterns-tmp"
echo ""
echo "System packages (Debian/Ubuntu/Kali): sudo apt install nmap"
