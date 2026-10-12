# recon.sh

A single bash script that chains a set of well-known, independently-maintained open-source recon
tools into one pipeline: subdomain enumeration → live-host probing → crawling / URL discovery →
parameter mining → [Nuclei](https://github.com/projectdiscovery/nuclei) template scanning, with a
plain-text summary at the end. Nothing here reimplements those tools; it only orchestrates whichever
ones are on your `PATH` and skips the rest.

> ### ⚠ Authorized use only
> Run this only against systems you own, or where you have **explicit, written authorization** to
> test (a penetration-test engagement letter, a bug-bounty program's published scope, your own lab).
> It performs active scanning (port scans, HTTP probing, vulnerability-template checks) against every
> host it discovers — unauthorized use against third-party systems may be illegal in your
> jurisdiction. You are responsible for staying inside the scope you were given. Nothing in this
> repository grants permission to test any system.

## What it does

| Stage | Tools used (every one installed runs; missing ones are skipped) | Output |
|---|---|---|
| Subdomain enumeration | [subfinder](https://github.com/projectdiscovery/subfinder), [assetfinder](https://github.com/tomnomnom/assetfinder), [findomain](https://github.com/Findomain/Findomain) *(optional)* | `subdomains_final.txt` |
| Network scan | [nmap](https://nmap.org/) | `nmap_results/` |
| Live-host probing | [httpx](https://github.com/projectdiscovery/httpx) | `web_apps/live_hosts.txt` |
| Crawling / URL discovery | [katana](https://github.com/projectdiscovery/katana), [gau](https://github.com/lc/gau), [hakrawler](https://github.com/hakluke/hakrawler), [urlfinder](https://github.com/projectdiscovery/urlfinder) | `urls/all_urls.txt` |
| Parameter mining | [gf](https://github.com/tomnomnom/gf) (+ [Gf-Patterns](https://github.com/tomnomnom/Gf-Patterns)), [urldedupe](https://github.com/ameenmaali/urldedupe) *(optional)* | `params/*.txt` |
| Vulnerability templates | [nuclei](https://github.com/projectdiscovery/nuclei) | `nuclei_results.txt` |
| Summary | — | `reports/summary.txt` |

Every stage checks whether its tool is installed before running it; a missing tool is skipped with a
warning instead of stopping the whole run, so a partial toolchain still produces useful output.

## Requirements

- Linux or macOS, `bash`, `git`, `curl`
- [Go](https://go.dev/doc/install) 1.21+ (to install the Go-based tools below)
- `nmap` (`sudo apt install nmap` / `brew install nmap`)
- Enough scope/rate headroom from whoever authorized the test — see the flags below to stay polite

### Install the tools

```bash
./scripts/install_tools.sh
```

This installs the Go-based tools (`subfinder`, `assetfinder`, `httpx`, `katana`, `nuclei`, `gau`,
`gf`, `hakrawler`, `urlfinder`) with `go install`, skipping anything already on `PATH`, and prints
where they landed (usually `$(go env GOPATH)/bin` — make sure that directory is on your `PATH`).

`gf` needs pattern definitions before it can find anything:

```bash
git clone https://github.com/tomnomnom/Gf-Patterns ~/.gf-patterns-tmp
mkdir -p ~/.gf && cp ~/.gf-patterns-tmp/*.json ~/.gf && rm -rf ~/.gf-patterns-tmp
```

### Optional tools

These are not Go modules, so `install_tools.sh` does not install them. `recon.sh` uses them
automatically if they are on `PATH`, and skips that part of the pipeline if not:

- **[findomain](https://github.com/Findomain/Findomain)** — extra passive subdomain source. Install
  a prebuilt binary from its releases page.
- **[urldedupe](https://github.com/ameenmaali/urldedupe)** — collapses near-duplicate URLs
  (same path, different parameter values) before parameter mining. Build from source per its README.

## Usage

```bash
./recon.sh -d example.com
```

```text
Usage: ./recon.sh -d <domain> [options]

Target selection
  -d, --domain DOMAIN     Target domain (e.g. example.com)
  -i, --input FILE        File with one domain/IP/CIDR per line instead of -d

Tuning
  -t, --threads N         httpx + katana threads (default: 100)
  -n, --nuclei N          nuclei concurrency (default: 25)
  -c, --katana N          katana concurrency (default: 50)
  --rate-limit N          nuclei requests/sec cap (default: 150)
  --severity LIST         nuclei severities, comma separated (default: critical,high,medium)
  --recursive             Recursive subdomain enumeration (subfinder -recursive)

Skip stages
  --no-install            Skip the auto-install-missing-tools step
  --no-nmap               Skip the nmap stage
  --no-nuclei             Skip the nuclei stage

  -o, --output DIR        Output folder name (default: <target>_recon_<timestamp>)
  -h, --help              Show this help
  -v, --version           Show version
```

Examples:

```bash
# A single domain, defaults
./recon.sh -d example.com

# Go easy on the target: lower concurrency and a tighter nuclei rate limit
./recon.sh -d example.com -t 30 -n 10 --rate-limit 50

# Only the recon stages, no vulnerability templates
./recon.sh -d example.com --no-nuclei

# A list of in-scope hosts from the engagement's scope document
./recon.sh -i scope.txt
```

## Output

Each run creates `<target>_recon_<UTC timestamp>/` (or the name given with `-o`):

```text
<target>_recon_<timestamp>/
├── subdomains_final.txt     # deduplicated subdomains from every source
├── nmap_results/            # nmap -oA output per host
├── web_apps/
│   └── live_hosts.txt       # hosts that answered over HTTP(S)
├── urls/
│   └── all_urls.txt         # deduplicated URLs from every crawler/archive source
├── params/
│   ├── raw_params.txt       # URLs containing a '?'
│   ├── params_by_name.txt   # same, with values stripped (one line per param name+path)
│   ├── sqli.txt xss.txt lfi.txt xxe.txt ssrf.txt   # gf pattern matches, if gf is set up
├── nuclei_results.txt        # nuclei findings at the requested severity
└── reports/
    └── summary.txt           # counts + key file listing for the run
```

Review every file before acting on it — these are raw tool outputs (crawlers, archives and
vulnerability templates all produce false positives), not a finished report.

## Notes on being a good citizen of the pipeline

- Defaults are conservative (`--rate-limit 150`, moderate thread counts) but still constitute active
  scanning; turn them down further (`-t`, `-n`, `--rate-limit`) on smaller or rate-limit-sensitive
  targets, and confirm acceptable scan windows/rates with whoever authorized the engagement.
- `--no-nmap` / `--no-nuclei` let you run only the passive/discovery stages first.
- Nothing is uploaded anywhere; all output stays in the local output folder.

## License

[MIT](LICENSE) for this script. Each tool it calls is a separate upstream project under its own
license — see the links in the table above.
