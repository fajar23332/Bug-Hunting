#!/usr/bin/env bash
# install_and_deploy.sh
# One-shot installer: installs prerequisites, go-tools, then deploy binaries system-wide.
# Target: Debian/Ubuntu. Use --target to change destination (default /usr/local/bin).
#
# Usage:
#   chmod +x install_and_deploy.sh
#   ./install_and_deploy.sh --yes                # run fully automatic (recommended)
#   ./install_and_deploy.sh --target /usr/bin --yes
#   ./install_and_deploy.sh --undo --target /usr/local/bin
#
set -euo pipefail

# ---------- CONFIG ----------
GOBIN="${HOME}/go/bin"
DEFAULT_TARGET="/usr/local/bin"   # safer default than /usr/bin
TIMESTAMP="$(date +%Y%m%d%H%M%S)"
BACKUP_SUFFIX=".bak-${TIMESTAMP}"
VENV_DIR=".venv"
REQUIREMENTS_FILE="requirements.txt"

# Go modules to install (add/remove as needed)
GO_MODULES=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "github.com/lc/gau/v2/cmd/gau@latest"
  "github.com/hakluke/hakrawler@latest"
  "github.com/tomnomnom/waybackurls@latest"
  "github.com/tomnomnom/assetfinder@latest"
  "github.com/ffuf/ffuf@latest"
  "github.com/hahwul/dalfox@latest"
  "github.com/tomnomnom/gf@latest"
  "github.com/tomnomnom/fff@latest"
)

# binaries we expect to be in $GOBIN after installs (for deploy)
EXPECTED_BINARIES=( subfinder httpx nuclei dnsx gau hakrawler waybackurls assetfinder ffuf dalfox gf fff )

# -----------------------------

usage() {
  cat <<EOF
Usage: $0 [--yes] [--target DIR] [--undo] [--skip-goinstall]
  --yes           : non-interactive, accept all prompts
  --target DIR    : target system dir to copy binaries (default ${DEFAULT_TARGET})
  --undo          : undo previous deploy (restore backups in target dir)
  --skip-goinstall: skip running 'go install' step (useful if you already installed)
EOF
  exit 1
}

# parse args
YES=0
TARGET_DIR="${DEFAULT_TARGET}"
UNDO=0
SKIP_GOINSTALL=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes) YES=1; shift ;;
    --target) TARGET_DIR="$2"; shift 2 ;;
    --undo) UNDO=1; shift ;;
    --skip-goinstall) SKIP_GOINSTALL=1; shift ;;
    -h|--help) usage ;;
    *) echo "Unknown arg: $1"; usage ;;
  esac
done

# helper to run commands with message
info(){ echo -e "\e[1;34m[INFO]\e[0m $*\e[0m"; }
warn(){ echo -e "\e[1;33m[WARN]\e[0m $*\e[0m"; }
err(){ echo -e "\e[1;31m[ERR]\e[0m $*\e[0m"; }

# UNDO mode: restore backups from target dir
if [[ "${UNDO}" -eq 1 ]]; then
  if [[ ! -d "${TARGET_DIR}" ]]; then
    err "Target dir ${TARGET_DIR} not found."
    exit 1
  fi
  info "Restoring backups in ${TARGET_DIR} (if any)..."
  for b in "${EXPECTED_BINARIES[@]}"; do
    backups=( $(ls "${TARGET_DIR}/${b}.bak-"* 2>/dev/null || true) )
    if [[ ${#backups[@]} -gt 0 ]]; then
      latest="${backups[-1]}"
      info "Restoring ${latest} -> ${TARGET_DIR}/${b}"
      sudo cp -v -- "${latest}" "${TARGET_DIR}/${b}"
      sudo chmod 755 "${TARGET_DIR}/${b}"
    else
      info "No backup for ${b}"
    fi
  done
  info "Undo complete."
  exit 0
fi

# Ensure on Debian/Ubuntu for auto apt install
IS_DEBIAN=0
if [[ -f "/etc/debian_version" ]]; then IS_DEBIAN=1; fi

info "One-shot installer starting. Target deploy dir: ${TARGET_DIR}"
echo

# 0) apt installs for base deps (non-interactive)
if [[ "${IS_DEBIAN}" -eq 1 ]]; then
  info "Installing OS packages (git, curl, build-essential, python3... ) via apt (sudo)"
  if [[ "${YES}" -eq 1 ]]; then
    sudo apt update -y
    sudo apt install -y git curl wget ca-certificates build-essential python3 python3-venv python3-pip
  else
    read -r -p "Run 'sudo apt update && sudo apt install -y git curl wget build-essential python3 python3-venv python3-pip'? [y/N]: " ans
    if [[ "${ans}" =~ ^[Yy]$ ]]; then
      sudo apt update -y
      sudo apt install -y git curl wget ca-certificates build-essential python3 python3-venv python3-pip
    else
      warn "Skipping apt install step. Ensure dependencies installed manually."
    fi
  fi
else
  warn "Non-Debian system detected. Please ensure git/curl/python3/go installed manually."
fi

# 1) Ensure go installed (apt if Debian and missing)
if ! command -v go >/dev/null 2>&1; then
  if [[ "${IS_DEBIAN}" -eq 1 ]]; then
    if [[ "${YES}" -eq 1 ]]; then
      info "Installing golang via apt (sudo)"
      sudo apt install -y golang-go
    else
      read -r -p "Install golang via apt? (sudo) [y/N]: " ans
      if [[ "${ans}" =~ ^[Yy]$ ]]; then
        sudo apt install -y golang-go
      else
        err "Go not installed. Please install Go and re-run with --skip-goinstall if you already have binaries."
        exit 1
      fi
    fi
  else
    err "Go not found and auto-install not supported on this OS. Install Go >=1.20 and re-run."
    exit 1
  fi
else
  info "Found go: $(command -v go)"
fi

# 2) setup GOBIN and PATH for session
mkdir -p "${GOBIN}"
export PATH="${GOBIN}:${PATH}"
info "GOBIN set to ${GOBIN}"

# 3) Python venv + pip requirements (if present)
if command -v python3 >/dev/null 2>&1; then
  info "Creating Python venv -> ${VENV_DIR}"
  python3 -m venv "${VENV_DIR}"
  # shellcheck disable=SC1091
  source "${VENV_DIR}/bin/activate"
  pip install --upgrade pip setuptools wheel >/dev/null
  if [[ -f "${REQUIREMENTS_FILE}" ]]; then
    info "Installing Python requirements from ${REQUIREMENTS_FILE}"
    pip install -r "${REQUIREMENTS_FILE}"
  else
    info "No ${REQUIREMENTS_FILE} found — skipping pip installs."
  fi
else
  warn "python3 not found — skipping python venv step."
fi

# 4) Go install tools (unless skipped)
if [[ "${SKIP_GOINSTALL}" -eq 0 ]]; then
  info "Installing go modules (this will take some minutes)..."
  export GO111MODULE=on
  for mod in "${GO_MODULES[@]}"; do
    info " -> go install ${mod}"
    if ! go install -v "${mod}"; then
      warn "go install failed for ${mod} (continue)."
    fi
  done
else
  info "Skipping go install step (--skip-goinstall)."
fi

# 5) sanity: list binaries in GOBIN and warn if missing
info "Checking binaries in ${GOBIN}:"
for b in "${EXPECTED_BINARIES[@]}"; do
  if [[ -x "${GOBIN}/${b}" ]]; then
    echo "  OK: ${b} -> ${GOBIN}/${b}"
  else
    echo "  MISSING: ${b} (will skip copy)"
  fi
done

# 6) Prepare target dir
if [[ ! -d "${TARGET_DIR}" ]]; then
  info "Creating target dir ${TARGET_DIR} (requires sudo)"
  sudo mkdir -p "${TARGET_DIR}"
  sudo chown root:root "${TARGET_DIR}" || true
fi

# 7) Copy with backups
info "Deploying binaries to ${TARGET_DIR} (backups suffix: ${BACKUP_SUFFIX})"
for b in "${EXPECTED_BINARIES[@]}"; do
  src="${GOBIN}/${b}"
  dst="${TARGET_DIR}/${b}"
  if [[ ! -f "${src}" ]]; then
    warn "Skipping ${b}: not found at ${src}"
    continue
  fi
  if [[ -f "${dst}" ]]; then
    info "Backing up existing ${dst} -> ${dst}${BACKUP_SUFFIX}"
    sudo cp -v -- "${dst}" "${dst}${BACKUP_SUFFIX}"
  fi
  info "Copying ${src} -> ${dst}"
  sudo cp -v -- "${src}" "${dst}"
  sudo chmod 755 "${dst}"
done

# 8) Add target to shell rc if not present
SHELL_RC="${HOME}/.bashrc"
if ! grep -qF "${TARGET_DIR}" "${SHELL_RC}" 2>/dev/null; then
  info "Adding ${TARGET_DIR} to PATH in ${SHELL_RC}"
  echo "export PATH=\"${TARGET_DIR}:\$PATH\"" >> "${SHELL_RC}"
  info "Note: open a new terminal or run: source ${SHELL_RC}"
fi

# 9) Final verification (which)
info "Final verification:"
for b in "${EXPECTED_BINARIES[@]}"; do
  if command -v "${b}" >/dev/null 2>&1; then
    echo "  FOUND: ${b} -> $(command -v ${b})"
  else
    echo "  NOT IN PATH: ${b}"
  fi
done

info "All done. If something's missing, re-run with --skip-goinstall (if tools already installed) or check ${GOBIN}."
info "To undo backups restore use: ./install_and_deploy.sh --undo --target ${TARGET_DIR}"
# === Python setup for hunt.py UI ===
echo "[+] Installing Python dependencies for hunt.py"
sudo apt install -y python3 python3-pip
pip install --upgrade pip

# Tools for colorful CLI
pip install colorama pyfiglet termcolor tqdm

echo "[+] Ensure git & basics"
sudo apt update
sudo apt install -y git wget curl

# clone SecLists if not exists
SECLISTS_DIR="$HOME/Seclists/SecLists-master"
if [ ! -d "$SECLISTS_DIR" ]; then
  echo "[+] Cloning SecLists into $SECLISTS_DIR (this may take a while)..."
  git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$HOME/Seclists/SecLists-master"
else
  echo "[+] SecLists already present at $SECLISTS_DIR"
fi

# prepare local wordlist folder
WL_LOCAL="$HOME/Bug-Hunting/wordlist"
mkdir -p "$WL_LOCAL"

# copy some useful defaults if they exist
cp -n "$SECLISTS_DIR/Discovery/Web-Content/raft-large-directories.txt" "$WL_LOCAL/raft-large-directories.txt" 2>/dev/null || true
cp -n "$SECLISTS_DIR/Discovery/Web-Content/combined_directories.txt" "$WL_LOCAL/combined_directories.txt" 2>/dev/null || true
cp -n "$SECLISTS_DIR/Fuzzing/big-list-of-naughty-strings.txt" "$WL_LOCAL/big-list-of-naughty-strings.txt" 2>/dev/null || true
# copy XSS polyglots (if exist)
cp -n "$SECLISTS_DIR/Fuzzing/XSS/Polyglots/XSS-Polyglot-Ultimate-0xsobky.txt" "$WL_LOCAL/xss-polyglot-ultimate.txt" 2>/dev/null || true
cp -n "$SECLISTS_DIR/Fuzzing/XSS/human-friendly/XSS-payloadbox.txt" "$WL_LOCAL/xss-payloadbox.txt" 2>/dev/null || true

echo "[+] Wordlists copied (if available). Local wordlists at: $WL_LOCAL"
