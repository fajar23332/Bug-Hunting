#!/usr/bin/env bash
# install_public.sh
# Installer for public repo: installs Python venv, go tools, and offers to copy binaries to /usr/bin
# For Linux (Ubuntu/Debian tested). Use at your own risk. Confirm prompts.
set -euo pipefail

REPO_ROOT="$(pwd)"
VENV_DIR=".venv"
REQUIREMENTS_FILE="requirements.txt"
GO_BIN_DIR="${HOME}/go/bin"
WORDLIST_DIR="${HOME}/wordlist"   # user-local wordlists (assumed present)
TOOLS=(
  "subfinder" "httpx" "nuclei" "dnsx" "gau" "hakrawler" "waybackurls" "assetfinder" "ffuf" "dalfox" "gf"
)
GO_TOOLS=(
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
)

echo "=== Repo installer (public) ==="
echo "Working dir: ${REPO_ROOT}"
echo

# 0. Check wordlist folder (non-blocking)
if [ -d "${WORDLIST_DIR}" ]; then
  echo "[i] Found wordlist dir: ${WORDLIST_DIR}"
else
  echo "[!] NOTE: ${WORDLIST_DIR} not found. The runner will still work but wordlist-local features require files in ${WORDLIST_DIR}."
fi
echo

# 1. Python venv + requirements (optional)
if command -v python3 >/dev/null 2>&1; then
  echo "[*] Creating Python venv -> ${VENV_DIR}"
  python3 -m venv "${VENV_DIR}"
  # shellcheck disable=SC1091
  source "${VENV_DIR}/bin/activate"
  pip install --upgrade pip setuptools wheel
  if [ -f "${REQUIREMENTS_FILE}" ]; then
    echo "[*] Installing Python deps from ${REQUIREMENTS_FILE}"
    pip install -r "${REQUIREMENTS_FILE}"
  else
    echo "[i] ${REQUIREMENTS_FILE} not present — skipping pip installs."
  fi
else
  echo "[!] python3 not found — skipping Python venv step."
fi
echo

# 2. Ensure go installed (ask to apt-install on Debian/Ubuntu)
if ! command -v go >/dev/null 2>&1; then
  echo "[WARN] 'go' is not installed or not in PATH."
  if [ -f "/etc/debian_version" ]; then
    read -r -p "Install golang via apt (requires sudo)? [y/N]: " INSTALL_GO
    if [[ "${INSTALL_GO}" =~ ^[Yy]$ ]]; then
      sudo apt update
      sudo apt install -y golang-go
    else
      echo "[!] You can install go manually (https://go.dev/dl) — skipping go tool installation."
    fi
  else
    echo "[!] Non-debian system detected — please install Go >=1.20 manually and re-run script if you want Go tools."
  fi
fi

# 3. go install tools (if go present)
export PATH="${GO_BIN_DIR}:${PATH}"
mkdir -p "${GO_BIN_DIR}"
if command -v go >/dev/null 2>&1; then
  echo "[*] Installing go tools (~ a few minutes)"
  for mod in "${GO_TOOLS[@]}"; do
    echo "  -> go install ${mod}"
    if ! GO111MODULE=on go install -v "${mod}"; then
      echo "[WARN] go install failed for ${mod} — continue"
    fi
  done
else
  echo "[i] Skipping go installs (go not available)."
fi
echo

# 4. Post-install verification
echo "[*] Check installed binaries in ${GO_BIN_DIR} (if any):"
for b in "${TOOLS[@]}"; do
  if command -v "${b}" >/dev/null 2>&1; then
    printf "  OK: %-12s -> %s\n" "${b}" "$(command -v ${b})"
  else
    printf "  MISSING: %-12s\n" "${b}"
  fi
done
echo

# 5. Offer copy-to-/usr/bin (system-wide)
echo "--------------------------------------------"
echo "OPTION: Copy installed binaries from ${GO_BIN_DIR} to /usr/bin (system-wide)."
echo "This will require sudo and may overwrite existing system binaries."
echo "If you want a 'system' install (easier for global access), choose 'y' below."
read -r -p "Copy binaries to /usr/bin? [y/N]: " COPYSYS

if [[ "${COPYSYS}" =~ ^[Yy]$ ]]; then
  echo "[!] About to copy files from ${GO_BIN_DIR} to /usr/bin (sudo)."
  echo "List of files to copy (preview):"
  ls -1 "${GO_BIN_DIR}" || true
  read -r -p "Proceed to copy ALL files listed above into /usr/bin? This will require sudo and may overwrite existing files. [y/N]: " CONFIRM_CP
  if [[ "${CONFIRM_CP}" =~ ^[Yy]$ ]]; then
    for f in "${GO_BIN_DIR}"/*; do
      [ -f "$f" ] || continue
      fname="$(basename "$f")"
      echo "  sudo cp -v \"${f}\" /usr/bin/${fname}"
      sudo cp -v "${f}" "/usr/bin/${fname}" || echo "[WARN] failed to copy ${f}"
      sudo chmod 755 "/usr/bin/${fname}" || true
    done
    echo "[*] Done copying to /usr/bin."
  else
    echo "[i] Copy cancelled."
  fi
else
  echo "[i] Skipping copy to /usr/bin. You can always copy manually later."
fi

echo
echo "=== FINISH ==="
echo "Remember to add ${GO_BIN_DIR} to your PATH if you didn't copy binaries:"
echo "  echo 'export PATH=\"\$HOME/go/bin:\$PATH\"' >> ~/.bashrc && source ~/.bashrc"
echo
echo "If you want to make the repo public on GitHub, next steps are in README.md."
