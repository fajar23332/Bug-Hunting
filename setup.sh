#!/usr/bin/env bash
set -euo pipefail

ME="$(basename "$0")"
echo
echo "=== $ME — Hunt Toolkit setup (clone SecLists + tools + python deps) ==="
echo

# --------- Config ----------
SECLISTS_DIR="$HOME/Seclists/SecLists-master"
WL_LOCAL="$HOME/Bug-Hunting/wordlist"
GOBIN="${GOBIN:-$HOME/go/bin}"
GOPATH="${GOPATH:-$HOME/go}"
PATH_ADD_LINE='export PATH="/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin:$PATH"'

# --------- Update & essentials ----------
echo "[1/8] apt update & install basics (git, curl, build tools, python)"
sudo apt update -y
sudo apt install -y sqlmap
sudo apt install -y git curl wget ca-certificates build-essential python3 python3-pip

# Ensure GOBIN/GOPATH exist and present in PATH for this run
mkdir -p "$GOBIN"
export GOPATH="$GOPATH"
export PATH="/usr/local/go/bin:$GOBIN:$HOME/.local/bin:$PATH"

# persist PATH to .bashrc if missing
if ! grep -qxF "$PATH_ADD_LINE" "$HOME/.bashrc" 2>/dev/null; then
  echo "$PATH_ADD_LINE" >> "$HOME/.bashrc"
  echo "[i] Added go & pip user bin to ~/.bashrc (reload shell to persist)"
fi

# --------- Go-based tools (install/update) ----------
echo "[2/8] Installing/updating Go tools to $GOBIN"
export GO111MODULE=on

if ! command -v go >/dev/null 2>&1; then
  echo "[!] 'go' not found in PATH."
  echo "[!] Skipping install of recon tools (subfinder/httpx/nuclei/etc)."
  echo "[!] Install Go first (lihat README), lalu jalankan ulang ./setup.sh"
else
  echo "[i] go detected: $(go version)"
  echo "[i] Installing/updating common Go tools"
  # wrap installs with || true to avoid entirely failing on single-tool errors
  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest || true
  go install github.com/lc/gau/v2/cmd/gau@latest || true
  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || true
  go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest || true
  go install github.com/hakluke/hakrawler@latest || true
  go install github.com/tomnomnom/assetfinder@latest || true
  go install github.com/ffuf/ffuf@latest || true
  go install github.com/hahwul/dalfox/v2@latest || true
  go install github.com/tomnomnom/gf@latest || true
fi

echo "[i] Go tools attempt finished. Make sure $GOBIN is in PATH (source ~/.bashrc)."
echo

# --------- Python deps for hunt.py UI ----------
echo "[3/8] Installing Python dependencies for hunt.py UI (colorama, pyfiglet, termcolor, tqdm)"
python3 -m pip install --user --upgrade pip
python3 -m pip install --user colorama pyfiglet termcolor tqdm

# ensure ~/.local/bin in PATH for pip user installs (already added above)
export PATH="$HOME/.local/bin:$PATH"

echo "[4/8] Fetch SecLists subset (sparse-checkout preferred)"
mkdir -p "$(dirname "$SECLISTS_DIR")"

read -r -d '' SECLISTS_PATHS <<'PATHS' || true
Discovery/Web-Content/raft-large-directories.txt
Discovery/Web-Content/raft-medium-directories.txt
Discovery/Web-Content/combined-directories.txt
Discovery/Web-Content/web-extensions.txt
Discovery/Web-Content/api/api-endpoints.txt
Fuzzing/big-list-of-naughty-strings.txt
Fuzzing/XSS/Polyglots/XSS-Polyglot-Ultimate-0xsobky.txt
Fuzzing/XSS/human-friendly/XSS-payloadbox.txt
Fuzzing/Databases/SQLi/Generic-SQLi.txt
Fuzzing/LFI/LFI-LFISuite-pathtotest.txt
PATHS

if [ ! -d "$SECLISTS_DIR/.git" ]; then
  echo "[i] Initializing sparse clone of SecLists into $SECLISTS_DIR"
  git clone --depth 1 --no-checkout https://github.com/danielmiessler/SecLists.git "$SECLISTS_DIR" || {
    echo "[w] shallow clone with --no-checkout failed; falling back to per-file downloads"
    SPARSE_OK=0
  }
  if command -v git >/dev/null 2>&1 && [ -d "$SECLISTS_DIR/.git" ]; then
    cd "$SECLISTS_DIR"
    git sparse-checkout init --cone >/dev/null 2>&1 || true
    readarray -t _paths <<< "$SECLISTS_PATHS"
    git sparse-checkout set "${_paths[@]}" >/dev/null 2>&1 || true
    git checkout --quiet || true
    SPARSE_OK=1
    echo "[i] Sparse-checkout applied. Selected paths should be available under $SECLISTS_DIR"
  else
    SPARSE_OK=0
  fi
else
  echo "[i] SecLists repo skeleton exists at $SECLISTS_DIR — attempting to update subset"
  cd "$SECLISTS_DIR"
  git sparse-checkout init --cone >/dev/null 2>&1 || true
  readarray -t _paths <<< "$SECLISTS_PATHS"
  git sparse-checkout set "${_paths[@]}" >/dev/null 2>&1 || true
  git pull --ff-only || true
  SPARSE_OK=1
fi

if [ "${SPARSE_OK:-0}" -ne 1 ]; then
  echo "[!] sparse-checkout failed or not supported. Falling back to per-file raw download."
  mkdir -p "$SECLISTS_DIR"
  REPO_USER="danielmiessler"
  REPO_NAME="SecLists"
  BRANCH="master"
  readarray -t _paths <<< "$SECLISTS_PATHS"
  for p in "${_paths[@]}"; do
    out="$SECLISTS_DIR/$p"
    outdir="$(dirname "$out")"
    mkdir -p "$outdir"
    url="https://raw.githubusercontent.com/${REPO_USER}/${REPO_NAME}/${BRANCH}/${p}"
    echo "[i] Downloading $p"
    if curl -sSfL "$url" -o "$out"; then
      echo "    saved: $out"
    else
      echo "    warn: failed to download $p (skipping)"
      rm -f "$out"
    fi
  done
fi

echo "[5/8] Prepare local wordlist folder: $WL_LOCAL"
mkdir -p "$WL_LOCAL"

cp -n "$SECLISTS_DIR/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt" "$WL_LOCAL/lfi.txt" 2>/dev/null || true
cp -n "$SECLISTS_DIR/Fuzzing/Databases/SQLi/Generic-SQLi.txt" "$WL_LOCAL/sqli.txt" 2>/dev/null || true

cp -n "$SECLISTS_DIR/Discovery/Web-Content/raft-large-directories.txt" "$WL_LOCAL/raft-large-directories.txt" 2>/dev/null || true
cp -n "$SECLISTS_DIR/Discovery/Web-Content/raft-medium-directories.txt" "$WL_LOCAL/raft-medium-directories.txt" 2>/dev/null || true
cp -n "$SECLISTS_DIR/Discovery/Web-Content/combined_directories.txt" "$WL_LOCAL/combined_directories.txt" 2>/dev/null || true
cp -n "$SECLISTS_DIR/Discovery/Web-Content/web-extensions.txt" "$WL_LOCAL/web-extensions.txt" 2>/dev/null || true
cp -n "$SECLISTS_DIR/Discovery/Web-Content/api/api-endpoints.txt" "$WL_LOCAL/api-endpoints.txt" 2>/dev/null || true

cp -n "$SECLISTS_DIR/Fuzzing/big-list-of-naughty-strings.txt" "$WL_LOCAL/big-list-of-naughty-strings.txt" 2>/dev/null || true
cp -n "$SECLISTS_DIR/Fuzzing/XSS/Polyglots/XSS-Polyglot-Ultimate-0xsobky.txt" "$WL_LOCAL/xss-polyglot-ultimate.txt" 2>/dev/null || true
cp -n "$SECLISTS_DIR/Fuzzing/XSS/human-friendly/XSS-payloadbox.txt" "$WL_LOCAL/xss-payloadbox.txt" 2>/dev/null || true

echo "[i] Copied starter wordlists to $WL_LOCAL (if present in SecLists)"

echo "[6/8] Optional: install hunt.py to /usr/local/bin for global use"
if [ -f "./hunt.py" ]; then
  read -r -p "Copy local ./hunt.py to /usr/local/bin/hunt and make executable? [y/N] " install_hunt || install_hunt="n"
  if [[ "${install_hunt,,}" == "y" ]]; then
    sudo cp -f ./hunt.py /usr/local/bin/hunt
    sudo chmod +x /usr/local/bin/hunt
    echo "[i] hunt installed to /usr/local/bin/hunt"
  else
    echo "[i] Skipping global install of hunt.py"
  fi
else
  echo "[i] hunt.py not found in current dir; skip global install"
fi

echo
echo "[7/8] Quick verification (binaries in PATH?)"
which subfinder || echo "WARN: subfinder not found in PATH"
which httpx || echo "WARN: httpx not found in PATH"
which gau || echo "WARN: gau not found in PATH"
which nuclei || echo "WARN: nuclei not found in PATH"
which hakrawler || echo "WARN: hakrawler not found in PATH"
which ffuf || echo "WARN: ffuf not found in PATH"
which dalfox || echo "WARN: dalfox not found in PATH"

echo
echo "[8/8] Setup complete ✅"
echo " - SecLists: $SECLISTS_DIR"
echo " - Local wordlists: $WL_LOCAL"
echo " - Go bin (GOBIN): $GOBIN"
echo
echo "NOTE: Please 'source ~/.bashrc' or open a new shell to apply PATH changes (go & pip user bin)."
echo "Run: python3 hunt.py  (or 'hunt' if you installed to /usr/local/bin)"
echo
echo "Quick checks:"
echo "  which subfinder  -> $(command -v subfinder || echo 'missing')"
echo "  which httpx      -> $(command -v httpx || echo 'missing')"
echo "  which nuclei     -> $(command -v nuclei || echo 'missing')"
echo "  which ffuf       -> $(command -v ffuf || echo 'missing')"
echo "  wordlists at     -> $WL_LOCAL"
echo
echo "[i] Script finished successfully."
exit 0
