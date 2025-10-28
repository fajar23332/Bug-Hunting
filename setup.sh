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
PATH_ADD_LINE='export PATH="$HOME/go/bin:$HOME/.local/bin:$PATH"'

# --------- Update & essentials ----------
echo "[1/8] apt update & install basics (git, curl, build tools, python, go)"
sudo apt update -y
sudo apt install -y git curl wget ca-certificates build-essential python3 python3-pip golang-go

# Ensure GOBIN/GOPATH exist and present in PATH for this run
mkdir -p "$GOBIN"
export GOPATH="$GOPATH"
export PATH="$GOBIN:$HOME/.local/bin:$PATH"

# persist PATH to .bashrc if missing
if ! grep -qxF "$PATH_ADD_LINE" "$HOME/.bashrc" 2>/dev/null; then
  echo "$PATH_ADD_LINE" >> "$HOME/.bashrc"
  echo "[i] Added go & pip user bin to ~/.bashrc (reload shell to persist)"
fi

# --------- Go-based tools (install/update) ----------
echo "[2/8] Installing/updating Go tools to $GOBIN"
export GO111MODULE=on

# ensure go binary exists
if ! command -v go >/dev/null 2>&1; then
  echo "[!] go not found in PATH after apt install. Aborting go tool install."
else
  echo "[i] Installing/updating common Go tools"
  # wrap installs with || true to avoid entirely failing on single-tool errors
  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest || true
  go install github.com/lc/gau/v2/cmd/gau@latest || true
  go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest || true
  go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest || true
  go install github.com/hakluke/hakrawler@latest || true
  go install github.com/tomnomnom/assetfinder@latest || true
  go install github.com/ffuf/ffuf@latest || true
  go install github.com/hahwul/dalfox/v2@latest || true
fi

echo "[i] Go tools attempt finished. Make sure $GOBIN is in PATH (source ~/.bashrc)."
echo

# --------- Python deps for hunt.py UI ----------
echo "[3/8] Installing Python dependencies for hunt.py UI (colorama, pyfiglet, termcolor, tqdm)"
python3 -m pip install --user --upgrade pip
python3 -m pip install --user colorama pyfiglet termcolor tqdm

# ensure ~/.local/bin in PATH for pip user installs (already added above)
export PATH="$HOME/.local/bin:$PATH"

# --------- Clone SecLists ----------
echo "[4/8] Clone SecLists (shallow clone to save time)"
if [ ! -d "$SECLISTS_DIR" ]; then
  mkdir -p "$(dirname "$SECLISTS_DIR")"
  git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$SECLISTS_DIR"
  echo "[i] SecLists cloned to: $SECLISTS_DIR"
else
  echo "[i] SecLists already exists at $SECLISTS_DIR — attempting shallow pull"
  git -C "$SECLISTS_DIR" pull --ff-only || true
fi

# --------- Prepare local wordlist folder & copy defaults ----------
echo "[5/8] Prepare local wordlist folder: $WL_LOCAL"
mkdir -p "$WL_LOCAL"

# copy recommended lists (no overwrite)
cp -n "$SECLISTS_DIR/Discovery/Web-Content/raft-large-directories.txt" "$WL_LOCAL/raft-large-directories.txt" 2>/dev/null || true
cp -n "$SECLISTS_DIR/Discovery/Web-Content/raft-medium-directories.txt" "$WL_LOCAL/raft-medium-directories.txt" 2>/dev/null || true
cp -n "$SECLISTS_DIR/Discovery/Web-Content/combined_directories.txt" "$WL_LOCAL/combined_directories.txt" 2>/dev/null || true
cp -n "$SECLISTS_DIR/Fuzzing/big-list-of-naughty-strings.txt" "$WL_LOCAL/big-list-of-naughty-strings.txt" 2>/dev/null || true
cp -n "$SECLISTS_DIR/Fuzzing/XSS/Polyglots/XSS-Polyglot-Ultimate-0xsobky.txt" "$WL_LOCAL/xss-polyglot-ultimate.txt" 2>/dev/null || true
cp -n "$SECLISTS_DIR/Fuzzing/XSS/human-friendly/XSS-payloadbox.txt" "$WL_LOCAL/xss-payloadbox.txt" 2>/dev/null || true
cp -n "$SECLISTS_DIR/Discovery/Web-Content/web-extensions.txt" "$WL_LOCAL/web-extensions.txt" 2>/dev/null || true

echo "[i] Copied starter wordlists to $WL_LOCAL (if present in SecLists)"

# --------- Optional: copy hunt.py to /usr/local/bin (ask) ----------
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

# --------- Final messages & verification ----------
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
