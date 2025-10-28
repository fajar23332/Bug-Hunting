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

# --------- [1/9] Update & essentials ----------
echo "[1/9] apt update & install basics (git, curl, build tools, python, sqlmap)"
sudo apt update -y
sudo apt install -y git curl wget ca-certificates build-essential python3 python3-pip sqlmap

# prepare GOBIN/GOPATH + PATH for current shell run
mkdir -p "$GOBIN"
export GOPATH="$GOPATH"
export PATH="/usr/local/go/bin:$GOBIN:$HOME/.local/bin:$PATH"

# persist PATH to .bashrc for future shells
if ! grep -qxF "$PATH_ADD_LINE" "$HOME/.bashrc" 2>/dev/null; then
  echo "$PATH_ADD_LINE" >> "$HOME/.bashrc"
  echo "[i] Added go & pip user bin to ~/.bashrc (reload shell later to persist)"
fi

# --------- [2/9] Go-based tools (install/update) ----------
echo "[2/9] Installing/updating Go tools to $GOBIN"
export GO111MODULE=on

if ! command -v go >/dev/null 2>&1; then
  echo "[!] 'go' not found in PATH. Skipping Go tool install."
  echo "[!] Install Go first (lihat README), lalu jalankan ulang ./setup.sh"
else
  echo "[i] go detected: $(go version)"
  echo "[i] Installing/updating recon tools..."
  # wrap each with || true biar gak nge-crash semuanya kalau satu gagal
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

echo "[i] Go tools install attempt finished."
echo

# --------- [2.5/9] Install gf patterns (xss/sqli/lfi/etc) ----------
echo "[2.5/9] Setting up gf patterns (~/.gf)"

GF_DIR="$HOME/.gf"
TOOLS_TMP="$HOME/.hunt-tmp-tools"
GF_REPO_DIR="$TOOLS_TMP/gf"

mkdir -p "$GF_DIR"
mkdir -p "$TOOLS_TMP"

# clone the gf repo just to grab the pattern jsons
if [ -d "$GF_REPO_DIR" ]; then
  rm -rf "$GF_REPO_DIR"
fi

git clone --depth 1 https://github.com/tomnomnom/gf.git "$GF_REPO_DIR" 2>/dev/null || true

# copy example patterns if available
if [ -d "$GF_REPO_DIR/examples" ]; then
  cp -v "$GF_REPO_DIR/examples/"*.json "$GF_DIR"/ 2>/dev/null || true
  echo "[i] Copied gf patterns into $GF_DIR:"
  ls "$GF_DIR" || true
else
  echo "[w] Couldn't find gf/examples patterns. gf patterns may be missing."
fi

# optional cleanup tmp clone
rm -rf "$TOOLS_TMP" 2>/dev/null || true

# --------- [3/9] Python deps for hunt.py UI ----------
echo "[3/9] Installing Python dependencies for hunt.py UI (colorama, pyfiglet, termcolor, tqdm)"
python3 -m pip install --user --upgrade pip
python3 -m pip install --user colorama pyfiglet termcolor tqdm

# ensure ~/.local/bin in PATH for this run (already exported above, but re-assert)
export PATH="$HOME/.local/bin:$PATH"

# --------- [4/9] Fetch SecLists subset ----------
echo "[4/9] Fetch SecLists subset (sparse-checkout preferred)"
mkdir -p "$(dirname "$SECLISTS_DIR")"

# Which SecLists paths we actually want
read -r -d '' SECLISTS_PATHS <<'PATHS' || true
Discovery/Web-Content/raft-large-directories.txt
Discovery/Web-Content/raft-medium-directories.txt
Discovery/Web-Content/combined_directories.txt
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
    echo "[w] shallow clone with --no-checkout failed; falling back to raw download mode"
    SPARSE_OK=0
  }
  if command -v git >/dev/null 2>&1 && [ -d "$SECLISTS_DIR/.git" ]; then
    cd "$SECLISTS_DIR"
    git sparse-checkout init --cone >/dev/null 2>&1 || true
    readarray -t _paths <<< "$SECLISTS_PATHS"
    git sparse-checkout set "${_paths[@]}" >/dev/null 2>&1 || true
    git checkout --quiet || true
    SPARSE_OK=1
    echo "[i] Sparse-checkout applied."
  else
    SPARSE_OK=0
  fi
else
  echo "[i] SecLists repo skeleton exists at $SECLISTS_DIR — updating subset"
  cd "$SECLISTS_DIR"
  git sparse-checkout init --cone >/dev/null 2>&1 || true
  readarray -t _paths <<< "$SECLISTS_PATHS"
  git sparse-checkout set "${_paths[@]}" >/dev/null 2>&1 || true
  git pull --ff-only || true
  SPARSE_OK=1
fi

if [ "${SPARSE_OK:-0}" -ne 1 ]; then
  echo "[!] Sparse-checkout not available. Falling back to raw per-file download."
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

# --------- [5/9] Prepare local wordlist folder ----------
echo "[5/9] Prepare local wordlist folder: $WL_LOCAL"
mkdir -p "$WL_LOCAL"

cp -n "$SECLISTS_DIR/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt"        "$WL_LOCAL/lfi.txt"                      2>/dev/null || true
cp -n "$SECLISTS_DIR/Fuzzing/Databases/SQLi/Generic-SQLi.txt"        "$WL_LOCAL/sqli.txt"                     2>/dev/null || true
cp -n "$SECLISTS_DIR/Discovery/Web-Content/raft-large-directories.txt"   "$WL_LOCAL/raft-large-directories.txt"    2>/dev/null || true
cp -n "$SECLISTS_DIR/Discovery/Web-Content/raft-medium-directories.txt"  "$WL_LOCAL/raft-medium-directories.txt"   2>/dev/null || true
cp -n "$SECLISTS_DIR/Discovery/Web-Content/combined_directories.txt"     "$WL_LOCAL/combined_directories.txt"      2>/dev/null || true
cp -n "$SECLISTS_DIR/Discovery/Web-Content/web-extensions.txt"      "$WL_LOCAL/web-extensions.txt"           2>/dev/null || true
cp -n "$SECLISTS_DIR/Discovery/Web-Content/api/api-endpoints.txt"   "$WL_LOCAL/api-endpoints.txt"            2>/dev/null || true
cp -n "$SECLISTS_DIR/Fuzzing/big-list-of-naughty-strings.txt"       "$WL_LOCAL/big-list-of-naughty-strings.txt" 2>/dev/null || true
cp -n "$SECLISTS_DIR/Fuzzing/XSS/Polyglots/XSS-Polyglot-Ultimate-0xsobky.txt" "$WL_LOCAL/xss-polyglot-ultimate.txt" 2>/dev/null || true
cp -n "$SECLISTS_DIR/Fuzzing/XSS/human-friendly/XSS-payloadbox.txt" "$WL_LOCAL/xss-payloadbox.txt"           2>/dev/null || true

echo "[i] Copied starter wordlists to $WL_LOCAL"

# --------- [6/9] Optional install hunt.py globally ----------
echo "[6/9] Optional: install hunt.py to /usr/local/bin for global use"
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
  echo "[i] hunt.py not found in current dir; skipping"
fi

# --------- [7/9] Deploy Go binaries globally (/usr/local/bin) ----------
echo "[7/9] Deploying recon tools to /usr/local/bin so they work everywhere"

TOOLS=("subfinder" "httpx" "gau" "nuclei" "dnsx" "hakrawler" "assetfinder" "ffuf" "dalfox" "gf")

for bin in "${TOOLS[@]}"; do
  SRC_BIN="${GOBIN}/${bin}"
  DST_BIN="/usr/local/bin/${bin}"

  if [ -f "$SRC_BIN" ]; then
    # backup old if exists
    if [ -f "$DST_BIN" ]; then
      TS=$(date +%s)
      sudo cp "$DST_BIN" "${DST_BIN}.bak-${TS}" || true
      echo "[i] Backup existing ${DST_BIN} -> ${DST_BIN}.bak-${TS}"
    fi
    echo "[i] Installing $bin -> /usr/local/bin/$bin"
    sudo cp "$SRC_BIN" "$DST_BIN"
    sudo chmod 755 "$DST_BIN"
  else
    echo "[w] $bin not found in $SRC_BIN (maybe Go install failed / Go missing)"
  fi
done

# --------- [8/9] Quick verification ----------
echo
echo "[8/9] Quick verification (binaries in PATH now?)"
which subfinder  || echo "WARN: subfinder not in PATH"
which httpx      || echo "WARN: httpx not in PATH"
which gau        || echo "WARN: gau not in PATH"
which nuclei     || echo "WARN: nuclei not in PATH"
which hakrawler  || echo "WARN: hakrawler not in PATH"
which ffuf       || echo "WARN: ffuf not in PATH"
which dalfox     || echo "WARN: dalfox not in PATH"
which gf         || echo "WARN: gf not in PATH"
which sqlmap     || echo "WARN: sqlmap not in PATH"

# --------- [9/9] Outro ----------
echo
echo "[9/9] Setup complete ✅"
echo " - SecLists         : $SECLISTS_DIR"
echo " - Local wordlists  : $WL_LOCAL"
echo " - Go bin (GOBIN)   : $GOBIN"
echo
echo "You can now run: 'hunt' (if you installed it) or 'python3 hunt.py'"
echo
echo "Full-power recon output dir:"
echo "  ~/bug-hunting/fullpower/<target>/fullpower.json"
echo
echo "Attack-focus output dir:"
echo "  ~/bug-hunting/<bugtype>/<target>/result.json"
echo
echo "[i] If some tool says 'command not found', re-check Go install or rerun setup after installing Go."
echo
exit 0
