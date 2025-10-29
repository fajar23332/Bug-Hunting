#!/usr/bin/env bash
# setup-auto.sh — smarter setup: detect installed tools, install if missing, update if present

run_sudo(){
  if [ "$EUID" -eq 0 ]; then
    "$@"
  else
    sudo "$@"
  fi
}

set -euo pipefail
IFS=$'\n\t'

ME="$(basename "$0")"
info(){ printf "\e[1;36m[%s]\e[0m %s\n" "$ME" "$*"; }
warn(){ printf "\e[1;33m[%s] WARN:\e[0m %s\n" "$ME" "$*" >&2; }
err(){ printf "\e[1;31m[%s] ERROR:\e[0m %s\n" "$ME" "$*" >&2; exit 1; }

# ---------- Config ----------
HOME="${HOME:-/root}"
GOBIN="${GOBIN:-$HOME/go/bin}"
GOPATH="${GOPATH:-$HOME/go}"
PATH_ADD_LINE='export PATH="/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin:$PATH"'
PY_PKGS=(colorama pyfiglet termcolor tqdm)
APT_PKGS=(git curl wget ca-certificates build-essential python3 python3-pip sqlmap unzip)
GO_TOOLS=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/lc/gau/v2/cmd/gau@latest"
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "github.com/hakluke/hakrawler@latest"
  "github.com/tomnomnom/assetfinder@latest"
  "github.com/ffuf/ffuf@latest"
  "github.com/hahwul/dalfox/v2@latest"
  "github.com/tomnomnom/gf@latest"
)

XRAY_VERSION="${XRAY_VERSION:-1.9.11}"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) XRAY_ASSET="xray_linux_amd64.zip" ;;
  aarch64|arm64) XRAY_ASSET="xray_linux_arm64.zip" ;;
  *) XRAY_ASSET="xray_linux_amd64.zip"; warn "unknown arch $ARCH: defaulting xray amd64";;
esac
XRAY_ZIP_URL="https://github.com/chaitin/xray/releases/download/${XRAY_VERSION}/${XRAY_ASSET}"
XRAY_INSTALL_DIR="${XRAY_INSTALL_DIR:-/opt/xray}"
XRAY_WRAPPER="/usr/local/bin/xray"

# ---------- helpers ----------
cmd_exists(){ command -v "$1" >/dev/null 2>&1; }
apt_installed(){ dpkg -s "$1" >/dev/null 2>&1 || return 1; }
ensure_dir(){ mkdir -p "$1"; }

require_sudo(){
  if [ "$EUID" -ne 0 ] && ! cmd_exists sudo; then
    err "This script requires sudo but 'sudo' is not available. Run as root or install sudo."
  fi
}

# ---------- 1) APT ----------
install_apt_pkgs(){
  info "Checking apt packages..."
  run_sudo apt update -y

  local to_install=()
  local to_upgrade=()
  for p in "${APT_PKGS[@]}"; do
    if apt_installed "$p"; then
      to_upgrade+=("$p")
    else
      to_install+=("$p")
    fi
  done

  if [ "${#to_install[@]}" -gt 0 ]; then
    info "Installing missing: ${to_install[*]}"
    run_sudo apt install -y "${to_install[@]}"
  else
    info "All apt packages already present."
  fi

  if [ "${#to_upgrade[@]}" -gt 0 ]; then
    info "Upgrading existing packages: ${to_upgrade[*]}"
    run_sudo apt install --only-upgrade -y "${to_upgrade[@]}" || true
  fi
}

# ---------- 2) PATH ----------
ensure_path_persist(){
  if ! grep -qxF "$PATH_ADD_LINE" "$HOME/.bashrc" 2>/dev/null; then
    echo "$PATH_ADD_LINE" >> "$HOME/.bashrc"
    info "Added go & pip user bin to ~/.bashrc"
  else
    info "PATH already configured"
  fi
  ensure_dir "$GOBIN"
  export PATH="/usr/local/go/bin:$GOBIN:$HOME/.local/bin:$PATH"
}

# ---------- 3) PYTHON ----------
ensure_pip_pkgs(){
  info "Checking Python packages..."
  for pkg in "${PY_PKGS[@]}"; do
    if python3 -c "import importlib, sys; sys.exit(0 if importlib.util.find_spec('$pkg') else 1)" >/dev/null 2>&1; then
      info "Updating $pkg"
      python3 -m pip install --user --upgrade "$pkg" || warn "Upgrade failed for $pkg"
    else
      info "Installing $pkg"
      python3 -m pip install --user "$pkg" || warn "Install failed for $pkg"
    fi
  done
  export PATH="$HOME/.local/bin:$PATH"
}

# ---------- 4) GO ----------
ensure_go_tools(){
  if ! cmd_exists go; then
    warn "'go' not found — skip Go installs."
    return
  fi
  info "Ensuring Go tools..."
  export GO111MODULE=on
  export GOBIN="$GOBIN"
  mkdir -p "$GOBIN"
  for pkg in "${GO_TOOLS[@]}"; do
    binname="$(basename "${pkg%%@*}")"
    BIN_PATH="$GOBIN/$binname"
    if [ -f "$BIN_PATH" ]; then
      info "Updating $binname"
      go install "$pkg" || warn "Update failed for $pkg"
    else
      info "Installing $binname"
      go install "$pkg" || warn "Install failed for $pkg"
    fi
  done
}

# ---------- 5) Deploy ----------
deploy_go_bins(){
  info "Deploying Go binaries..."
  TOOLS=("subfinder" "httpx" "gau" "nuclei" "dnsx" "hakrawler" "assetfinder" "ffuf" "dalfox" "gf")
  for bin in "${TOOLS[@]}"; do
    SRC="${GOBIN}/${bin}"
    DST="/usr/local/bin/${bin}"
    if [ -f "$SRC" ]; then
      if [ -f "$DST" ]; then
        if ! run_sudo cmp --silent "$SRC" "$DST"; then
          TS=$(date +%s)
          run_sudo mv "$DST" "${DST}.bak-${TS}" || true
          info "Backup $DST → ${DST}.bak-${TS}"
          run_sudo install -m 0755 "$SRC" "$DST"
          info "Updated $DST"
        else
          info "$DST already latest."
        fi
      else
        run_sudo install -m 0755 "$SRC" "$DST"
        info "Installed $DST"
      fi
    else
      warn "Missing binary $SRC"
    fi
  done
}

# ---------- 6) XRAY ----------
ensure_xray(){
  info "Checking XRAY..."
  TMPZIP="/tmp/${XRAY_ASSET}"
  run_sudo mkdir -p /tmp
  if wget -q -O "$TMPZIP" "$XRAY_ZIP_URL"; then
    info "Downloaded $XRAY_ASSET"
    TMPDIR="$(mktemp -d)"
    unzip -q "$TMPZIP" -d "$TMPDIR"
    run_sudo mkdir -p "$XRAY_INSTALL_DIR"
    run_sudo cp -r "$TMPDIR"/* "$XRAY_INSTALL_DIR"/
    if [ -f "${XRAY_INSTALL_DIR}/xray_linux_amd64" ]; then
      run_sudo mv "${XRAY_INSTALL_DIR}/xray_linux_amd64" "${XRAY_INSTALL_DIR}/xray" || true
    fi
    run_sudo tee "$XRAY_WRAPPER" >/dev/null <<'EOF'
#!/bin/bash
cd /opt/xray || { echo "[xray] /opt/xray not found."; exit 1; }
exec ./xray "$@"
EOF
    run_sudo chmod +x "$XRAY_WRAPPER"
    rm -rf "$TMPDIR" "$TMPZIP"
    info "xray ready at ${XRAY_INSTALL_DIR}"
  else
    warn "Failed to download xray from $XRAY_ZIP_URL"
  fi
}

# ---------- 7) SECLISTS ----------
fetch_seclists_subset(){
  SECLISTS_DIR="${SECLISTS_DIR:-$HOME/Seclists/SecLists-master}"
  info "Fetching SecLists subset..."
  ensure_dir "$SECLISTS_DIR"
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

  if cmd_exists git; then
    if [ ! -d "$SECLISTS_DIR/.git" ]; then
      git clone --depth 1 --no-checkout https://github.com/danielmiessler/SecLists.git "$SECLISTS_DIR" || warn "git clone failed"
    fi
    if [ -d "$SECLISTS_DIR/.git" ]; then
      cd "$SECLISTS_DIR"
      git sparse-checkout init --cone >/dev/null 2>&1 || true
      readarray -t _paths <<< "$SECLISTS_PATHS"
      git sparse-checkout set "${_paths[@]}" >/dev/null 2>&1 || true
      git checkout --quiet || true
      info "SecLists sparse-checkout applied."
      return
    fi
  fi

  info "Git not available — downloading raw files..."
  local downloaded=0
  for p in $(echo "$SECLISTS_PATHS"); do
    out="$SECLISTS_DIR/$p"
    mkdir -p "$(dirname "$out")"
    for BR in main master; do
      url="https://raw.githubusercontent.com/danielmiessler/SecLists/$BR/$p"
      if curl -sSfL "$url" -o "$out"; then
        downloaded=$((downloaded+1))
        break
      fi
    done
  done
  info "Downloaded $downloaded files into $SECLISTS_DIR"
}

# ---------- main ----------
main(){
  require_sudo
  install_apt_pkgs
  ensure_path_persist
  ensure_pip_pkgs
  ensure_go_tools
  deploy_go_bins
  ensure_xray
  fetch_seclists_subset
  info "✅ All done. Reload shell (source ~/.bashrc) if needed."
}

main "$@"
