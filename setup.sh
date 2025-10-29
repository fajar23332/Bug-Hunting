#!/usr/bin/env bash
# setup-auto.sh — smarter setup: detect installed tools, install if missing, update if present
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

# ---------- 1) APT packages: install if missing, otherwise upgrade ---------- 
install_apt_pkgs(){
  info "Checking apt packages..."
  sudo apt update -y

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
    info "Installing missing apt packages: ${to_install[*]}"
    sudo apt install -y "${to_install[@]}"
  else
    info "No missing apt packages."
  fi

  if [ "${#to_upgrade[@]}" -gt 0 ]; then
    info "Attempting to upgrade apt packages (only-upgrade): ${to_upgrade[*]}"
    # apt supports --only-upgrade but fallback to normal install if not supported
    sudo apt install --only-upgrade -y "${to_upgrade[@]}" || true
  fi
}

# ---------- 2) Ensure PATH persistence for go/pip user bin ----------
ensure_path_persist(){
  if ! grep -qxF "$PATH_ADD_LINE" "$HOME/.bashrc" 2>/dev/null; then
    echo "$PATH_ADD_LINE" >> "$HOME/.bashrc"
    info "Added go & pip user bin to ~/.bashrc (reload shell later)"
  else
    info "PATH already present in ~/.bashrc"
  fi
  ensure_dir "$GOBIN"
  export PATH="/usr/local/go/bin:$GOBIN:$HOME/.local/bin:$PATH"
}

# ---------- 3) Python user packages (pip) ----------
ensure_pip_pkgs(){
  info "Checking Python user packages..."
  for pkg in "${PY_PKGS[@]}"; do
    if python3 -c "import importlib, sys; sys.exit(0 if importlib.util.find_spec('$pkg') else 1)" >/dev/null 2>&1; then
      info "Python package '$pkg' present — upgrading to latest"
      python3 -m pip install --user --upgrade "$pkg" || warn "pip upgrade failed for $pkg"
    else
      info "Installing python package '$pkg'"
      python3 -m pip install --user "$pkg" || warn "pip install failed for $pkg"
    fi
  done
  export PATH="$HOME/.local/bin:$PATH"
}

# ---------- 4) Go tools: install if missing, update if exists ----------
ensure_go_tools(){
  if ! cmd_exists go; then
    warn "'go' not in PATH. Skipping go tool installs. Install Go and re-run this script."
    return
  fi
  info "Ensuring Go tools (install if missing, update if present)..."
  export GO111MODULE=on
  export GOBIN="$GOBIN"
  mkdir -p "$GOBIN"
  for pkg in "${GO_TOOLS[@]}"; do
    # derive binary name from package path (best-effort)
    binname="$(basename "${pkg%%@*}")"
    BIN_PATH="$GOBIN/$binname"
    if [ -f "$BIN_PATH" ]; then
      info "Found $binname at $BIN_PATH → updating via go install $pkg"
      go install "$pkg" || warn "go install (update) failed for $pkg"
    else
      info "$binname not found → installing via go install $pkg"
      go install "$pkg" || warn "go install failed for $pkg"
    fi
  done
}

# ---------- 5) Deploy Go binaries to /usr/local/bin (only copy if missing or different) ----------
deploy_go_bins(){
  info "Deploying go binaries to /usr/local/bin (backup existing before replace)"
  TOOLS=("subfinder" "httpx" "gau" "nuclei" "dnsx" "hakrawler" "assetfinder" "ffuf" "dalfox" "gf")
  for bin in "${TOOLS[@]}"; do
    SRC_BIN="${GOBIN}/${bin}"
    DST_BIN="/usr/local/bin/${bin}"
    if [ -f "$SRC_BIN" ]; then
      if [ -f "$DST_BIN" ]; then
        # check checksum to avoid redundant copy
        if ! sudo cmp --silent "$SRC_BIN" "$DST_BIN"; then
          TS=$(date +%s)
          sudo mv "$DST_BIN" "${DST_BIN}.bak-${TS}" || true
          info "Backing up $DST_BIN -> ${DST_BIN}.bak-${TS}"
          sudo install -m 0755 "$SRC_BIN" "$DST_BIN"
          info "Updated $DST_BIN"
        else
          info "$DST_BIN is up-to-date — skipping"
        fi
      else
        sudo install -m 0755 "$SRC_BIN" "$DST_BIN"
        info "Installed $DST_BIN"
      fi
    else
      warn "Source $SRC_BIN not found (skip deploy)."
    fi
  done
}

# ---------- 6) Xray install/update (archive-based) ----------
ensure_xray(){
  info "Checking xray installation..."
  if [ -x "$XRAY_WRAPPER" ] || [ -x "${XRAY_INSTALL_DIR}/xray" ]; then
    info "xray present — will attempt to update by fetching latest release ${XRAY_VERSION}"
  else
    info "xray not present — will install ${XRAY_VERSION}"
  fi

  TMPZIP="/tmp/${XRAY_ASSET}"
  mkdir -p /tmp
  if wget -q -O "$TMPZIP" "$XRAY_ZIP_URL"; then
    info "Downloaded xray asset $TMPZIP"
    TMPDIR="$(mktemp -d)"
    unzip -q "$TMPZIP" -d "$TMPDIR"
    sudo mkdir -p "${XRAY_INSTALL_DIR}"
    sudo cp -r "${TMPDIR}/"* "${XRAY_INSTALL_DIR}/"
    # rename binary if necessary
    if [ -f "${XRAY_INSTALL_DIR}/xray_linux_amd64" ]; then
      sudo mv -f "${XRAY_INSTALL_DIR}/xray_linux_amd64" "${XRAY_INSTALL_DIR}/xray" || true
    fi
    sudo chown -R root:root "${XRAY_INSTALL_DIR}"
    sudo chmod -R 755 "${XRAY_INSTALL_DIR}"
    # wrapper
    sudo tee "$XRAY_WRAPPER" >/dev/null <<'EOF'
#!/bin/bash
cd /opt/xray || { echo "[xray] /opt/xray not found."; exit 1; }
exec ./xray "$@"
EOF
    sudo chmod +x "$XRAY_WRAPPER"
    rm -rf "$TMPDIR" "$TMPZIP"
    info "xray installed/updated at ${XRAY_INSTALL_DIR} (wrapper: $XRAY_WRAPPER)"
  else
    warn "Failed to download xray from $XRAY_ZIP_URL"
  fi
}

# ---------- 7) SecLists subset (sparse or raw) ----------
fetch_seclists_subset(){
  SECLISTS_DIR="${SECLISTS_DIR:-$HOME/Seclists/SecLists-master}"
  info "Fetching SecLists subset into $SECLISTS_DIR (sparse preferred)"
  TOOLS_TMP="${TOOLS_TMP:-$HOME/.hunt-tmp-tools}"
  ensure_dir "$TOOLS_TMP"
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
      git clone --depth 1 --no-checkout https://github.com/danielmiessler/SecLists.git "$SECLISTS_DIR" || warn "git clone SecLists failed"
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

  # fallback per-file raw download
  mkdir -p "$SECLISTS_DIR"
  REPO_USER="danielmiessler"
  REPO_NAME="SecLists"
  BRANCHES_TO_TRY=("main" "master")
  for BR in "${BRANCHES_TO_TRY[@]}"; do
    for p in $(echo "$SECLISTS_PATHS"); do
      out="$SECLISTS_DIR/$p"
      outdir="$(dirname "$out")"
      mkdir -p "$outdir"
      url="https://raw.githubusercontent.com/${REPO_USER}/${REPO_NAME}/${BR}/${p}"
      info "Downloading $p from $BR"
      if curl -sSfL "$url" -o "$out"; then
        info "saved: $out"
      else
        warn "failed to download $p from $BR"
        rm -f "$out"
      fi
    done
    # stop after successful branch attempt
    if find "$SECLISTS_DIR" -type f | read; then break; fi
  done
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

  info "All done. Reload shell (source ~/.bashrc) if needed."
}

main "$@"
