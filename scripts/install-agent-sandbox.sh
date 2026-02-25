#!/usr/bin/env bash
set -euo pipefail

# Agent Sandbox CLI Stack Installer
# Installs all CLI tools for agentic daily workflow management.
# Targets: macOS (Homebrew) — Apple Silicon & Intel

TOOLS_BREW=(himalaya task khard vdirsyncer zk jrnl uv)
TOOLS_GO=(github.com/mrusme/caldr)
UV_PYTHON_VERSION="3.13"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

info()  { printf "${BOLD}[+]${NC} %s\n" "$1"; }
ok()    { printf "${GREEN}[ok]${NC} %s\n" "$1"; }
warn()  { printf "${YELLOW}[!]${NC} %s\n" "$1"; }
fail()  { printf "${RED}[x]${NC} %s\n" "$1"; }

check_command() { command -v "$1" >/dev/null 2>&1; }

# ── Preflight ──

if [[ "$(uname -s)" != "Darwin" ]]; then
  fail "This installer targets macOS only."
  exit 1
fi

if ! check_command brew; then
  info "Homebrew not found. Installing..."
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  if [[ -f /opt/homebrew/bin/brew ]]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
  elif [[ -f /usr/local/bin/brew ]]; then
    eval "$(/usr/local/bin/brew shellenv)"
  fi
fi

# ── Rust ──

if check_command rustc; then
  ok "Rust already installed ($(rustc --version))"
else
  info "Installing Rust via rustup..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
  . "$HOME/.cargo/env"
  ok "Rust installed ($(rustc --version))"
fi

# Source cargo env for the rest of the script
if [[ -f "$HOME/.cargo/env" ]]; then
  . "$HOME/.cargo/env"
fi

# ── Brew tools ──

info "Installing CLI tools via Homebrew..."
FAILED=()
for tool in "${TOOLS_BREW[@]}"; do
  if check_command "$tool"; then
    ok "$tool already installed ($(command -v "$tool"))"
  else
    info "Installing $tool..."
    if brew install "$tool" 2>/dev/null; then
      ok "$tool installed"
    else
      fail "$tool failed to install"
      FAILED+=("$tool")
    fi
  fi
done

# ── Go tools (caldr) ──

info "Installing Go-based tools..."
if ! check_command go; then
  info "Go not found. Installing via Homebrew..."
  brew install go
fi

for pkg in "${TOOLS_GO[@]}"; do
  bin_name="$(basename "$pkg")"
  if check_command "$bin_name"; then
    ok "$bin_name already installed ($(command -v "$bin_name"))"
  else
    info "Installing $bin_name..."
    if go install "${pkg}@latest" 2>/dev/null; then
      # Symlink into Homebrew bin if not already in PATH
      go_bin="$(go env GOPATH)/bin/$bin_name"
      if [[ -x "$go_bin" ]] && ! check_command "$bin_name"; then
        ln -sf "$go_bin" /opt/homebrew/bin/"$bin_name" 2>/dev/null \
          || ln -sf "$go_bin" /usr/local/bin/"$bin_name" 2>/dev/null \
          || warn "$bin_name built at $go_bin but could not symlink into PATH"
      fi
      ok "$bin_name installed"
    else
      fail "$bin_name failed to install"
      FAILED+=("$bin_name")
    fi
  fi
done

# ── Python via uv ──

info "Setting up Python ${UV_PYTHON_VERSION} via uv..."
if uv python list --only-installed 2>/dev/null | grep -q "cpython-${UV_PYTHON_VERSION}"; then
  ok "Python ${UV_PYTHON_VERSION} already installed via uv"
else
  uv python install "${UV_PYTHON_VERSION}"
  ok "Python ${UV_PYTHON_VERSION} installed via uv"
fi

# ── Shell config ──

ZSHRC="$HOME/.zshrc"
info "Updating shell config ($ZSHRC)..."

add_line_if_missing() {
  local line="$1" file="$2"
  grep -qxF "$line" "$file" 2>/dev/null || echo "$line" >> "$file"
}

touch "$ZSHRC"
add_line_if_missing 'export PATH="$HOME/.local/bin:$PATH"' "$ZSHRC"
add_line_if_missing '. "$HOME/.cargo/env"' "$ZSHRC"
add_line_if_missing 'alias python="uv run python"' "$ZSHRC"
add_line_if_missing 'alias python3="uv run python"' "$ZSHRC"
add_line_if_missing 'alias pip="uv pip"' "$ZSHRC"
ok "Shell config updated"

# ── Summary ──

echo ""
info "Agent Sandbox CLI Stack — Installation Summary"
echo "────────────────────────────────────────────────"
printf "  %-14s %-12s %s\n" "DOMAIN" "TOOL" "STATUS"
echo "────────────────────────────────────────────────"

check_and_print() {
  local domain="$1" tool="$2" cmd="$3"
  if check_command "$cmd"; then
    printf "  %-14s %-12s ${GREEN}%s${NC}\n" "$domain" "$tool" "installed"
  else
    printf "  %-14s %-12s ${RED}%s${NC}\n" "$domain" "$tool" "MISSING"
  fi
}

check_and_print "Rust"      "rustc"      "rustc"
check_and_print "Cargo"     "cargo"      "cargo"
check_and_print "Go"        "go"         "go"
check_and_print "uv"        "uv"         "uv"
check_and_print "Python"    "python3.13" "python3.13"
check_and_print "Email"     "himalaya"   "himalaya"
check_and_print "Tasks"     "taskwarrior" "task"
check_and_print "Calendar"  "caldr"      "caldr"
check_and_print "Contacts"  "khard"      "khard"
check_and_print "Sync"      "vdirsyncer" "vdirsyncer"
check_and_print "Notes/KB"  "zk"         "zk"
check_and_print "Logging"   "jrnl"       "jrnl"

echo "────────────────────────────────────────────────"

if [[ ${#FAILED[@]} -gt 0 ]]; then
  echo ""
  warn "Failed: ${FAILED[*]}"
  warn "Re-run or install manually."
  exit 1
fi

echo ""
ok "All tools installed. Configure with:"
echo "  himalaya account add        # IMAP/SMTP email"
echo "  task                        # creates ~/.taskrc on first run"
echo "  caldr -r                    # sync CalDAV events"
echo "  vdirsyncer discover         # setup CalDAV/CardDAV sync"
echo "  zk init <notebook-dir>      # create a notebook"
echo "  jrnl 'first entry'          # creates journal on first use"
