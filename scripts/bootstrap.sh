#!/usr/bin/env bash
# =============================================================================
# scripts/bootstrap.sh
# One-time developer setup: generates go.sum, validates toolchain, builds all.
#
# Run this ONCE after cloning, before your first commit/push:
#   bash scripts/bootstrap.sh
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}==> ${NC}$*"; }
ok()   { echo -e "${GREEN} ✓  ${NC}$*"; }
warn() { echo -e "${YELLOW} !  ${NC}$*"; }
fail() { echo -e "${RED}ERR ${NC}$*" >&2; exit 1; }

echo ""
echo "╔════════════════════════════════════════════════╗"
echo "║   DDoS Platform — Bootstrap / Setup Script   ║"
echo "╚════════════════════════════════════════════════╝"
echo ""

# ── Step 1: Check Go version ──────────────────────────────
log "Checking Go version..."
if ! command -v go &>/dev/null; then
    fail "Go is not installed. Install Go 1.22+ from https://go.dev/dl/"
fi
GO_VER=$(go version | awk '{print $3}' | sed 's/go//')
GO_MAJOR=$(echo "$GO_VER" | cut -d. -f1)
GO_MINOR=$(echo "$GO_VER" | cut -d. -f2)
if [ "$GO_MAJOR" -lt 1 ] || { [ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -lt 22 ]; }; then
    fail "Go 1.22+ required, found go$GO_VER"
fi
ok "Go $GO_VER"

# ── Step 2: Check network connectivity to proxy.golang.org ──
log "Checking module proxy connectivity..."
if curl -sf --max-time 5 "https://proxy.golang.org/github.com/gin-gonic/gin/@v/v1.9.1.info" > /dev/null 2>&1; then
    ok "Module proxy reachable"
    NETWORK=true
else
    warn "Module proxy not reachable — skipping go mod tidy"
    warn "You'll need network access to generate go.sum"
    NETWORK=false
fi

# ── Step 3: Generate go.sum ───────────────────────────────
if [ "$NETWORK" = true ]; then
    log "Running go mod tidy (generates go.sum)..."
    go mod tidy
    ok "go.sum generated ($(wc -l < go.sum) lines)"

    log "Verifying module checksums..."
    go mod verify
    ok "All modules verified"
else
    if [ -f go.sum ]; then
        ok "go.sum already exists ($(wc -l < go.sum) lines)"
    else
        warn "go.sum missing and no network. CI will run 'go mod tidy' automatically."
        warn "To generate locally: connect to the internet and re-run this script."
    fi
fi

# ── Step 4: Download modules to cache ────────────────────
if [ "$NETWORK" = true ] && [ -f go.sum ]; then
    log "Downloading all modules to cache..."
    go mod download
    ok "Modules cached"
fi

# ── Step 5: Build portable binaries ──────────────────────
log "Building ddos-webpanel..."
mkdir -p bin
if go build -o bin/ddos-webpanel ./cmd/webpanel/backend/ 2>/dev/null; then
    ok "bin/ddos-webpanel"
else
    warn "webpanel build failed (check output above)"
fi

log "Building ddosctl..."
if go build -o bin/ddosctl ./cmd/ddosctl/ 2>/dev/null; then
    ok "bin/ddosctl"
else
    warn "ddosctl build failed"
fi

# ── Step 6: Run portable tests ────────────────────────────
log "Running portable unit tests..."
if go test -timeout 60s \
    ./pkg/... \
    ./cmd/ddosctl/... \
    ./cmd/webpanel/... \
    2>&1 | tail -5; then
    ok "Portable tests passed"
else
    warn "Some tests failed — check output above"
fi

# ── Step 7: go vet ────────────────────────────────────────
log "Running go vet..."
if go vet ./... 2>&1; then
    ok "go vet passed"
else
    warn "go vet reported issues — fix before pushing"
fi

# ── Step 8: Check for go.sum to commit ───────────────────
echo ""
if [ -f go.sum ]; then
    if git status --porcelain go.sum 2>/dev/null | grep -q "go.sum"; then
        echo -e "${YELLOW}⚠  go.sum has been modified or created. Commit it:${NC}"
        echo ""
        echo "    git add go.sum"
        echo "    git commit -m 'chore: add/update go.sum'"
        echo "    git push"
        echo ""
    else
        ok "go.sum is committed and up-to-date"
    fi
else
    warn "go.sum not present — CI will generate it on first push"
fi

# ── Check for BPF toolchain (optional) ───────────────────
echo ""
log "Checking optional BPF toolchain..."
if command -v clang &>/dev/null; then
    CLANG_VER=$(clang --version | head -1 | grep -oP '\d+\.\d+' | head -1)
    ok "clang $CLANG_VER found"
    if command -v llc &>/dev/null; then
        ok "llc found (BPF compilation available)"
        echo "    Run: make xdp    to compile the XDP program"
    fi
else
    warn "clang not found — XDP compilation unavailable on this machine"
    warn "Install with: apt install clang llvm libbpf-dev linux-headers-\$(uname -r)"
fi

echo ""
echo "╔════════════════════════════════════════════════╗"
echo "║              Bootstrap complete!              ║"
echo "╠════════════════════════════════════════════════╣"
echo "║  Web panel:   ./bin/ddos-webpanel --help      ║"
echo "║  CLI tool:    ./bin/ddosctl help               ║"
echo "║  Full build:  make all                        ║"
echo "║  Tests:       make test                       ║"
echo "╚════════════════════════════════════════════════╝"
echo ""
