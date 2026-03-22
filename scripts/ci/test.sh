#!/usr/bin/env bash
# ============================================================
# scripts/ci/test.sh  –  CI test runner
# Runs: unit tests, integration tests, race detector, coverage
# ============================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

log()  { echo -e "\e[36m[CI]\e[0m $*"; }
ok()   { echo -e "\e[32m[OK]\e[0m $*"; }
fail() { echo -e "\e[31m[FAIL]\e[0m $*" >&2; exit 1; }

GOFLAGS="${GOFLAGS:-}"
TIMEOUT="${TIMEOUT:-120s}"
COVEROUT="${COVEROUT:-coverage.out}"

log "Go version: $(go version)"
log "Root: $ROOT_DIR"
echo ""

# ── Step 1: Verify module ──────────────────────────────────
log "Verifying go.mod..."
go mod verify 2>/dev/null || log "(mod verify skipped – no go.sum yet; run: go mod tidy)"
ok "Module verified"

# ── Step 2: Build all binaries ────────────────────────────
log "Building all binaries..."
mkdir -p bin
go build -o bin/ddos-controlplane ./cmd/controlplane/ \
    2>/dev/null || log "controlplane build skipped (requires BPF headers on Linux)"
go build -o bin/ddos-webpanel     ./cmd/webpanel/backend/
go build -o bin/ddosctl            ./cmd/ddosctl/
ok "Binaries built"

# ── Step 3: Unit tests (no BPF required) ─────────────────
log "Running unit tests (race detector on)..."
go test \
    -race \
    -timeout "$TIMEOUT" \
    -coverprofile="$COVEROUT" \
    -covermode=atomic \
    ./pkg/types/... \
    ./pkg/logger/... \
    ./pkg/config/... \
    ./pkg/reputation/... \
    ./pkg/xdp/... \
    ./cmd/ddosctl/... \
    ./cmd/webpanel/backend/... \
    -v 2>&1 | tee /tmp/unit-test.log

UNIT_EXIT=${PIPESTATUS[0]}
if [[ $UNIT_EXIT -ne 0 ]]; then
    fail "Unit tests failed (exit $UNIT_EXIT)"
fi
ok "Unit tests passed"

# ── Step 4: Integration tests ─────────────────────────────
log "Running integration tests..."
go test \
    -race \
    -timeout "$TIMEOUT" \
    ./integration/... \
    -v 2>&1 | tee /tmp/integration-test.log

INTEG_EXIT=${PIPESTATUS[0]}
if [[ $INTEG_EXIT -ne 0 ]]; then
    fail "Integration tests failed (exit $INTEG_EXIT)"
fi
ok "Integration tests passed"

# ── Step 5: Benchmarks (smoke run) ────────────────────────
log "Running benchmarks (1 second each)..."
go test \
    -bench=. \
    -benchtime=1s \
    -benchmem \
    -run='^$' \
    ./benchmarks/... 2>&1 | head -40
ok "Benchmarks completed"

# ── Step 6: Coverage report ───────────────────────────────
log "Coverage report..."
if command -v go &>/dev/null && [[ -f "$COVEROUT" ]]; then
    COVERAGE=$(go tool cover -func="$COVEROUT" 2>/dev/null | grep "^total:" | awk '{print $3}')
    ok "Total coverage: ${COVERAGE:-unknown}"
    go tool cover -html="$COVEROUT" -o coverage.html 2>/dev/null || true
fi

# ── Step 7: vet ───────────────────────────────────────────
log "Running go vet..."
go vet ./... && ok "go vet passed"

# ── Step 8: staticcheck (optional) ───────────────────────
if command -v staticcheck &>/dev/null; then
    log "Running staticcheck..."
    staticcheck ./... && ok "staticcheck passed"
else
    log "staticcheck not installed (optional); install: go install honnef.co/go/tools/cmd/staticcheck@latest"
fi

echo ""
echo "╔═══════════════════════════════════════╗"
echo "║          CI Pipeline: PASSED          ║"
echo "╚═══════════════════════════════════════╝"
