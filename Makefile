# ============================================================
# Makefile – DDoS Mitigation Platform
# ============================================================
.PHONY: all xdp go-controlplane go-webpanel install clean test lint

IFACE         ?= eth0
BPF_OBJ       ?= /usr/local/lib/ddos/xdp_main.o
CLANG         ?= clang
GO            ?= go
BUILD_FLAGS   ?= -v -trimpath

all: xdp go-controlplane go-webpanel go-ddosctl

# ── BPF / XDP ─────────────────────────────────────────────
xdp:
	@echo "==> Building XDP program..."
	@bash scripts/build_xdp.sh
	@echo "✓  XDP: $(BPF_OBJ)"

# ── Go binaries ───────────────────────────────────────────
go-controlplane:
	@echo "==> Building control plane..."
	$(GO) build $(BUILD_FLAGS) -o bin/ddos-controlplane ./cmd/controlplane/
	@echo "✓  bin/ddos-controlplane"

go-webpanel:
	@echo "==> Building web panel..."
	$(GO) build $(BUILD_FLAGS) -o bin/ddos-webpanel ./cmd/webpanel/backend/
	@echo "✓  bin/ddos-webpanel"

go-ddosctl:
	@echo "==> Building ddosctl CLI..."
	$(GO) build $(BUILD_FLAGS) -o bin/ddosctl ./cmd/ddosctl/
	@echo "✓  bin/ddosctl"

# ── Testing ───────────────────────────────────────────────
test:
	$(GO) test ./... -race -count=1

test-verbose:
	$(GO) test ./... -race -v -count=1

test-cover:
	$(GO) test ./... -race -coverprofile=coverage.out
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "✓  coverage.html generated"

bench:
	$(GO) test ./benchmarks/ -bench=. -benchmem -benchtime=5s

bench-api:
	$(GO) test ./benchmarks/ -bench=BenchmarkMetrics -benchmem -benchtime=10s -count=3

lint:
	golangci-lint run ./...

# ── Development run (no XDP, stub mode) ──────────────────
run-controlplane:
	$(GO) run ./cmd/controlplane/ --iface $(IFACE)

run-webpanel:
	$(GO) run ./cmd/webpanel/backend/ \
	    --cp http://localhost:8080 \
	    --frontend ./cmd/webpanel/frontend

# ── Installation ──────────────────────────────────────────
install:
	@bash scripts/install.sh $(IFACE)
	install -m755 bin/ddosctl $(INSTALL_BIN)/ddosctl

INSTALL_BIN ?= /usr/local/bin

load:
	@bash scripts/load_xdp.sh load --iface $(IFACE)

unload:
	@bash scripts/load_xdp.sh unload

status:
	@bash scripts/load_xdp.sh status

# ── Clean ─────────────────────────────────────────────────
clean:
	rm -rf bin/
	rm -f $(BPF_OBJ)

# ── Go module management ───────────────────────────────────
tidy:
	$(GO) mod tidy

# ── Binary directory ──────────────────────────────────────
bin/:
	mkdir -p bin

# ── Bootstrap (first-time setup) ──────────────────────────
bootstrap:
	@bash scripts/bootstrap.sh

setup:
	@bash scripts/setup.sh

# ── Sample config ─────────────────────────────────────────
sample-config:
	@cp -n deployments/controlplane-sample.json /etc/ddos-platform/controlplane.json 2>/dev/null || \
	  echo "Config already exists at /etc/ddos-platform/controlplane.json"
