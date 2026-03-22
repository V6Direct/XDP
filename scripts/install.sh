#!/usr/bin/env bash
# ============================================================
# install.sh  –  Full deployment of the DDoS Mitigation Platform
# ============================================================
set -euo pipefail

INSTALL_BIN="/usr/local/bin"
INSTALL_LIB="/usr/local/lib/ddos"
INSTALL_SHARE="/usr/local/share/ddos-platform"
ETC_DIR="/etc/ddos-platform"
LOG_DIR="/var/log/ddos-platform"
SYSTEMD_DIR="/etc/systemd/system"

IFACE="${1:-eth0}"

log()  { echo -e "\e[36m==>\e[0m $*"; }
ok()   { echo -e "\e[32m ✓ \e[0m $*"; }
warn() { echo -e "\e[33m ! \e[0m $*"; }
err()  { echo -e "\e[31mERR\e[0m $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || err "Run as root"

command -v go    &>/dev/null || err "Go not installed"
command -v clang &>/dev/null || err "Clang not installed"

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   DDoS Mitigation Platform  –  Installer    ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
log "Interface: $IFACE"
echo ""

# ── Step 1: Build XDP BPF object ──────────────────────────
log "Building XDP BPF program..."
bash scripts/build_xdp.sh
ok "XDP program built → $INSTALL_LIB/xdp_main.o"

# ── Step 2: Build Go binaries ──────────────────────────────
log "Building Go binaries..."
go build -o "$INSTALL_BIN/ddos-controlplane" ./cmd/controlplane/
ok "ddos-controlplane → $INSTALL_BIN/ddos-controlplane"

go build -o "$INSTALL_BIN/ddos-webpanel" ./cmd/webpanel/backend/
ok "ddos-webpanel → $INSTALL_BIN/ddos-webpanel"

# ── Step 3: Install frontend ───────────────────────────────
log "Installing frontend..."
mkdir -p "$INSTALL_SHARE/frontend"
cp cmd/webpanel/frontend/{index.html,app.js,styles.css} "$INSTALL_SHARE/frontend/"
ok "Frontend → $INSTALL_SHARE/frontend/"

# ── Step 4: Create directories ─────────────────────────────
log "Creating directories..."
mkdir -p "$ETC_DIR" "$LOG_DIR" "/sys/fs/bpf/ddos"

# ── Step 5: Install configs if not present ─────────────────
log "Installing config files..."
if [[ ! -f "$ETC_DIR/controlplane.env" ]]; then
    cp deployments/controlplane.env.example "$ETC_DIR/controlplane.env"
    sed -i "s/^DDOS_IFACE=.*/DDOS_IFACE=$IFACE/" "$ETC_DIR/controlplane.env"
    ok "Created $ETC_DIR/controlplane.env"
else
    warn "Skipping $ETC_DIR/controlplane.env (already exists)"
fi

if [[ ! -f "$ETC_DIR/webpanel.env" ]]; then
    cp deployments/webpanel.env.example "$ETC_DIR/webpanel.env"
    # Generate a random JWT secret
    JWT=$(openssl rand -hex 32 2>/dev/null || cat /dev/urandom | head -c 32 | xxd -p -c 64)
    sed -i "s/^JWT_SECRET=.*/JWT_SECRET=$JWT/" "$ETC_DIR/webpanel.env"
    ok "Created $ETC_DIR/webpanel.env (JWT secret generated)"
else
    warn "Skipping $ETC_DIR/webpanel.env (already exists)"
fi

# ── Step 6: Create service user for webpanel ───────────────
if ! id ddos-panel &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin ddos-panel
    ok "Created system user: ddos-panel"
fi
chown ddos-panel:ddos-panel "$LOG_DIR"

# ── Step 7: Install systemd units ─────────────────────────
log "Installing systemd units..."
cp deployments/ddos-controlplane.service "$SYSTEMD_DIR/"
cp deployments/ddos-webpanel.service     "$SYSTEMD_DIR/"
systemctl daemon-reload
ok "Systemd units installed and daemon reloaded"

# ── Step 8: Enable and start services ──────────────────────
log "Enabling services..."
systemctl enable ddos-controlplane ddos-webpanel
ok "Services enabled for auto-start"

log "Starting services..."
systemctl start ddos-controlplane
sleep 2
systemctl start ddos-webpanel

# ── Step 9: Verify ─────────────────────────────────────────
echo ""
log "Verifying installation..."
sleep 2

if systemctl is-active --quiet ddos-controlplane; then
    ok "ddos-controlplane: RUNNING"
else
    warn "ddos-controlplane: NOT RUNNING (check: journalctl -u ddos-controlplane)"
fi

if systemctl is-active --quiet ddos-webpanel; then
    ok "ddos-webpanel: RUNNING"
else
    warn "ddos-webpanel: NOT RUNNING (check: journalctl -u ddos-webpanel)"
fi

# ── Done ───────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║              Installation Complete           ║"
echo "╠══════════════════════════════════════════════╣"
echo "║  Web Panel:    http://localhost:3000         ║"
echo "║  Control API:  http://localhost:8080         ║"
echo "║  Metrics:      http://localhost:9090/metrics ║"
echo "║                                              ║"
echo "║  Default creds:  admin / changeme            ║"
echo "║  CHANGE PASSWORD before exposing to network! ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
