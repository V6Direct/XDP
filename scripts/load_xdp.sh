#!/usr/bin/env bash
# ============================================================
# load_xdp.sh  –  Load, reload, status, or unload the DDoS
#                 mitigation XDP program via the control plane
# Usage:
#   ./load_xdp.sh load   [--iface eth0] [--replace]
#   ./load_xdp.sh unload
#   ./load_xdp.sh status
#   ./load_xdp.sh reload [--iface eth0]
# ============================================================
set -euo pipefail

IFACE="${IFACE:-eth0}"
CP_BIN="${CP_BIN:-/usr/local/bin/ddos-controlplane}"
PIN_PATH="/sys/fs/bpf/ddos"
BPF_OBJ="/usr/local/lib/ddos/xdp_main.o"
SYSTEMD_UNIT="ddos-controlplane"

usage() {
    cat <<EOF
Usage: $0 <command> [options]

Commands:
  load    [--iface IFACE] [--replace]   Load XDP and start control plane
  unload                                 Detach XDP and stop control plane
  reload  [--iface IFACE]               Reload (unload + load)
  status                                 Show current status
  check                                  Verify prerequisites

Options:
  --iface IFACE   Network interface (default: eth0)
  --replace       Replace existing XDP program and unpin maps

Environment:
  IFACE           Override default interface
  CP_BIN          Path to controlplane binary (default: /usr/local/bin/ddos-controlplane)
EOF
}

# ── Helpers ────────────────────────────────────────────────

log()  { echo -e "\e[36m==>\e[0m $*"; }
ok()   { echo -e "\e[32m ✓ \e[0m $*"; }
warn() { echo -e "\e[33m ! \e[0m $*"; }
err()  { echo -e "\e[31mERR\e[0m $*" >&2; exit 1; }

require_root() {
    [[ $EUID -eq 0 ]] || err "This script must run as root"
}

check_prerequisites() {
    log "Checking prerequisites..."

    command -v ip      &>/dev/null || err "'ip' not found (install iproute2)"
    command -v bpftool &>/dev/null || warn "'bpftool' not found (optional, for status)"

    [[ -f "$BPF_OBJ" ]]  || err "BPF object not found: $BPF_OBJ  (run scripts/build_xdp.sh first)"
    [[ -f "$CP_BIN" ]]   || err "Control plane binary not found: $CP_BIN  (run: go build ./cmd/controlplane)"

    # Check interface exists
    ip link show "$IFACE" &>/dev/null || err "Interface $IFACE not found"

    # Check BPF filesystem
    if ! mount | grep -q 'type bpf'; then
        log "Mounting BPF filesystem..."
        mount -t bpf none /sys/fs/bpf || err "Failed to mount bpffs"
        ok "BPF filesystem mounted"
    else
        ok "BPF filesystem already mounted"
    fi

    ok "Prerequisites satisfied"
}

# ── Commands ───────────────────────────────────────────────

cmd_load() {
    local replace=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --iface)   IFACE="$2"; shift 2 ;;
            --replace) replace="--replace"; shift ;;
            *)         shift ;;
        esac
    done

    require_root
    check_prerequisites

    log "Loading XDP on interface: $IFACE"
    mkdir -p "$PIN_PATH"

    # If systemd unit exists, use it
    if systemctl list-unit-files | grep -q "$SYSTEMD_UNIT.service"; then
        log "Starting via systemd..."
        systemctl start "$SYSTEMD_UNIT"
        ok "systemd unit $SYSTEMD_UNIT started"
    else
        log "Starting control plane directly..."
        nohup "$CP_BIN" \
            --iface "$IFACE" \
            --api   ":8080" \
            --metrics ":9090" \
            $replace \
            > /var/log/ddos-controlplane.log 2>&1 &

        echo $! > /var/run/ddos-controlplane.pid
        ok "Control plane started (PID $!)"
    fi

    sleep 1
    cmd_status
}

cmd_unload() {
    require_root
    log "Unloading XDP..."

    # Stop via systemd or PID file
    if systemctl is-active --quiet "$SYSTEMD_UNIT" 2>/dev/null; then
        systemctl stop "$SYSTEMD_UNIT"
        ok "Systemd unit stopped"
    elif [[ -f /var/run/ddos-controlplane.pid ]]; then
        PID=$(cat /var/run/ddos-controlplane.pid)
        kill "$PID" 2>/dev/null || warn "PID $PID not running"
        rm -f /var/run/ddos-controlplane.pid
        ok "Process $PID stopped"
    else
        warn "No running control plane found"
    fi

    # Run detach command
    if [[ -f "$CP_BIN" ]]; then
        "$CP_BIN" --detach 2>/dev/null || true
    fi

    # Remove XDP from interface directly as fallback
    if ip link show "$IFACE" &>/dev/null; then
        ip link set dev "$IFACE" xdp off 2>/dev/null && ok "XDP detached from $IFACE" || true
    fi

    # Clean up pins
    if [[ -d "$PIN_PATH" ]]; then
        rm -rf "$PIN_PATH"
        ok "BPF pins removed from $PIN_PATH"
    fi

    ok "Unload complete"
}

cmd_reload() {
    log "Reloading..."
    cmd_unload
    sleep 1
    cmd_load "$@"
}

cmd_status() {
    echo ""
    log "XDP / DDoS Mitigation Status"
    echo "────────────────────────────────────────"

    # Interface XDP
    echo -n "  XDP on $IFACE: "
    if ip link show "$IFACE" 2>/dev/null | grep -q xdp; then
        echo -e "\e[32mATTACHED\e[0m"
        ip link show "$IFACE" | grep -o 'xdp[^ ]*' || true
    else
        echo -e "\e[33mNOT ATTACHED\e[0m"
    fi

    # BPF pins
    echo -n "  BPF pins ($PIN_PATH): "
    if [[ -d "$PIN_PATH" ]]; then
        PIN_COUNT=$(ls "$PIN_PATH" 2>/dev/null | wc -l)
        echo -e "\e[32m$PIN_COUNT maps pinned\e[0m"
        ls "$PIN_PATH" 2>/dev/null | sed 's/^/    /'
    else
        echo -e "\e[33mNONE\e[0m"
    fi

    # Process
    echo -n "  Control plane process: "
    if pgrep -f "ddos-controlplane" &>/dev/null; then
        PID=$(pgrep -f "ddos-controlplane")
        echo -e "\e[32mRUNNING (PID $PID)\e[0m"
    else
        echo -e "\e[33mNOT RUNNING\e[0m"
    fi

    # Systemd unit
    if systemctl list-unit-files 2>/dev/null | grep -q "$SYSTEMD_UNIT.service"; then
        echo -n "  Systemd unit: "
        systemctl is-active "$SYSTEMD_UNIT" && true || true
    fi

    # API health
    echo -n "  API health: "
    if curl -sf http://localhost:8080/healthz &>/dev/null; then
        echo -e "\e[32mOK\e[0m"
    else
        echo -e "\e[33mUNREACHABLE\e[0m"
    fi

    # bpftool prog list if available
    if command -v bpftool &>/dev/null; then
        echo ""
        echo "  BPF programs:"
        bpftool prog list 2>/dev/null | grep -A2 "xdp" | sed 's/^/    /' || echo "    (none)"
    fi

    echo "────────────────────────────────────────"
    echo ""
}

# ── Entry point ────────────────────────────────────────────

COMMAND="${1:-help}"
shift || true

case "$COMMAND" in
    load)          cmd_load   "$@" ;;
    unload)        cmd_unload "$@" ;;
    reload)        cmd_reload "$@" ;;
    status)        cmd_status      ;;
    check)         require_root; check_prerequisites ;;
    help|--help|-h) usage ;;
    *) err "Unknown command: $COMMAND. Use 'help' for usage." ;;
esac
