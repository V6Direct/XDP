#!/usr/bin/env bash
# ============================================================
# build_xdp.sh  –  Compile XDP BPF program with libbpf CO-RE
# Requires: clang >= 12, libbpf-dev, linux-headers
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
SRC_DIR="$ROOT_DIR/pkg/xdp/c_src"
OUT_DIR="/usr/local/lib/ddos"

CLANG="${CLANG:-clang}"
LLC="${LLC:-llc}"

# ── Detect kernel version ──────────────────────────────────
KERNEL_VER=$(uname -r)
ARCH=$(uname -m)
if [[ "$ARCH" == "x86_64" ]]; then
    BPF_ARCH="x86"
elif [[ "$ARCH" == "aarch64" ]]; then
    BPF_ARCH="arm64"
else
    BPF_ARCH="$ARCH"
fi

echo "==> Building XDP program"
echo "    Kernel : $KERNEL_VER"
echo "    Arch   : $ARCH (BPF=$BPF_ARCH)"
echo "    Clang  : $($CLANG --version | head -1)"
echo "    Source : $SRC_DIR/xdp_main.c"
echo "    Output : $OUT_DIR/xdp_main.o"
echo ""

# ── Locate kernel headers ──────────────────────────────────
KERNEL_HEADERS="/usr/src/linux-headers-$KERNEL_VER"
if [[ ! -d "$KERNEL_HEADERS" ]]; then
    KERNEL_HEADERS="/usr/src/linux-headers-$(ls /usr/src/ | grep "linux-headers" | sort -V | tail -1)"
fi
if [[ ! -d "$KERNEL_HEADERS" ]]; then
    echo "ERROR: Cannot find kernel headers. Install linux-headers-$(uname -r)"
    exit 1
fi

echo "    Headers: $KERNEL_HEADERS"

# ── Create output directory ────────────────────────────────
mkdir -p "$OUT_DIR"

# ── Compile ────────────────────────────────────────────────
$CLANG \
    -O2 \
    -g \
    -target bpf \
    -D__TARGET_ARCH_${BPF_ARCH} \
    -I"$SRC_DIR" \
    -I"$KERNEL_HEADERS/include" \
    -I"$KERNEL_HEADERS/arch/${BPF_ARCH}/include" \
    -I"/usr/include" \
    -I"/usr/include/bpf" \
    -march=bpf \
    -mcpu=probe \
    -Wall \
    -Wno-unused-value \
    -Wno-pointer-sign \
    -Wno-compare-distinct-pointer-types \
    -fno-stack-protector \
    -c "$SRC_DIR/xdp_main.c" \
    -o "$OUT_DIR/xdp_main.o"

echo "✓  Compiled: $OUT_DIR/xdp_main.o"

# ── Verify BTF section exists ──────────────────────────────
if command -v llvm-objdump &>/dev/null; then
    SECTIONS=$(llvm-objdump -h "$OUT_DIR/xdp_main.o" | grep -E 'xdp|maps|\.BTF' || true)
    echo ""
    echo "==> BPF ELF sections:"
    echo "$SECTIONS"
fi

echo ""
echo "✓  Build complete"
