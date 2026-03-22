# DDoS Mitigation Platform

A production-ready DDoS mitigation platform for Network Service Providers (NSPs) using Linux XDP/eBPF for kernel-space packet filtering, a Go control plane for dynamic policy management, and a web panel for real-time monitoring.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        KERNEL SPACE                          │
│                                                              │
│  NIC → XDP Program (xdp_main.c)                             │
│         ├── SYN flood protection                            │
│         ├── UDP amplification filtering                     │
│         └── ICMP rate limiting                              │
│                        ↕ BPF Maps (pinned /sys/fs/bpf/ddos/)│
└──────────────────────────────────────────────────────────────┘
                           ↕
┌──────────────────────────────────────────────────────────────┐
│                       USER SPACE                             │
│                                                              │
│  Control Plane (Go)                                         │
│  ├── XDP loader (cilium/ebpf)                               │
│  ├── BPF map manager                                        │
│  ├── REST API   :8080                                       │
│  └── Prometheus :9090/metrics                               │
│                                                              │
│  Web Panel (Go + Gin)                                        │
│  ├── JWT auth backend  :3000                                │
│  └── Static frontend (HTML/JS/CSS)                          │
└──────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
ddos-platform/
├── cmd/
│   ├── controlplane/
│   │   ├── main.go          # REST API server + signal handling
│   │   ├── xdp_loader.go    # BPF object loading + XDP attachment
│   │   ├── maps.go          # BPF map read/write operations
│   │   └── metrics.go       # Prometheus metrics server
│   └── webpanel/
│       ├── backend/
│       │   ├── main.go             # Gin server entrypoint
│       │   ├── api/handlers.go     # Route handlers
│       │   ├── auth/auth.go        # JWT authentication
│       │   └── models/models.go    # Domain types
│       └── frontend/
│           ├── index.html   # Dashboard SPA
│           ├── app.js       # All client-side logic
│           └── styles.css   # Dark industrial UI theme
├── pkg/
│   ├── types/types.go       # Shared Go types (mirrors BPF structs)
│   └── xdp/c_src/
│       ├── xdp_main.c       # XDP BPF entrypoint
│       ├── xdp_maps.h       # BPF map definitions
│       └── xdp_filters.h    # Protocol parsing + filter logic
├── scripts/
│   ├── build_xdp.sh         # Compile BPF with clang
│   ├── load_xdp.sh          # Lifecycle management script
│   └── install.sh           # Full system installer
├── deployments/
│   ├── ddos-controlplane.service
│   ├── ddos-webpanel.service
│   ├── controlplane.env.example
│   └── webpanel.env.example
└── Makefile
```

---

## Prerequisites

| Requirement         | Version      | Notes                          |
|---------------------|--------------|--------------------------------|
| Linux kernel        | ≥ 5.10       | XDP + BPF CO-RE support        |
| Clang/LLVM          | ≥ 12         | BPF compilation                |
| libbpf-dev          | ≥ 0.8        | CO-RE support                  |
| linux-headers       | = uname -r   | BPF compilation                |
| Go                  | ≥ 1.22       | Control plane + web panel      |
| bpftool (optional)  | any          | Debugging/status               |

### Install dependencies (Debian/Ubuntu)

```bash
apt-get install -y \
    clang llvm libelf-dev libbpf-dev \
    linux-headers-$(uname -r) \
    golang-go \
    bpftool iproute2 curl
```

---

## Quick Start

```bash
# 1. Clone and enter
git clone https://github.com/V6Direct/XDP.git
cd XDP

# 2. Get Go dependencies
go mod tidy

# 3. Build everything (run as root for XDP)
make all

# 4. Install + deploy (set IFACE to your public interface)
sudo make install IFACE=eth0

# 5. Open the web panel
xdg-open http://localhost:3000
# Login: admin / changeme  ← CHANGE THIS IMMEDIATELY
```

---

## Manual Build & Run

### Build XDP BPF program
```bash
sudo bash scripts/build_xdp.sh
```

### Build Go binaries
```bash
go build -o bin/ddos-controlplane ./cmd/controlplane/
go build -o bin/ddos-webpanel     ./cmd/webpanel/backend/
```

### Run control plane
```bash
# Requires root
sudo ./bin/ddos-controlplane --iface eth0 --api :8080 --metrics :9090
```

### Run web panel
```bash
./bin/ddos-webpanel --cp http://localhost:8080 --frontend ./cmd/webpanel/frontend --addr :3000
```

---

## API Reference

### Control Plane API (`:8080`)

| Method   | Path                  | Description                         |
|----------|-----------------------|-------------------------------------|
| `GET`    | `/api/v1/metrics`     | Full metrics snapshot               |
| `GET`    | `/api/v1/blocked`     | List blocked IPs                    |
| `POST`   | `/api/v1/blocked`     | Block an IP `{"ip":"1.2.3.4","reason":1}` |
| `DELETE` | `/api/v1/blocked`     | Unblock an IP `{"ip":"1.2.3.4"}`  |
| `GET`    | `/api/v1/attackers`   | Top 20 attacking IPs                |
| `GET`    | `/api/v1/config`      | Get current rate-limit config       |
| `POST`   | `/api/v1/config`      | Update rate-limit thresholds        |
| `POST`   | `/api/v1/whitelist`   | Add IP to whitelist                 |
| `DELETE` | `/api/v1/whitelist`   | Remove IP from whitelist            |
| `GET`    | `/healthz`            | Health check                        |

### Web Panel API (`:3000`)

| Method | Path                  | Auth     | Description        |
|--------|-----------------------|----------|--------------------|
| `POST` | `/api/auth/login`     | None     | Get JWT token      |
| `GET`  | `/api/v1/dashboard`   | Bearer   | Full dashboard     |
| `GET`  | `/api/v1/metrics`     | Bearer   | Metrics (proxied)  |
| `GET`  | `/api/v1/alerts`      | Bearer   | Security alerts    |
| ...    | All controlplane routes | Bearer | Proxied to CP      |

### Prometheus Metrics (`:9090/metrics`)

```
ddos_total_packets_total
ddos_dropped_packets_total
ddos_passed_packets_total
ddos_total_bytes_total
ddos_syn_floods_total
ddos_udp_amplification_total
ddos_icmp_floods_total
ddos_packets_per_second
ddos_bits_per_second
ddos_blocked_ips_count
```

---

## BPF Maps

All maps are pinned under `/sys/fs/bpf/ddos/`:

| Map Name           | Type                  | Key        | Value         | Description                     |
|--------------------|-----------------------|------------|---------------|---------------------------------|
| `ip_stats_map`     | LRU_PERCPU_HASH       | src_ip u32 | ip_stats      | Per-IP packet counters          |
| `blocked_ips`      | LRU_HASH              | src_ip u32 | blocked_entry | Currently blocked IPs           |
| `global_stats_map` | PERCPU_ARRAY          | 0          | global_stats  | Aggregate per-CPU counters      |
| `whitelist_map`    | HASH                  | src_ip u32 | u8            | IPs that bypass all filtering   |
| `config_map`       | ARRAY                 | index u32  | threshold u64 | Runtime rate-limit config       |

### Config map indices

| Index | Name              | Default |
|-------|-------------------|---------|
| 0     | `CFG_SYN_RATE`    | 1000    |
| 1     | `CFG_UDP_RATE`    | 5000    |
| 2     | `CFG_ICMP_RATE`   | 100     |
| 3     | `CFG_ENABLED`     | 1       |

---

## Security Notes

1. **Change default credentials** immediately after install.
2. The control plane REST API (`:8080`) should **not be publicly exposed** — bind to localhost or a management interface.
3. Replace the SHA-256 password hashing in `auth/auth.go` with **bcrypt** for production.
4. Use TLS (reverse proxy like nginx/caddy) in front of both services for production.
5. The JWT secret is auto-generated on first install; store it securely.

---

## Deployment with Prometheus + Grafana

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'ddos-mitigation'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 5s
```

---

## License

MIT – See LICENSE file.

## Warning

Yes we know this code is a mess.
