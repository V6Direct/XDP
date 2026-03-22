// Package types defines shared data structures used across the DDoS mitigation platform.
// All structs here are consistent with BPF map layouts and REST API responses.
package types

import "time"

// ─── BPF-aligned structs ─────────────────────────────────────────────────────
// These mirror the C structs in xdp_maps.h exactly (field order + sizing).

// IPStats mirrors struct ip_stats in xdp_maps.h.
// Layout must be kept in sync with the BPF side.
type IPStats struct {
	SYNCount      uint64
	UDPCount      uint64
	ICMPCount     uint64
	TotalPackets  uint64
	TotalBytes    uint64
	WindowStartNS uint64
	Blocked       uint32
	Pad           uint32
}

// GlobalStats mirrors struct global_stats in xdp_maps.h.
// This is a per-CPU map; values from all CPUs must be summed.
type GlobalStats struct {
	TotalPackets      uint64
	TotalBytes        uint64
	DroppedPackets    uint64
	SYNFloods         uint64
	UDPAmplifications uint64
	ICMPFloods        uint64
	PassedPackets     uint64
	Pad               uint64
}

// BlockedEntry mirrors struct blocked_entry in xdp_maps.h.
type BlockedEntry struct {
	BlockedAtNS uint64
	Reason      uint32 // 1=SYN, 2=UDP, 3=ICMP
	Pad         uint32
}

// ─── Application-level structs ───────────────────────────────────────────────

// IPPrefix represents a CIDR block for whitelist/blacklist operations.
type IPPrefix struct {
	Addr      string `json:"addr"`
	PrefixLen int    `json:"prefix_len"`
}

// BlockedIP is the API representation of a blocked IP entry.
type BlockedIP struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	BlockedAt time.Time `json:"blocked_at"`
}

// AttackingIP represents a top attacker with rate info.
type AttackingIP struct {
	IP           string  `json:"ip"`
	PPS          float64 `json:"pps"`
	BPS          float64 `json:"bps"`
	SYNCount     uint64  `json:"syn_count"`
	UDPCount     uint64  `json:"udp_count"`
	ICMPCount    uint64  `json:"icmp_count"`
	TotalPackets uint64  `json:"total_packets"`
	TotalBytes   uint64  `json:"total_bytes"`
}

// Metrics is the aggregated metrics snapshot exported via REST + Prometheus.
type Metrics struct {
	TotalPackets      uint64        `json:"total_packets"`
	TotalBytes        uint64        `json:"total_bytes"`
	DroppedPackets    uint64        `json:"dropped_packets"`
	PassedPackets     uint64        `json:"passed_packets"`
	SYNFloods         uint64        `json:"syn_floods"`
	UDPAmplifications uint64        `json:"udp_amplifications"`
	ICMPFloods        uint64        `json:"icmp_floods"`
	PPS               float64       `json:"pps"`
	BPS               float64       `json:"bps"`
	BlockedIPCount    int           `json:"blocked_ip_count"`
	TopAttackers      []AttackingIP `json:"top_attackers"`
	Timestamp         time.Time     `json:"timestamp"`
}

// Alert represents a security alert.
type Alert struct {
	ID        string    `json:"id"`
	Level     string    `json:"level"` // info, warning, critical
	Type      string    `json:"type"`  // syn_flood, udp_amp, icmp_flood
	Message   string    `json:"message"`
	SourceIP  string    `json:"source_ip"`
	Timestamp time.Time `json:"timestamp"`
}

// Config holds runtime-tunable parameters sent to the XDP program.
type Config struct {
	SYNRateLimit  uint64 `json:"syn_rate_limit"`
	UDPRateLimit  uint64 `json:"udp_rate_limit"`
	ICMPRateLimit uint64 `json:"icmp_rate_limit"`
	Enabled       bool   `json:"enabled"`
}

// ReasonString converts a numeric block reason to a human-readable string.
func ReasonString(r uint32) string {
	switch r {
	case 1:
		return "syn_flood"
	case 2:
		return "udp_amplification"
	case 3:
		return "icmp_flood"
	default:
		return "unknown"
	}
}
