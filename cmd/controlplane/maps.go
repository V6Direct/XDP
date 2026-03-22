package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/nsp/ddos-platform/pkg/types"
)

// MapManager wraps BPF map interactions with thread-safe caching.
type MapManager struct {
	objs    *XDPObjects
	mu      sync.RWMutex
	cache   *types.Metrics
	lastPPS time.Time
	prevPkt uint64
	prevByt uint64
}

// NewMapManager creates a MapManager backed by loaded BPF objects.
func NewMapManager(objs *XDPObjects) *MapManager {
	return &MapManager{
		objs:    objs,
		cache:   &types.Metrics{},
		lastPPS: time.Now(),
	}
}

// ReadGlobalStats sums per-CPU global_stats_map values and returns aggregated stats.
func (m *MapManager) ReadGlobalStats() (*types.GlobalStats, error) {
	var key uint32 = 0

	// Per-CPU maps return one value per logical CPU
	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("possible CPUs: %w", err)
	}

	// Each value is a GlobalStats; size = numCPU * sizeof(GlobalStats)
	rawValues := make([]types.GlobalStats, numCPU)
	if err := m.objs.GlobalStats.Lookup(key, &rawValues); err != nil {
		return nil, fmt.Errorf("lookup global_stats: %w", err)
	}

	agg := &types.GlobalStats{}
	for _, v := range rawValues {
		agg.TotalPackets += v.TotalPackets
		agg.TotalBytes += v.TotalBytes
		agg.DroppedPackets += v.DroppedPackets
		agg.SYNFloods += v.SYNFloods
		agg.UDPAmplifications += v.UDPAmplifications
		agg.ICMPFloods += v.ICMPFloods
		agg.PassedPackets += v.PassedPackets
	}
	return agg, nil
}

// ListBlockedIPs returns all currently blocked IP entries.
func (m *MapManager) ListBlockedIPs() ([]types.BlockedIP, error) {
	var blocked []types.BlockedIP

	var key uint32
	var value types.BlockedEntry

	iter := m.objs.BlockedIPs.Iterate()
	for iter.Next(&key, &value) {
		ip := uint32ToIP(key)
		blocked = append(blocked, types.BlockedIP{
			IP:        ip.String(),
			Reason:    types.ReasonString(value.Reason),
			BlockedAt: time.Unix(0, int64(value.BlockedAtNS)),
		})
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate blocked_ips: %w", err)
	}
	return blocked, nil
}

// BlockIP manually adds an IP to the blocked map.
func (m *MapManager) BlockIP(ipStr string, reason uint32) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP: %s", ipStr)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 supported: %s", ipStr)
	}

	key := ipToUint32(ip4)
	value := types.BlockedEntry{
		BlockedAtNS: uint64(time.Now().UnixNano()),
		Reason:      reason,
	}
	return m.objs.BlockedIPs.Put(key, value)
}

// UnblockIP removes an IP from the blocked map.
func (m *MapManager) UnblockIP(ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP: %s", ipStr)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 supported: %s", ipStr)
	}
	key := ipToUint32(ip4)
	return m.objs.BlockedIPs.Delete(key)
}

// WhitelistIP adds an IP to the whitelist (bypass all filtering).
func (m *MapManager) WhitelistIP(ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP: %s", ipStr)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 supported: %s", ipStr)
	}
	key := ipToUint32(ip4)
	var val uint8 = 1
	return m.objs.WhitelistMap.Put(key, val)
}

// UnwhitelistIP removes an IP from the whitelist.
func (m *MapManager) UnwhitelistIP(ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP: %s", ipStr)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 supported: %s", ipStr)
	}
	key := ipToUint32(ip4)
	return m.objs.WhitelistMap.Delete(key)
}

// UpdateConfig writes runtime thresholds to the XDP config map.
func (m *MapManager) UpdateConfig(cfg types.Config) error {
	entries := map[uint32]uint64{
		0: cfg.SYNRateLimit,
		1: cfg.UDPRateLimit,
		2: cfg.ICMPRateLimit,
	}
	if cfg.Enabled {
		entries[3] = 1
	} else {
		entries[3] = 0
	}
	for k, v := range entries {
		if err := m.objs.ConfigMap.Put(k, v); err != nil {
			return fmt.Errorf("update config key %d: %w", k, err)
		}
	}
	return nil
}

// GetTopAttackers returns the top N IPs by total packet count.
func (m *MapManager) GetTopAttackers(n int) ([]types.AttackingIP, error) {
	type entry struct {
		ip    uint32
		stats types.IPStats
	}

	var entries []entry

	var key uint32
	var value types.IPStats

	iter := m.objs.IPStatsMap.Iterate()
	for iter.Next(&key, &value) {
		entries = append(entries, entry{ip: key, stats: value})
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate ip_stats: %w", err)
	}

	// Sort by total_packets descending
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].stats.TotalPackets > entries[j].stats.TotalPackets
	})

	if n > len(entries) {
		n = len(entries)
	}

	result := make([]types.AttackingIP, 0, n)
	for _, e := range entries[:n] {
		result = append(result, types.AttackingIP{
			IP:           uint32ToIP(e.ip).String(),
			TotalPackets: e.stats.TotalPackets,
			TotalBytes:   e.stats.TotalBytes,
			SYNCount:     e.stats.SYNCount,
			UDPCount:     e.stats.UDPCount,
			ICMPCount:    e.stats.ICMPCount,
		})
	}
	return result, nil
}

// CollectMetrics reads all maps and returns a full Metrics snapshot.
func (m *MapManager) CollectMetrics() (*types.Metrics, error) {
	gs, err := m.ReadGlobalStats()
	if err != nil {
		return nil, err
	}

	blocked, err := m.ListBlockedIPs()
	if err != nil {
		return nil, err
	}

	attackers, err := m.GetTopAttackers(20)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	elapsed := now.Sub(m.lastPPS).Seconds()
	if elapsed <= 0 {
		elapsed = 1
	}

	pps := float64(gs.TotalPackets-m.prevPkt) / elapsed
	bps := float64(gs.TotalBytes-m.prevByt) / elapsed * 8

	m.mu.Lock()
	m.prevPkt = gs.TotalPackets
	m.prevByt = gs.TotalBytes
	m.lastPPS = now
	m.mu.Unlock()

	metrics := &types.Metrics{
		TotalPackets:      gs.TotalPackets,
		TotalBytes:        gs.TotalBytes,
		DroppedPackets:    gs.DroppedPackets,
		PassedPackets:     gs.PassedPackets,
		SYNFloods:         gs.SYNFloods,
		UDPAmplifications: gs.UDPAmplifications,
		ICMPFloods:        gs.ICMPFloods,
		PPS:               pps,
		BPS:               bps,
		BlockedIPCount:    len(blocked),
		TopAttackers:      attackers,
		Timestamp:         now,
	}

	m.mu.Lock()
	m.cache = metrics
	m.mu.Unlock()

	return metrics, nil
}

// CachedMetrics returns the last collected metrics snapshot (thread-safe).
func (m *MapManager) CachedMetrics() *types.Metrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cache
}

// ─── IP conversion helpers ────────────────────────────────────────────────────

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return binary.BigEndian.Uint32(ip)
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

// sizeofIPStats returns the size of IPStats struct for BPF map value validation.
func sizeofIPStats() int {
	return int(unsafe.Sizeof(types.IPStats{}))
}
