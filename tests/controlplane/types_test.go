package types_test

import (
	"encoding/json"
	"testing"
	"time"
	"unsafe"

	"github.com/nsp/ddos-platform/pkg/types"
)

// ─── Struct layout / size assertions ─────────────────────────────────────────

// TestIPStatsSize asserts the Go struct exactly matches the C BPF struct size.
// C layout: 6×__u64 + 2×__u32 = 48 + 8 = 56 bytes.
func TestIPStatsSize(t *testing.T) {
	const want = 56
	got := int(unsafe.Sizeof(types.IPStats{}))
	if got != want {
		t.Errorf("IPStats size = %d bytes, want %d — BPF layout mismatch", got, want)
	}
}

// TestGlobalStatsSize asserts: 8×__u64 = 64 bytes.
func TestGlobalStatsSize(t *testing.T) {
	const want = 64
	got := int(unsafe.Sizeof(types.GlobalStats{}))
	if got != want {
		t.Errorf("GlobalStats size = %d bytes, want %d — BPF layout mismatch", got, want)
	}
}

// TestBlockedEntrySize asserts: 1×__u64 + 2×__u32 = 8 + 8 = 16 bytes.
func TestBlockedEntrySize(t *testing.T) {
	const want = 16
	got := int(unsafe.Sizeof(types.BlockedEntry{}))
	if got != want {
		t.Errorf("BlockedEntry size = %d bytes, want %d — BPF layout mismatch", got, want)
	}
}

// ─── Field offset assertions ──────────────────────────────────────────────────
// These catch silent reordering which would corrupt BPF reads.

func TestIPStatsFieldOffsets(t *testing.T) {
	var s types.IPStats
	base := uintptr(unsafe.Pointer(&s))

	offsets := map[string]uintptr{
		"SYNCount":      uintptr(unsafe.Pointer(&s.SYNCount)) - base,
		"UDPCount":      uintptr(unsafe.Pointer(&s.UDPCount)) - base,
		"ICMPCount":     uintptr(unsafe.Pointer(&s.ICMPCount)) - base,
		"TotalPackets":  uintptr(unsafe.Pointer(&s.TotalPackets)) - base,
		"TotalBytes":    uintptr(unsafe.Pointer(&s.TotalBytes)) - base,
		"WindowStartNS": uintptr(unsafe.Pointer(&s.WindowStartNS)) - base,
		"Blocked":       uintptr(unsafe.Pointer(&s.Blocked)) - base,
		"Pad":           uintptr(unsafe.Pointer(&s.Pad)) - base,
	}
	want := map[string]uintptr{
		"SYNCount":      0,
		"UDPCount":      8,
		"ICMPCount":     16,
		"TotalPackets":  24,
		"TotalBytes":    32,
		"WindowStartNS": 40,
		"Blocked":       48,
		"Pad":           52,
	}
	for field, wantOffset := range want {
		gotOffset := offsets[field]
		if gotOffset != wantOffset {
			t.Errorf("IPStats.%s offset = %d, want %d (BPF struct offset mismatch)",
				field, gotOffset, wantOffset)
		}
	}
}

func TestGlobalStatsFieldOffsets(t *testing.T) {
	var s types.GlobalStats
	base := uintptr(unsafe.Pointer(&s))

	check := func(name string, got, want uintptr) {
		t.Helper()
		if got != want {
			t.Errorf("GlobalStats.%s offset = %d, want %d", name, got, want)
		}
	}
	check("TotalPackets",      uintptr(unsafe.Pointer(&s.TotalPackets))-base,      0)
	check("TotalBytes",        uintptr(unsafe.Pointer(&s.TotalBytes))-base,        8)
	check("DroppedPackets",    uintptr(unsafe.Pointer(&s.DroppedPackets))-base,    16)
	check("SYNFloods",         uintptr(unsafe.Pointer(&s.SYNFloods))-base,         24)
	check("UDPAmplifications", uintptr(unsafe.Pointer(&s.UDPAmplifications))-base, 32)
	check("ICMPFloods",        uintptr(unsafe.Pointer(&s.ICMPFloods))-base,        40)
	check("PassedPackets",     uintptr(unsafe.Pointer(&s.PassedPackets))-base,     48)
	check("Pad",               uintptr(unsafe.Pointer(&s.Pad))-base,               56)
}

func TestBlockedEntryFieldOffsets(t *testing.T) {
	var s types.BlockedEntry
	base := uintptr(unsafe.Pointer(&s))

	gotAt := uintptr(unsafe.Pointer(&s.BlockedAtNS)) - base
	gotReason := uintptr(unsafe.Pointer(&s.Reason)) - base
	gotPad := uintptr(unsafe.Pointer(&s.Pad)) - base

	if gotAt != 0 {
		t.Errorf("BlockedEntry.BlockedAtNS offset = %d, want 0", gotAt)
	}
	if gotReason != 8 {
		t.Errorf("BlockedEntry.Reason offset = %d, want 8", gotReason)
	}
	if gotPad != 12 {
		t.Errorf("BlockedEntry.Pad offset = %d, want 12", gotPad)
	}
}

// ─── JSON serialisation ───────────────────────────────────────────────────────

func TestMetricsJSONRoundTrip(t *testing.T) {
	original := types.Metrics{
		TotalPackets:      1_000_000,
		TotalBytes:        64_000_000,
		DroppedPackets:    5_000,
		PassedPackets:     995_000,
		SYNFloods:         12,
		UDPAmplifications: 3,
		ICMPFloods:        7,
		PPS:               99_500.5,
		BPS:               512_000_000.0,
		BlockedIPCount:    42,
		TopAttackers: []types.AttackingIP{
			{IP: "1.2.3.4", PPS: 10_000, SYNCount: 500},
		},
		Timestamp: time.Now().Truncate(time.Second),
	}

	b, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded types.Metrics
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.TotalPackets != original.TotalPackets {
		t.Errorf("TotalPackets: got %d, want %d", decoded.TotalPackets, original.TotalPackets)
	}
	if decoded.DroppedPackets != original.DroppedPackets {
		t.Errorf("DroppedPackets: got %d, want %d", decoded.DroppedPackets, original.DroppedPackets)
	}
	if decoded.PPS != original.PPS {
		t.Errorf("PPS: got %f, want %f", decoded.PPS, original.PPS)
	}
	if decoded.BlockedIPCount != original.BlockedIPCount {
		t.Errorf("BlockedIPCount: got %d, want %d", decoded.BlockedIPCount, original.BlockedIPCount)
	}
	if len(decoded.TopAttackers) != 1 || decoded.TopAttackers[0].IP != "1.2.3.4" {
		t.Errorf("TopAttackers mismatch: %+v", decoded.TopAttackers)
	}
}

func TestMetricsJSONFieldNames(t *testing.T) {
	m := types.Metrics{
		TotalPackets:      1,
		SYNFloods:         2,
		UDPAmplifications: 3,
		ICMPFloods:        4,
		BlockedIPCount:    5,
	}
	b, _ := json.Marshal(m)
	s := string(b)

	required := []string{
		`"total_packets"`,
		`"dropped_packets"`,
		`"passed_packets"`,
		`"syn_floods"`,
		`"udp_amplifications"`,
		`"icmp_floods"`,
		`"pps"`,
		`"bps"`,
		`"blocked_ip_count"`,
		`"top_attackers"`,
		`"timestamp"`,
	}
	for _, key := range required {
		found := false
		for i := 0; i < len(s)-len(key)+1; i++ {
			if s[i:i+len(key)] == key {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("JSON key %s not found in: %s", key, s)
		}
	}
}

func TestAlertJSONFieldNames(t *testing.T) {
	a := types.Alert{
		Level:    "critical",
		Type:     "syn_flood",
		Message:  "test",
		SourceIP: "1.2.3.4",
	}
	b, _ := json.Marshal(a)
	s := string(b)

	for _, key := range []string{`"level"`, `"type"`, `"message"`, `"source_ip"`, `"timestamp"`} {
		found := false
		for i := 0; i < len(s)-len(key)+1; i++ {
			if s[i:i+len(key)] == key {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Alert JSON key %s missing from: %s", key, s)
		}
	}
}

// ─── ReasonString ─────────────────────────────────────────────────────────────

func TestReasonString(t *testing.T) {
	cases := []struct {
		in   uint32
		want string
	}{
		{1, "syn_flood"},
		{2, "udp_amplification"},
		{3, "icmp_flood"},
		{0, "unknown"},
		{99, "unknown"},
	}
	for _, tc := range cases {
		got := types.ReasonString(tc.in)
		if got != tc.want {
			t.Errorf("ReasonString(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ─── Config JSON ──────────────────────────────────────────────────────────────

func TestConfigJSONRoundTrip(t *testing.T) {
	cfg := types.Config{
		SYNRateLimit:  2000,
		UDPRateLimit:  10000,
		ICMPRateLimit: 200,
		Enabled:       true,
	}
	b, _ := json.Marshal(cfg)
	var got types.Config
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	if got.SYNRateLimit != cfg.SYNRateLimit {
		t.Errorf("SYNRateLimit: got %d want %d", got.SYNRateLimit, cfg.SYNRateLimit)
	}
	if got.Enabled != cfg.Enabled {
		t.Errorf("Enabled: got %v want %v", got.Enabled, cfg.Enabled)
	}
}
