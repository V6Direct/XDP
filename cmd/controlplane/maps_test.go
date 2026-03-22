//go:build linux

package main

import (
	"net"
	"testing"
)

// ─── IP conversion helpers ────────────────────────────────────────────────────

func TestIPToUint32RoundTrip(t *testing.T) {
	cases := []string{
		"1.2.3.4",
		"192.168.100.200",
		"10.0.0.1",
		"255.255.255.255",
		"0.0.0.0",
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc).To4()
		if ip == nil {
			t.Fatalf("ParseIP(%q) returned nil", tc)
		}
		n := ipToUint32(ip)
		recovered := uint32ToIP(n)
		if recovered.String() != tc {
			t.Errorf("round-trip failed: input=%s got=%s (uint32=%d)", tc, recovered.String(), n)
		}
	}
}

func TestIPToUint32KnownValues(t *testing.T) {
	cases := []struct {
		ip   string
		want uint32
	}{
		{"0.0.0.0", 0x00000000},
		{"1.0.0.0", 0x01000000},
		{"255.255.255.255", 0xFFFFFFFF},
		{"192.168.1.1", 0xC0A80101},
		{"10.0.0.1", 0x0A000001},
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip).To4()
		got := ipToUint32(ip)
		if got != tc.want {
			t.Errorf("ipToUint32(%s): got 0x%08X, want 0x%08X", tc.ip, got, tc.want)
		}
	}
}

func TestUint32ToIPKnownValues(t *testing.T) {
	cases := []struct {
		n    uint32
		want string
	}{
		{0x00000000, "0.0.0.0"},
		{0x7F000001, "127.0.0.1"},
		{0xC0A80101, "192.168.1.1"},
		{0xFFFFFFFF, "255.255.255.255"},
	}
	for _, tc := range cases {
		got := uint32ToIP(tc.n).String()
		if got != tc.want {
			t.Errorf("uint32ToIP(0x%08X): got %s, want %s", tc.n, got, tc.want)
		}
	}
}

// ─── Struct size consistency ──────────────────────────────────────────────────

func TestSizeofIPStatsNonZero(t *testing.T) {
	s := sizeofIPStats()
	if s == 0 {
		t.Fatal("sizeofIPStats() returned 0 — struct is empty")
	}
	// 6 × uint64 + 2 × uint32 = 48 + 8 = 56 bytes
	const expected = 56
	if s != expected {
		t.Errorf("sizeofIPStats() = %d, want %d (layout mismatch with BPF struct)", s, expected)
	}
}

func TestMetricsSizeNonZero(t *testing.T) {
	s := metricsSize()
	if s == 0 {
		t.Fatal("metricsSize() returned 0")
	}
}
