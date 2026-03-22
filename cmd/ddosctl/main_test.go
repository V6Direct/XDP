package main

import (
	"testing"
)

// ─── humanNum ─────────────────────────────────────────────────────────────────

func TestHumanNum(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "0"},
		{999, "999"},
		{1000, "1.00K"},
		{1500, "1.50K"},
		{999999, "1000.00K"},
		{1_000_000, "1.00M"},
		{1_500_000, "1.50M"},
		{1_000_000_000, "1.00G"},
		{2_500_000_000, "2.50G"},
	}
	for _, tc := range cases {
		got := humanNum(tc.in)
		if got != tc.want {
			t.Errorf("humanNum(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ─── humanBits ────────────────────────────────────────────────────────────────

func TestHumanBits(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "0 bps"},
		{500, "500 bps"},
		{1500, "1.50 Kbps"},
		{1_500_000, "1.50 Mbps"},
		{1_500_000_000, "1.50 Gbps"},
		{1_500_000_000_000, "1.50 Tbps"},
	}
	for _, tc := range cases {
		got := humanBits(tc.in)
		if got != tc.want {
			t.Errorf("humanBits(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ─── humanBytes ───────────────────────────────────────────────────────────────

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1500, "1.50 KB"},
		{1_500_000, "1.50 MB"},
		{1_500_000_000, "1.50 GB"},
		{1_500_000_000_000, "1.50 TB"},
	}
	for _, tc := range cases {
		got := humanBytes(tc.in)
		if got != tc.want {
			t.Errorf("humanBytes(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ─── envOrDefault ─────────────────────────────────────────────────────────────

func TestEnvOrDefault(t *testing.T) {
	// Unset env var → return default
	got := envOrDefault("__DDOS_TEST_UNSET_VAR__", "mydefault")
	if got != "mydefault" {
		t.Errorf("got %q, want mydefault", got)
	}
}

// ─── humanNum boundary ────────────────────────────────────────────────────────

func TestHumanNumBoundaryExact(t *testing.T) {
	// Exactly 1K, 1M, 1G
	if got := humanNum(1000); got != "1.00K" {
		t.Errorf("1000 → %q, want 1.00K", got)
	}
	if got := humanNum(1_000_000); got != "1.00M" {
		t.Errorf("1M → %q, want 1.00M", got)
	}
	if got := humanNum(1_000_000_000); got != "1.00G" {
		t.Errorf("1G → %q, want 1.00G", got)
	}
}
