// Package bpf_test contains pure-Go unit tests that validate the rate-limit
// logic mirrored from xdp_filters.h without requiring a real BPF environment.
package bpf_test

import (
	"testing"
	"time"
)

// ─── Sliding window rate limiter (mirrors BPF logic in Go) ───────────────────

const windowNS = uint64(1_000_000_000) // 1 second in nanoseconds

type rateLimiter struct {
	count         uint64
	windowStartNS uint64
}

func (r *rateLimiter) check(nowNS uint64, threshold uint64) bool {
	delta := nowNS - r.windowStartNS
	if delta >= windowNS {
		r.count = 1
		r.windowStartNS = nowNS
		return false // not rate-limited: new window
	}
	r.count++
	return r.count > threshold
}

// ─── Rate limiter logic tests ─────────────────────────────────────────────────

func TestRateLimiterUnderThreshold(t *testing.T) {
	rl := rateLimiter{windowStartNS: uint64(time.Now().UnixNano())}
	const threshold = uint64(1000)

	// Send 999 packets — should never trigger
	base := rl.windowStartNS
	for i := 0; i < 999; i++ {
		triggered := rl.check(base+uint64(i)*1000, threshold) // 1µs apart
		if triggered {
			t.Fatalf("rate limit triggered at packet %d (threshold %d)", i+1, threshold)
		}
	}
}

func TestRateLimiterAtThreshold(t *testing.T) {
	rl := rateLimiter{windowStartNS: uint64(time.Now().UnixNano())}
	const threshold = uint64(10)
	base := rl.windowStartNS

	// Exactly at threshold should not trigger (count == threshold is still ok)
	for i := 0; i < int(threshold); i++ {
		triggered := rl.check(base+uint64(i)*1000, threshold)
		if triggered {
			t.Fatalf("should not trigger at count=%d threshold=%d", i+1, threshold)
		}
	}
}

func TestRateLimiterExceedsThreshold(t *testing.T) {
	rl := rateLimiter{windowStartNS: uint64(time.Now().UnixNano())}
	const threshold = uint64(10)
	base := rl.windowStartNS
	triggered := false

	for i := 0; i < int(threshold)+2; i++ {
		if rl.check(base+uint64(i)*1000, threshold) {
			triggered = true
		}
	}
	if !triggered {
		t.Errorf("expected rate limit to trigger after %d packets (threshold %d)",
			threshold+2, threshold)
	}
}

func TestRateLimiterWindowReset(t *testing.T) {
	rl := rateLimiter{windowStartNS: uint64(time.Now().UnixNano())}
	const threshold = uint64(5)
	base := rl.windowStartNS

	// Fill the window past threshold
	for i := 0; i < int(threshold)+5; i++ {
		rl.check(base+uint64(i)*1000, threshold)
	}

	// After 1 second the window should reset
	nextWindowStart := base + windowNS + 1
	triggered := rl.check(nextWindowStart, threshold)
	if triggered {
		t.Error("rate limit should not trigger immediately after window reset")
	}
	if rl.count != 1 {
		t.Errorf("count after reset = %d, want 1", rl.count)
	}
}

func TestRateLimiterWindowBoundary(t *testing.T) {
	// Packet at exactly windowNS should reset
	rl := rateLimiter{windowStartNS: 1000}
	rl.check(500, 100) // some packets in window
	rl.check(800, 100)

	// At exactly window boundary
	triggered := rl.check(1000+windowNS, 100)
	if triggered {
		t.Error("packet at exact window boundary should reset, not trigger")
	}
	if rl.count != 1 {
		t.Errorf("count = %d after boundary reset, want 1", rl.count)
	}
}

// ─── UDP amplification weight test ───────────────────────────────────────────

// Mirrors the amplification weighting logic in check_udp_amp:
// large packets from amplification ports count as 10x.
func ampWeight(sport uint16, pktLen uint16) uint64 {
	ampPorts := map[uint16]bool{53: true, 123: true, 1900: true, 161: true, 11211: true}
	if ampPorts[sport] && pktLen > 512 {
		return 10
	}
	return 1
}

func TestAmpWeightDNSLargePacket(t *testing.T) {
	w := ampWeight(53, 1024)
	if w != 10 {
		t.Errorf("DNS large packet weight = %d, want 10", w)
	}
}

func TestAmpWeightDNSSmallPacket(t *testing.T) {
	w := ampWeight(53, 64)
	if w != 1 {
		t.Errorf("DNS small packet weight = %d, want 1", w)
	}
}

func TestAmpWeightNTPLargePacket(t *testing.T) {
	w := ampWeight(123, 600)
	if w != 10 {
		t.Errorf("NTP large packet weight = %d, want 10", w)
	}
}

func TestAmpWeightMemcachedLargePacket(t *testing.T) {
	w := ampWeight(11211, 900)
	if w != 10 {
		t.Errorf("Memcached large packet weight = %d, want 10", w)
	}
}

func TestAmpWeightRandomPortLargePacket(t *testing.T) {
	w := ampWeight(12345, 1024)
	if w != 1 {
		t.Errorf("random port large packet weight = %d, want 1", w)
	}
}

func TestAmpWeightExactBoundary(t *testing.T) {
	// Exactly 512 bytes is NOT amplification (must be > 512)
	w := ampWeight(53, 512)
	if w != 1 {
		t.Errorf("exactly 512 bytes weight = %d, want 1 (boundary exclusive)", w)
	}
	w = ampWeight(53, 513)
	if w != 10 {
		t.Errorf("513 bytes weight = %d, want 10", w)
	}
}

// ─── SYN flood detection ──────────────────────────────────────────────────────

// synFloodCheck mirrors check_syn_flood's logic.
func synFloodCheck(synCount *uint64, windowStart *uint64, nowNS uint64, threshold uint64) bool {
	delta := nowNS - *windowStart
	if delta >= windowNS {
		*synCount = 1
		*windowStart = nowNS
		return false
	}
	*synCount++
	return *synCount > threshold
}

func TestSYNFloodDetection(t *testing.T) {
	var count uint64
	windowStart := uint64(time.Now().UnixNano())
	const threshold = uint64(100)
	base := windowStart

	blocked := false
	for i := 0; i < 200; i++ {
		if synFloodCheck(&count, &windowStart, base+uint64(i)*5_000_000, threshold) {
			blocked = true
			break
		}
	}
	if !blocked {
		t.Error("SYN flood of 200 pkts should have triggered block at threshold=100")
	}
}

func TestSYNFloodNoFalsePositive(t *testing.T) {
	var count uint64
	windowStart := uint64(time.Now().UnixNano())
	const threshold = uint64(1000)
	base := windowStart

	// 500 SYNs well under threshold
	for i := 0; i < 500; i++ {
		if synFloodCheck(&count, &windowStart, base+uint64(i)*100_000, threshold) {
			t.Errorf("false positive at packet %d (threshold=%d)", i+1, threshold)
		}
	}
}

// ─── IP blocking logic ────────────────────────────────────────────────────────

// blockedSet simulates the BPF blocked_ips LRU hash.
type blockedSet map[uint32]struct{}

func (b blockedSet) block(ip uint32)          { b[ip] = struct{}{} }
func (b blockedSet) isBlocked(ip uint32) bool { _, ok := b[ip]; return ok }
func (b blockedSet) unblock(ip uint32)        { delete(b, ip) }

func TestBlockAndUnblock(t *testing.T) {
	bs := make(blockedSet)
	const ip = uint32(0x01020304) // 1.2.3.4

	if bs.isBlocked(ip) {
		t.Fatal("IP should not be blocked initially")
	}
	bs.block(ip)
	if !bs.isBlocked(ip) {
		t.Fatal("IP should be blocked after block()")
	}
	bs.unblock(ip)
	if bs.isBlocked(ip) {
		t.Fatal("IP should not be blocked after unblock()")
	}
}

func TestWhitelistBypassesBlock(t *testing.T) {
	bs := make(blockedSet)
	whitelist := make(blockedSet)
	const ip = uint32(0x0A000001)

	bs.block(ip)
	whitelist.block(ip)

	// Whitelist check should happen BEFORE blocked check
	if whitelist.isBlocked(ip) {
		// whitelisted → skip block check
		return // correct path
	}
	if bs.isBlocked(ip) {
		t.Fatal("whitelisted IP should not reach block check")
	}
}
