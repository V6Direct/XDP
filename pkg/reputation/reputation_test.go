package reputation_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nsp/ddos-platform/pkg/reputation"
)

// ─── Test helpers ─────────────────────────────────────────────────────────────

func feedServer(body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(body))
	}))
}

func feedServerStatus(status int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
}

// ─── parseFeed via loadFeed with mock server ──────────────────────────────────

func TestLoadFeedBasicIPs(t *testing.T) {
	body := `# Threat feed
1.2.3.4
5.6.7.8
10.0.0.1
`
	srv := feedServer(body)
	defer srv.Close()

	var blocked []string
	blockFn := func(ip string, _ uint32) error {
		blocked = append(blocked, ip)
		return nil
	}

	feeds := []reputation.Feed{{
		Name:     "test",
		URL:      srv.URL,
		Interval: time.Hour,
		Enabled:  true,
	}}

	mgr := reputation.NewManager(feeds, blockFn, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mgr.Start(ctx)
	time.Sleep(200 * time.Millisecond)
	mgr.Stop()

	if len(blocked) != 3 {
		t.Errorf("expected 3 blocked IPs, got %d: %v", len(blocked), blocked)
	}
}

func TestLoadFeedWithCIDR(t *testing.T) {
	body := `192.168.0.0/16
10.0.0.0/8
`
	srv := feedServer(body)
	defer srv.Close()

	var count int32
	blockFn := func(_ string, _ uint32) error {
		atomic.AddInt32(&count, 1)
		return nil
	}

	feeds := []reputation.Feed{{Name: "cidr-test", URL: srv.URL, Interval: time.Hour, Enabled: true}}
	mgr := reputation.NewManager(feeds, blockFn, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mgr.Start(ctx)
	time.Sleep(200 * time.Millisecond)
	mgr.Stop()

	if atomic.LoadInt32(&count) != 2 {
		t.Errorf("expected 2 CIDR network addresses blocked, got %d", count)
	}
}

func TestLoadFeedSkipsComments(t *testing.T) {
	body := `# This is a comment
; Also a comment
1.2.3.4  # inline comment
# 5.6.7.8 - commented out IP

2.3.4.5
`
	srv := feedServer(body)
	defer srv.Close()

	var blocked []string
	blockFn := func(ip string, _ uint32) error {
		blocked = append(blocked, ip)
		return nil
	}

	feeds := []reputation.Feed{{Name: "comment-test", URL: srv.URL, Interval: time.Hour, Enabled: true}}
	mgr := reputation.NewManager(feeds, blockFn, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mgr.Start(ctx)
	time.Sleep(200 * time.Millisecond)
	mgr.Stop()

	// Should only block 1.2.3.4 and 2.3.4.5 (not the commented-out 5.6.7.8)
	if len(blocked) != 2 {
		t.Errorf("expected 2 blocked, got %d: %v", len(blocked), blocked)
	}
	for _, ip := range blocked {
		if ip == "5.6.7.8" {
			t.Error("commented-out IP 5.6.7.8 should not be blocked")
		}
	}
}

func TestLoadFeedSkipsIPv6(t *testing.T) {
	body := `1.2.3.4
::1
2001:db8::1
5.6.7.8
`
	srv := feedServer(body)
	defer srv.Close()

	var blocked []string
	blockFn := func(ip string, _ uint32) error {
		blocked = append(blocked, ip)
		return nil
	}

	feeds := []reputation.Feed{{Name: "ipv6-test", URL: srv.URL, Interval: time.Hour, Enabled: true}}
	mgr := reputation.NewManager(feeds, blockFn, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mgr.Start(ctx)
	time.Sleep(200 * time.Millisecond)
	mgr.Stop()

	if len(blocked) != 2 {
		t.Errorf("expected 2 IPv4 IPs, got %d: %v", len(blocked), blocked)
	}
}

func TestLoadFeedDisabled(t *testing.T) {
	srv := feedServer("1.2.3.4\n5.6.7.8\n")
	defer srv.Close()

	var count int32
	blockFn := func(_ string, _ uint32) error {
		atomic.AddInt32(&count, 1)
		return nil
	}

	feeds := []reputation.Feed{{
		Name:     "disabled-feed",
		URL:      srv.URL,
		Interval: time.Hour,
		Enabled:  false, // disabled
	}}

	mgr := reputation.NewManager(feeds, blockFn, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	mgr.Start(ctx)
	time.Sleep(300 * time.Millisecond)
	mgr.Stop()

	if atomic.LoadInt32(&count) != 0 {
		t.Errorf("disabled feed should not block any IPs, got %d", count)
	}
}

func TestFeedNon200(t *testing.T) {
	srv := feedServerStatus(http.StatusForbidden)
	defer srv.Close()

	var count int32
	blockFn := func(_ string, _ uint32) error { atomic.AddInt32(&count, 1); return nil }

	feeds := []reputation.Feed{{Name: "403-feed", URL: srv.URL, Interval: time.Hour, Enabled: true}}
	mgr := reputation.NewManager(feeds, blockFn, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	mgr.Start(ctx)
	time.Sleep(500 * time.Millisecond)
	mgr.Stop()

	if atomic.LoadInt32(&count) != 0 {
		t.Errorf("403 response should not produce blocks, got %d", count)
	}
}

func TestManagerStats(t *testing.T) {
	body := "1.2.3.4\n5.6.7.8\n"
	srv := feedServer(body)
	defer srv.Close()

	blockFn := func(_ string, _ uint32) error { return nil }
	feeds := []reputation.Feed{{Name: "stats-test", URL: srv.URL, Interval: time.Hour, Enabled: true}}
	mgr := reputation.NewManager(feeds, blockFn, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	mgr.Start(ctx)
	time.Sleep(500 * time.Millisecond)
	mgr.Stop()

	stats := mgr.Stats()
	stat, ok := stats["stats-test"]
	if !ok {
		t.Fatal("stats-test feed not found in Stats()")
	}
	if stat.IPCount != 2 {
		t.Errorf("IPCount = %d, want 2", stat.IPCount)
	}
	if stat.LastLoaded.IsZero() {
		t.Error("LastLoaded should not be zero after successful load")
	}
	if !stat.Enabled {
		t.Error("feed should be enabled")
	}
}

func TestHashStringDeterministic(t *testing.T) {
	// Two identical URLs must produce the same stagger
	// We test this indirectly: same URL feeds → same behavior
	// The hash is internal, but we can verify start stagger doesn't panic
	feeds := make([]reputation.Feed, 5)
	for i := range feeds {
		feeds[i] = reputation.Feed{
			Name:     fmt.Sprintf("feed-%d", i),
			URL:      "http://localhost/feed",
			Interval: time.Hour,
			Enabled:  false, // disabled so no actual HTTP
		}
	}
	mgr := reputation.NewManager(feeds, func(string, uint32) error { return nil }, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	mgr.Start(ctx) // should not panic
	mgr.Stop()
}
