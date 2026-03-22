// Package reputation implements automatic IP blocklist synchronisation from
// public threat-intelligence feeds.  It periodically downloads feed files,
// parses CIDR/IP lists, and calls the provided block function for each entry.
//
// Supported feed formats:
//   - Plain text: one IP or CIDR per line (comments with # ignored)
//   - Emerging Threats / Spamhaus DROP style
package reputation

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nsp/ddos-platform/pkg/logger"
)

// Feed describes a remote threat-intelligence IP blocklist.
type Feed struct {
	Name     string        // human-readable label
	URL      string        // HTTP(S) URL
	Interval time.Duration // refresh interval (minimum 5 minutes)
	Enabled  bool
}

// BlockFunc is called for each IP discovered in a feed.
// The implementation should add the IP to the BPF blocked_ips map.
type BlockFunc func(ip string, reason uint32) error

// Manager downloads and applies reputation feeds.
type Manager struct {
	feeds      []Feed
	blockFn    BlockFunc
	log        *logger.Logger
	client     *http.Client
	mu         sync.RWMutex
	loaded     map[string]time.Time // feed URL → last successful load
	ipCount    map[string]int       // feed URL → IPs loaded
	stopCh     chan struct{}
	noStagger  bool       // skip startup stagger delay (for testing)
	stopOnce   sync.Once // ensures Stop() is idempotent
}

// Option is a functional option for Manager.
type Option func(*Manager)

// WithNoStagger disables the startup stagger delay between feeds.
// Use this in tests to make feeds load immediately on Start().
func WithNoStagger() Option {
	return func(m *Manager) { m.noStagger = true }
}

// DefaultFeeds contains well-known public IP blocklists.
var DefaultFeeds = []Feed{
	{
		Name:     "Spamhaus DROP",
		URL:      "https://www.spamhaus.org/drop/drop.txt",
		Interval: 4 * time.Hour,
		Enabled:  true,
	},
	{
		Name:     "Emerging Threats Compromised IPs",
		URL:      "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
		Interval: 2 * time.Hour,
		Enabled:  true,
	},
	{
		Name:     "DigitalSide OSINT",
		URL:      "https://osint.digitalside.it/Threat-Intel/lists/latestips.txt",
		Interval: 1 * time.Hour,
		Enabled:  true,
	},
}

// NewManager creates a reputation Manager.
func NewManager(feeds []Feed, blockFn BlockFunc, log *logger.Logger, opts ...Option) *Manager {
	if log == nil {
		log = logger.Default
	}
	m := &Manager{
		feeds:   feeds,
		blockFn: blockFn,
		log:     log.With("component", "reputation"),
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:       10,
				IdleConnTimeout:    90 * time.Second,
				DisableCompression: false,
			},
		},
		loaded:  make(map[string]time.Time),
		ipCount: make(map[string]int),
		stopCh:  make(chan struct{}),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Start begins background feed refresh goroutines.
func (m *Manager) Start(ctx context.Context) {
	for _, feed := range m.feeds {
		if !feed.Enabled {
			m.log.Info("feed disabled", "name", feed.Name)
			continue
		}
		interval := feed.Interval
		if interval < 5*time.Minute {
			interval = 5 * time.Minute
		}
		go m.runFeed(ctx, feed, interval)
	}
}

// Stop signals all feed goroutines to exit. Safe to call multiple times.
func (m *Manager) Stop() {
	m.stopOnce.Do(func() { close(m.stopCh) })
}

// Stats returns a snapshot of feed load times and IP counts.
func (m *Manager) Stats() map[string]FeedStat {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]FeedStat, len(m.feeds))
	for _, f := range m.feeds {
		out[f.Name] = FeedStat{
			LastLoaded: m.loaded[f.URL],
			IPCount:    m.ipCount[f.URL],
			Enabled:    f.Enabled,
		}
	}
	return out
}

// FeedStat holds runtime statistics for a single feed.
type FeedStat struct {
	LastLoaded time.Time
	IPCount    int
	Enabled    bool
}

// ─── Internal ─────────────────────────────────────────────────────────────────

func (m *Manager) runFeed(ctx context.Context, feed Feed, interval time.Duration) {
	// Stagger initial loads to avoid thundering herd on startup.
	// Skipped when noStagger is set (e.g. in tests).
	if !m.noStagger {
		startDelay := time.Duration(hashString(feed.URL)%60) * time.Second
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-time.After(startDelay):
		}
	}

	// Load immediately on first run
	m.loadFeed(ctx, feed)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.loadFeed(ctx, feed)
		}
	}
}

func (m *Manager) loadFeed(ctx context.Context, feed Feed) {
	m.log.Info("loading feed", "name", feed.Name, "url", feed.URL)
	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feed.URL, nil)
	if err != nil {
		m.log.Error("create request failed", "name", feed.Name, "err", err.Error())
		return
	}
	req.Header.Set("User-Agent", "DDoS-Mitigation-Platform/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		m.log.Warn("feed fetch failed", "name", feed.Name, "err", err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		m.log.Warn("feed non-200", "name", feed.Name, "status", resp.StatusCode)
		return
	}

	count, err := m.parseFeed(resp.Body)
	if err != nil {
		m.log.Error("parse feed failed", "name", feed.Name, "err", err.Error())
		return
	}

	m.mu.Lock()
	m.loaded[feed.URL] = time.Now()
	m.ipCount[feed.URL] = count
	m.mu.Unlock()

	m.log.Info("feed loaded",
		"name", feed.Name,
		"ips", count,
		"duration_ms", time.Since(start).Milliseconds(),
	)
}

// parseFeed reads a plain-text IP/CIDR feed and calls blockFn for each entry.
// Returns the number of IPs successfully processed.
func (m *Manager) parseFeed(r io.Reader) (int, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1<<20), 1<<20) // 1 MB buffer

	count := 0
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Strip inline comments (e.g. "1.2.3.0/24 ; SBL123456")
		if idx := strings.IndexAny(line, "#;"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		if line == "" {
			continue
		}

		// Try to parse as CIDR or plain IP
		ip, err := parseIPOrCIDR(line)
		if err != nil {
			// Non-fatal: skip malformed lines
			m.log.Debug("skip malformed line", "line_num", lineNum, "line", line)
			continue
		}

		if err := m.blockFn(ip, 4); err != nil { // reason 4 = reputation feed
			m.log.Warn("block failed", "ip", ip, "err", err.Error())
			continue
		}
		count++
	}

	if err := scanner.Err(); err != nil {
		return count, fmt.Errorf("scanner: %w", err)
	}
	return count, nil
}

// parseIPOrCIDR extracts a host IP from a plain IP or the network address of a CIDR.
func parseIPOrCIDR(s string) (string, error) {
	// Try CIDR first
	if strings.Contains(s, "/") {
		ip, _, err := net.ParseCIDR(s)
		if err != nil {
			return "", fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
		return ip.String(), nil
	}
	// Plain IP
	ip := net.ParseIP(s)
	if ip == nil {
		return "", fmt.Errorf("invalid IP %q", s)
	}
	if ip.To4() == nil {
		return "", fmt.Errorf("IPv6 not supported: %q", s)
	}
	return ip.String(), nil
}

// hashString produces a simple deterministic hash for stagger calculation.
func hashString(s string) uint64 {
	var h uint64 = 14695981039346656037
	for _, c := range []byte(s) {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}
