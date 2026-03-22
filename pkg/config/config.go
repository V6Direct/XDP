// Package config provides hot-reloadable runtime configuration for the
// DDoS platform.  Changes to thresholds are applied without restarting
// by calling Reload() or by watching a config file.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/nsp/ddos-platform/pkg/types"
)

// RuntimeConfig extends types.Config with operational parameters.
type RuntimeConfig struct {
	types.Config

	// API and server addresses
	APIAddr     string `json:"api_addr"`
	MetricsAddr string `json:"metrics_addr"`
	Interface   string `json:"interface"`

	// Log level: debug, info, warn, error
	LogLevel string `json:"log_level"`

	// Reputation feed settings
	ReputationFeeds []FeedConfig `json:"reputation_feeds"`

	// Max number of IPs to track (must match BPF map size)
	MaxTrackedIPs int `json:"max_tracked_ips"`

	// Block duration: 0 = permanent, >0 = auto-expire after N seconds
	BlockDurationSecs int `json:"block_duration_secs"`

	// JWT secret for web panel (empty = random)
	JWTSecret string `json:"jwt_secret,omitempty"`

	// Internal
	loadedAt time.Time `json:"-"`
	path     string    `json:"-"`
}

// FeedConfig describes a single reputation feed in the config file.
type FeedConfig struct {
	Name            string `json:"name"`
	URL             string `json:"url"`
	IntervalMinutes int    `json:"interval_minutes"`
	Enabled         bool   `json:"enabled"`
}

// Defaults returns a RuntimeConfig populated with production-safe defaults.
func Defaults() RuntimeConfig {
	return RuntimeConfig{
		Config: types.Config{
			SYNRateLimit:  1000,
			UDPRateLimit:  5000,
			ICMPRateLimit: 100,
			Enabled:       true,
		},
		APIAddr:           ":8080",
		MetricsAddr:       ":9090",
		Interface:         "eth0",
		LogLevel:          "info",
		MaxTrackedIPs:     65536,
		BlockDurationSecs: 0,
		ReputationFeeds:   []FeedConfig{},
	}
}

// Manager manages a RuntimeConfig with thread-safe access and hot-reload.
type Manager struct {
	mu      sync.RWMutex
	current RuntimeConfig
	path    string
	onChange []func(RuntimeConfig)
}

// NewManager creates a config Manager.  If path is non-empty, the config
// is loaded from that JSON file; otherwise defaults are used.
func NewManager(path string) (*Manager, error) {
	m := &Manager{
		current: Defaults(),
		path:    path,
	}
	if path != "" {
		if err := m.loadFile(path); err != nil {
			// Non-fatal: use defaults if file missing
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("load config %s: %w", path, err)
			}
		}
	}
	// Override from environment variables
	m.applyEnv()
	return m, nil
}

// Get returns a snapshot of the current configuration (thread-safe).
func (m *Manager) Get() RuntimeConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

// Set replaces the entire config atomically and notifies watchers.
func (m *Manager) Set(cfg RuntimeConfig) {
	m.mu.Lock()
	cfg.loadedAt = time.Now()
	m.current = cfg
	callbacks := make([]func(RuntimeConfig), len(m.onChange))
	copy(callbacks, m.onChange)
	m.mu.Unlock()

	for _, fn := range callbacks {
		fn(cfg)
	}
}

// Update applies a mutation function to the current config atomically.
func (m *Manager) Update(fn func(*RuntimeConfig)) {
	m.mu.Lock()
	cfg := m.current
	fn(&cfg)
	cfg.loadedAt = time.Now()
	m.current = cfg
	callbacks := make([]func(RuntimeConfig), len(m.onChange))
	copy(callbacks, m.onChange)
	m.mu.Unlock()

	for _, cb := range callbacks {
		cb(cfg)
	}
}

// Reload re-reads the config file and applies changes.
func (m *Manager) Reload() error {
	if m.path == "" {
		return fmt.Errorf("no config file path set")
	}
	return m.loadFile(m.path)
}

// OnChange registers a callback invoked whenever the config changes.
func (m *Manager) OnChange(fn func(RuntimeConfig)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onChange = append(m.onChange, fn)
}

// Save writes the current config to the file at path.
func (m *Manager) Save(path string) error {
	m.mu.RLock()
	cfg := m.current
	m.mu.RUnlock()

	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return os.WriteFile(path, b, 0640)
}

// Validate returns an error if the config has invalid values.
func (cfg RuntimeConfig) Validate() error {
	if cfg.SYNRateLimit == 0 {
		return fmt.Errorf("syn_rate_limit must be > 0")
	}
	if cfg.UDPRateLimit == 0 {
		return fmt.Errorf("udp_rate_limit must be > 0")
	}
	if cfg.ICMPRateLimit == 0 {
		return fmt.Errorf("icmp_rate_limit must be > 0")
	}
	if cfg.Interface == "" {
		return fmt.Errorf("interface must not be empty")
	}
	if cfg.MaxTrackedIPs <= 0 {
		return fmt.Errorf("max_tracked_ips must be > 0")
	}
	for i, f := range cfg.ReputationFeeds {
		if f.Name == "" {
			return fmt.Errorf("reputation_feeds[%d].name must not be empty", i)
		}
		if f.URL == "" {
			return fmt.Errorf("reputation_feeds[%d].url must not be empty", i)
		}
	}
	return nil
}

// ─── Internal ─────────────────────────────────────────────────────────────────

func (m *Manager) loadFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// Start from defaults, then overlay file values
	cfg := Defaults()
	if err := json.Unmarshal(b, &cfg); err != nil {
		return fmt.Errorf("parse JSON: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("validate: %w", err)
	}
	cfg.loadedAt = time.Now()
	cfg.path = path

	m.mu.Lock()
	m.current = cfg
	callbacks := make([]func(RuntimeConfig), len(m.onChange))
	copy(callbacks, m.onChange)
	m.mu.Unlock()

	for _, fn := range callbacks {
		fn(cfg)
	}
	return nil
}

// applyEnv overrides config fields from well-known environment variables.
func (m *Manager) applyEnv() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if v := os.Getenv("DDOS_IFACE"); v != "" {
		m.current.Interface = v
	}
	if v := os.Getenv("DDOS_API_ADDR"); v != "" {
		m.current.APIAddr = v
	}
	if v := os.Getenv("DDOS_METRICS_ADDR"); v != "" {
		m.current.MetricsAddr = v
	}
	if v := os.Getenv("DDOS_LOG_LEVEL"); v != "" {
		m.current.LogLevel = v
	}
	if v := os.Getenv("JWT_SECRET"); v != "" {
		m.current.JWTSecret = v
	}
}
