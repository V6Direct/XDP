package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/nsp/ddos-platform/pkg/config"
)

func writeTempConfig(t *testing.T, cfg config.RuntimeConfig) string {
	t.Helper()
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, b, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// ─── Defaults ─────────────────────────────────────────────────────────────────

func TestDefaultsAreValid(t *testing.T) {
	cfg := config.Defaults()
	if err := cfg.Validate(); err != nil {
		t.Errorf("defaults are invalid: %v", err)
	}
}

func TestDefaultValues(t *testing.T) {
	cfg := config.Defaults()
	if cfg.SYNRateLimit != 1000 {
		t.Errorf("SYNRateLimit = %d, want 1000", cfg.SYNRateLimit)
	}
	if cfg.UDPRateLimit != 5000 {
		t.Errorf("UDPRateLimit = %d, want 5000", cfg.UDPRateLimit)
	}
	if cfg.ICMPRateLimit != 100 {
		t.Errorf("ICMPRateLimit = %d, want 100", cfg.ICMPRateLimit)
	}
	if !cfg.Enabled {
		t.Error("Enabled should default to true")
	}
	if cfg.Interface != "eth0" {
		t.Errorf("Interface = %q, want eth0", cfg.Interface)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want info", cfg.LogLevel)
	}
}

// ─── NewManager ───────────────────────────────────────────────────────────────

func TestNewManagerNoFile(t *testing.T) {
	mgr, err := config.NewManager("")
	if err != nil {
		t.Fatalf("NewManager empty path: %v", err)
	}
	cfg := mgr.Get()
	if err := cfg.Validate(); err != nil {
		t.Errorf("config from empty path invalid: %v", err)
	}
}

func TestNewManagerMissingFile(t *testing.T) {
	// Missing file should not error (falls back to defaults)
	mgr, err := config.NewManager("/tmp/does-not-exist-ddos-test.json")
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if mgr == nil {
		t.Fatal("manager should not be nil")
	}
}

func TestNewManagerFromFile(t *testing.T) {
	cfg := config.Defaults()
	cfg.SYNRateLimit = 2500
	cfg.Interface = "eth1"
	path := writeTempConfig(t, cfg)

	mgr, err := config.NewManager(path)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	got := mgr.Get()
	if got.SYNRateLimit != 2500 {
		t.Errorf("SYNRateLimit = %d, want 2500", got.SYNRateLimit)
	}
	if got.Interface != "eth1" {
		t.Errorf("Interface = %q, want eth1", got.Interface)
	}
}

// ─── Set / Get ────────────────────────────────────────────────────────────────

func TestSetGet(t *testing.T) {
	mgr, _ := config.NewManager("")
	cfg := config.Defaults()
	cfg.SYNRateLimit = 9999
	mgr.Set(cfg)

	got := mgr.Get()
	if got.SYNRateLimit != 9999 {
		t.Errorf("SYNRateLimit = %d, want 9999", got.SYNRateLimit)
	}
}

func TestUpdatePartial(t *testing.T) {
	mgr, _ := config.NewManager("")
	mgr.Update(func(c *config.RuntimeConfig) {
		c.ICMPRateLimit = 42
	})
	if mgr.Get().ICMPRateLimit != 42 {
		t.Errorf("ICMPRateLimit = %d, want 42", mgr.Get().ICMPRateLimit)
	}
	// Other fields should remain at defaults
	if mgr.Get().SYNRateLimit != 1000 {
		t.Errorf("SYNRateLimit = %d, want 1000 (should not change)", mgr.Get().SYNRateLimit)
	}
}

// ─── OnChange ─────────────────────────────────────────────────────────────────

func TestOnChangeCalled(t *testing.T) {
	mgr, _ := config.NewManager("")

	var calls int32
	mgr.OnChange(func(c config.RuntimeConfig) {
		atomic.AddInt32(&calls, 1)
	})

	mgr.Set(config.Defaults())
	mgr.Set(config.Defaults())

	if atomic.LoadInt32(&calls) != 2 {
		t.Errorf("OnChange called %d times, want 2", calls)
	}
}

func TestOnChangeReceivesNewValues(t *testing.T) {
	mgr, _ := config.NewManager("")

	var received uint64
	mgr.OnChange(func(c config.RuntimeConfig) {
		atomic.StoreUint64(&received, c.SYNRateLimit)
	})

	cfg := config.Defaults()
	cfg.SYNRateLimit = 77777
	mgr.Set(cfg)

	if atomic.LoadUint64(&received) != 77777 {
		t.Errorf("OnChange received SYNRateLimit = %d, want 77777", received)
	}
}

// ─── Reload ───────────────────────────────────────────────────────────────────

func TestReload(t *testing.T) {
	cfg := config.Defaults()
	cfg.SYNRateLimit = 1111
	path := writeTempConfig(t, cfg)

	mgr, err := config.NewManager(path)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if mgr.Get().SYNRateLimit != 1111 {
		t.Fatalf("initial SYNRateLimit = %d", mgr.Get().SYNRateLimit)
	}

	// Write updated config to file
	cfg.SYNRateLimit = 2222
	b, _ := json.MarshalIndent(cfg, "", "  ")
	_ = os.WriteFile(path, b, 0644)

	if err := mgr.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if mgr.Get().SYNRateLimit != 2222 {
		t.Errorf("after reload SYNRateLimit = %d, want 2222", mgr.Get().SYNRateLimit)
	}
}

func TestReloadNoPathErrors(t *testing.T) {
	mgr, _ := config.NewManager("")
	err := mgr.Reload()
	if err == nil {
		t.Error("Reload with no path should return error")
	}
}

// ─── Validate ─────────────────────────────────────────────────────────────────

func TestValidateZeroSYN(t *testing.T) {
	cfg := config.Defaults()
	cfg.SYNRateLimit = 0
	if err := cfg.Validate(); err == nil {
		t.Error("zero SYNRateLimit should be invalid")
	}
}

func TestValidateEmptyInterface(t *testing.T) {
	cfg := config.Defaults()
	cfg.Interface = ""
	if err := cfg.Validate(); err == nil {
		t.Error("empty interface should be invalid")
	}
}

func TestValidateZeroMaxTrackedIPs(t *testing.T) {
	cfg := config.Defaults()
	cfg.MaxTrackedIPs = 0
	if err := cfg.Validate(); err == nil {
		t.Error("zero MaxTrackedIPs should be invalid")
	}
}

func TestValidateInvalidFeedMissingURL(t *testing.T) {
	cfg := config.Defaults()
	cfg.ReputationFeeds = []config.FeedConfig{{Name: "test", URL: "", Enabled: true}}
	if err := cfg.Validate(); err == nil {
		t.Error("feed with empty URL should be invalid")
	}
}

// ─── Save ─────────────────────────────────────────────────────────────────────

func TestSaveAndReload(t *testing.T) {
	mgr, _ := config.NewManager("")
	mgr.Update(func(c *config.RuntimeConfig) {
		c.SYNRateLimit = 8888
		c.Interface = "bond0"
	})

	path := filepath.Join(t.TempDir(), "saved.json")
	if err := mgr.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	mgr2, err := config.NewManager(path)
	if err != nil {
		t.Fatalf("NewManager from saved: %v", err)
	}
	got := mgr2.Get()
	if got.SYNRateLimit != 8888 {
		t.Errorf("SYNRateLimit = %d, want 8888", got.SYNRateLimit)
	}
	if got.Interface != "bond0" {
		t.Errorf("Interface = %q, want bond0", got.Interface)
	}
}

// ─── Concurrency ──────────────────────────────────────────────────────────────

func TestConcurrentSetGet(t *testing.T) {
	mgr, _ := config.NewManager("")
	done := make(chan struct{}, 200)

	for i := 0; i < 100; i++ {
		go func(n uint64) {
			cfg := config.Defaults()
			cfg.SYNRateLimit = n
			mgr.Set(cfg)
			done <- struct{}{}
		}(uint64(i))
		go func() {
			_ = mgr.Get()
			done <- struct{}{}
		}()
	}
	for i := 0; i < 200; i++ {
		<-done
	}
}
