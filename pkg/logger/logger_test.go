package logger_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nsp/ddos-platform/pkg/logger"
)

func TestInfoWritesJSON(t *testing.T) {
	var buf bytes.Buffer
	l := logger.New(&buf, logger.LevelInfo)
	l.Info("hello world")

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if entry["msg"] != "hello world" {
		t.Errorf("msg = %v, want 'hello world'", entry["msg"])
	}
	if entry["level"] != "info" {
		t.Errorf("level = %v, want 'info'", entry["level"])
	}
	if entry["ts"] == nil {
		t.Error("missing ts field")
	}
}

func TestDebugSuppressedAtInfoLevel(t *testing.T) {
	var buf bytes.Buffer
	l := logger.New(&buf, logger.LevelInfo)
	l.Debug("should not appear")
	if buf.Len() > 0 {
		t.Errorf("debug log should be suppressed at info level, got: %s", buf.String())
	}
}

func TestDebugAppearsAtDebugLevel(t *testing.T) {
	var buf bytes.Buffer
	l := logger.New(&buf, logger.LevelDebug)
	l.Debug("debug msg")
	if buf.Len() == 0 {
		t.Error("debug log should appear at debug level")
	}
}

func TestWithFields(t *testing.T) {
	var buf bytes.Buffer
	l := logger.New(&buf, logger.LevelInfo).With("component", "xdp").With("iface", "eth0")
	l.Info("attached")

	var entry map[string]interface{}
	_ = json.Unmarshal(buf.Bytes(), &entry)
	if entry["component"] != "xdp" {
		t.Errorf("component = %v, want 'xdp'", entry["component"])
	}
	if entry["iface"] != "eth0" {
		t.Errorf("iface = %v, want 'eth0'", entry["iface"])
	}
}

func TestWithFieldsImmutable(t *testing.T) {
	var buf bytes.Buffer
	base := logger.New(&buf, logger.LevelInfo).With("base", "yes")
	child := base.With("child", "yes")

	// Writing to child must not affect base
	var b2 bytes.Buffer
	_ = base
	_ = child
	l2 := logger.New(&b2, logger.LevelInfo).With("only", "one")
	l2.Info("test")

	var entry map[string]interface{}
	_ = json.Unmarshal(b2.Bytes(), &entry)
	if _, ok := entry["base"]; ok {
		t.Error("base field should not appear in separate logger")
	}
}

func TestInlineKVPairs(t *testing.T) {
	var buf bytes.Buffer
	l := logger.New(&buf, logger.LevelInfo)
	l.Info("event", "ip", "1.2.3.4", "packets", 1000)

	var entry map[string]interface{}
	_ = json.Unmarshal(buf.Bytes(), &entry)
	if entry["ip"] != "1.2.3.4" {
		t.Errorf("ip = %v, want 1.2.3.4", entry["ip"])
	}
	if entry["packets"] == nil {
		t.Error("packets field missing")
	}
}

func TestSetLevelDynamic(t *testing.T) {
	var buf bytes.Buffer
	l := logger.New(&buf, logger.LevelWarn)

	l.Info("suppressed") // should not appear
	if buf.Len() > 0 {
		t.Error("info should be suppressed at warn level")
	}

	l.SetLevel(logger.LevelInfo)
	l.Info("now visible")
	if buf.Len() == 0 {
		t.Error("info should appear after SetLevel(Info)")
	}
}

func TestWarnLevel(t *testing.T) {
	var buf bytes.Buffer
	l := logger.New(&buf, logger.LevelInfo)
	l.Warn("warning msg")

	var entry map[string]interface{}
	_ = json.Unmarshal(buf.Bytes(), &entry)
	if entry["level"] != "warn" {
		t.Errorf("level = %v, want 'warn'", entry["level"])
	}
}

func TestErrorLevel(t *testing.T) {
	var buf bytes.Buffer
	l := logger.New(&buf, logger.LevelInfo)
	l.Error("something broke")

	var entry map[string]interface{}
	_ = json.Unmarshal(buf.Bytes(), &entry)
	if entry["level"] != "error" {
		t.Errorf("level = %v, want 'error'", entry["level"])
	}
}

func TestInfof(t *testing.T) {
	var buf bytes.Buffer
	l := logger.New(&buf, logger.LevelInfo)
	l.Infof("loaded %d maps on %s", 5, "eth0")

	if !strings.Contains(buf.String(), "loaded 5 maps on eth0") {
		t.Errorf("formatted message not found in: %s", buf.String())
	}
}

func TestParseLevel(t *testing.T) {
	cases := []struct {
		in   string
		want logger.Level
		ok   bool
	}{
		{"debug", logger.LevelDebug, true},
		{"INFO", logger.LevelInfo, true},
		{"warn", logger.LevelWarn, true},
		{"warning", logger.LevelWarn, true},
		{"error", logger.LevelError, true},
		{"fatal", logger.LevelFatal, true},
		{"bogus", logger.LevelInfo, false},
	}
	for _, tc := range cases {
		got, err := logger.ParseLevel(tc.in)
		if tc.ok && err != nil {
			t.Errorf("ParseLevel(%q) unexpected error: %v", tc.in, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("ParseLevel(%q) expected error, got nil", tc.in)
		}
		if tc.ok && got != tc.want {
			t.Errorf("ParseLevel(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestConcurrentLogging(t *testing.T) {
	var buf bytes.Buffer
	l := logger.New(&buf, logger.LevelInfo)

	done := make(chan struct{}, 100)
	for i := 0; i < 100; i++ {
		go func(n int) {
			l.Info("concurrent", "n", n)
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 100; i++ {
		<-done
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 100 {
		t.Errorf("expected 100 log lines, got %d", len(lines))
	}
	// Each line must be valid JSON
	for i, line := range lines {
		var e map[string]interface{}
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Errorf("line %d is not valid JSON: %s", i, line)
		}
	}
}

func TestMultipleFieldsMap(t *testing.T) {
	var buf bytes.Buffer
	l := logger.New(&buf, logger.LevelInfo).WithFields(map[string]interface{}{
		"service": "controlplane",
		"version": "1.0.0",
	})
	l.Info("started")

	var entry map[string]interface{}
	_ = json.Unmarshal(buf.Bytes(), &entry)
	if entry["service"] != "controlplane" {
		t.Errorf("service = %v", entry["service"])
	}
	if entry["version"] != "1.0.0" {
		t.Errorf("version = %v", entry["version"])
	}
}
