// Package logger provides structured, leveled logging for the DDoS platform.
// It wraps the standard log package with JSON output, log levels, and
// context fields — without pulling in heavy external dependencies.
package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Level represents a log severity level.
type Level int32

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

var levelNames = map[Level]string{
	LevelDebug: "debug",
	LevelInfo:  "info",
	LevelWarn:  "warn",
	LevelError: "error",
	LevelFatal: "fatal",
}

// Logger is a structured logger that writes JSON lines.
type Logger struct {
	level  atomic.Int32
	out    io.Writer
	mu     sync.Mutex
	fields map[string]interface{}
	caller bool
}

// New creates a Logger writing to the given writer at the given minimum level.
func New(out io.Writer, level Level) *Logger {
	l := &Logger{
		out:    out,
		fields: make(map[string]interface{}),
		caller: false,
	}
	l.level.Store(int32(level))
	return l
}

// Default is the package-level logger (stderr, info level).
var Default = New(os.Stderr, LevelInfo)

// SetLevel changes the minimum log level atomically (safe for concurrent use).
func (l *Logger) SetLevel(level Level) {
	l.level.Store(int32(level))
}

// WithCaller enables file:line caller information in log entries.
func (l *Logger) WithCaller(enabled bool) *Logger {
	l2 := l.clone()
	l2.caller = enabled
	return l2
}

// With returns a new Logger with additional fixed fields.
func (l *Logger) With(key string, value interface{}) *Logger {
	l2 := l.clone()
	l2.fields[key] = value
	return l2
}

// WithFields returns a new Logger with multiple additional fixed fields.
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	l2 := l.clone()
	for k, v := range fields {
		l2.fields[k] = v
	}
	return l2
}

// Debug logs at debug level.
func (l *Logger) Debug(msg string, fields ...interface{}) {
	l.log(LevelDebug, msg, fields...)
}

// Info logs at info level.
func (l *Logger) Info(msg string, fields ...interface{}) {
	l.log(LevelInfo, msg, fields...)
}

// Warn logs at warn level.
func (l *Logger) Warn(msg string, fields ...interface{}) {
	l.log(LevelWarn, msg, fields...)
}

// Error logs at error level.
func (l *Logger) Error(msg string, fields ...interface{}) {
	l.log(LevelError, msg, fields...)
}

// Fatal logs at fatal level and calls os.Exit(1).
func (l *Logger) Fatal(msg string, fields ...interface{}) {
	l.log(LevelFatal, msg, fields...)
	os.Exit(1)
}

// Infof logs a formatted message at info level.
func (l *Logger) Infof(format string, args ...interface{}) {
	l.log(LevelInfo, fmt.Sprintf(format, args...))
}

// Errorf logs a formatted message at error level.
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.log(LevelError, fmt.Sprintf(format, args...))
}

// Warnf logs a formatted message at warn level.
func (l *Logger) Warnf(format string, args ...interface{}) {
	l.log(LevelWarn, fmt.Sprintf(format, args...))
}

// ─── Internal ─────────────────────────────────────────────────────────────────

func (l *Logger) log(level Level, msg string, kvPairs ...interface{}) {
	if Level(l.level.Load()) > level {
		return
	}

	entry := make(map[string]interface{}, 4+len(l.fields)+len(kvPairs)/2)
	entry["ts"]    = time.Now().UTC().Format(time.RFC3339Nano)
	entry["level"] = levelNames[level]
	entry["msg"]   = msg

	// Fixed fields
	for k, v := range l.fields {
		entry[k] = v
	}

	// Inline key-value pairs (must be even count)
	for i := 0; i+1 < len(kvPairs); i += 2 {
		key, ok := kvPairs[i].(string)
		if !ok {
			key = fmt.Sprintf("field_%d", i)
		}
		entry[key] = kvPairs[i+1]
	}

	// Caller info
	if l.caller {
		_, file, line, ok := runtime.Caller(2)
		if ok {
			// Shorten path to last two segments
			parts := strings.Split(file, "/")
			if len(parts) > 2 {
				parts = parts[len(parts)-2:]
			}
			entry["caller"] = fmt.Sprintf("%s:%d", strings.Join(parts, "/"), line)
		}
	}

	b, err := json.Marshal(entry)
	if err != nil {
		return
	}

	l.mu.Lock()
	_, _ = l.out.Write(b)
	_, _ = l.out.Write([]byte("\n"))
	l.mu.Unlock()
}

func (l *Logger) clone() *Logger {
	l2 := &Logger{
		out:    l.out,
		fields: make(map[string]interface{}, len(l.fields)),
		caller: l.caller,
	}
	l2.level.Store(l.level.Load())
	for k, v := range l.fields {
		l2.fields[k] = v
	}
	return l2
}

// ParseLevel converts a string level name to a Level constant.
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug, nil
	case "info":
		return LevelInfo, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	case "fatal":
		return LevelFatal, nil
	default:
		return LevelInfo, fmt.Errorf("unknown log level %q", s)
	}
}
