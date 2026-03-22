//go:build linux

// cmd/controlplane/main.go
// DDoS Mitigation Platform - Control Plane
// Loads XDP program, manages BPF maps, exposes REST API + Prometheus metrics.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nsp/ddos-platform/pkg/config"
	"github.com/nsp/ddos-platform/pkg/logger"
	"github.com/nsp/ddos-platform/pkg/reputation"
	"github.com/nsp/ddos-platform/pkg/types"
)

// ─── CLI flags ────────────────────────────────────────────────────────────────

var (
	flagIface       = flag.String("iface", "", "Network interface to attach XDP to (overrides config)")
	flagReplace     = flag.Bool("replace", false, "Replace existing XDP program / unpin maps")
	flagAPIAddr     = flag.String("api", "", "REST API listen address (overrides config)")
	flagMetricsAddr = flag.String("metrics", "", "Prometheus metrics listen address (overrides config)")
	flagDetach      = flag.Bool("detach", false, "Detach XDP and exit")
	flagConfig      = flag.String("config", "", "Path to JSON config file")
	flagLogLevel    = flag.String("log-level", "", "Log level: debug, info, warn, error (overrides config)")
)

func main() {
	flag.Parse()

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "error: controlplane must run as root (required for BPF)")
		os.Exit(1)
	}

	// ── Load configuration ──
	cfgMgr, err := config.NewManager(*flagConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	// Apply CLI flag overrides (empty string = use config value)
	cfgMgr.Update(func(c *config.RuntimeConfig) {
		if *flagIface != "" {
			c.Interface = *flagIface
		}
		if *flagAPIAddr != "" {
			c.APIAddr = *flagAPIAddr
		}
		if *flagMetricsAddr != "" {
			c.MetricsAddr = *flagMetricsAddr
		}
		if *flagLogLevel != "" {
			c.LogLevel = *flagLogLevel
		}
	})

	cfg := cfgMgr.Get()

	// ── Initialise structured logger ──
	lvl, err := logger.ParseLevel(cfg.LogLevel)
	if err != nil {
		lvl = logger.LevelInfo
	}
	log := logger.New(os.Stderr, lvl).
		WithFields(map[string]interface{}{
			"component": "controlplane",
			"iface":     cfg.Interface,
		})

	if *flagDetach {
		if err := UnpinMaps(); err != nil {
			log.Error("unpin maps failed", "err", err.Error())
			os.Exit(1)
		}
		log.Info("XDP program detached and maps unpinned")
		os.Exit(0)
	}

	log.Info("starting DDoS control plane",
		"iface",   cfg.Interface,
		"api",     cfg.APIAddr,
		"metrics", cfg.MetricsAddr,
	)

	// ── Load & attach XDP ──
	objs, err := LoadXDP(cfg.Interface, *flagReplace)
	if err != nil {
		log.Error("LoadXDP failed", "err", err.Error())
		os.Exit(1)
	}
	defer func() {
		if err := objs.DetachXDP(); err != nil {
			log.Error("DetachXDP", "err", err.Error())
		}
	}()

	// ── Push initial config to BPF maps ──
	mgr := NewMapManager(objs)
	if err := mgr.UpdateConfig(cfg.Config); err != nil {
		log.Warn("initial config push failed", "err", err.Error())
	}

	// Hot-reload: whenever config changes, push new thresholds to BPF
	cfgMgr.OnChange(func(c config.RuntimeConfig) {
		if err := mgr.UpdateConfig(c.Config); err != nil {
			log.Error("config hot-reload to BPF failed", "err", err.Error())
		} else {
			log.Info("BPF config updated",
				"syn", c.SYNRateLimit,
				"udp", c.UDPRateLimit,
				"icmp", c.ICMPRateLimit,
			)
		}
	})

	// ── Context with signal handling ──
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for {
			sig := <-sigCh
			switch sig {
			case syscall.SIGHUP:
				log.Info("SIGHUP received, reloading config")
				if err := cfgMgr.Reload(); err != nil {
					log.Error("config reload failed", "err", err.Error())
				}
			default:
				log.Info("shutdown signal received", "signal", sig.String())
				cancel()
				return
			}
		}
	}()

	// ── Reputation feed manager ──
	if len(cfg.ReputationFeeds) > 0 {
		feeds := make([]reputation.Feed, 0, len(cfg.ReputationFeeds))
		for _, f := range cfg.ReputationFeeds {
			feeds = append(feeds, reputation.Feed{
				Name:     f.Name,
				URL:      f.URL,
				Interval: time.Duration(f.IntervalMinutes) * time.Minute,
				Enabled:  f.Enabled,
			})
		}
		repMgr := reputation.NewManager(feeds, func(ip string, reason uint32) error {
			return mgr.BlockIP(ip, reason)
		}, log)
		repMgr.Start(ctx)
		defer repMgr.Stop()
		log.Info("reputation feed manager started", "feeds", len(feeds))
	}

	// ── Prometheus metrics server ──
	metricsSrv := NewMetricsServer(cfg.MetricsAddr, mgr)
	go metricsSrv.Start(ctx)

	// ── REST API server ──
	apiSrv := newAPIServer(cfg.APIAddr, mgr, metricsSrv)
	go func() {
		log.Info("REST API listening", "addr", cfg.APIAddr)
		if err := apiSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("API server error", "err", err.Error())
		}
	}()
	defer func() {
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutCancel()
		_ = apiSrv.Shutdown(shutCtx)
	}()

	log.Info("control plane running — send SIGINT/SIGTERM to stop, SIGHUP to reload config")
	<-ctx.Done()
	log.Info("control plane stopped")
}

// ─── REST API ─────────────────────────────────────────────────────────────────

func newAPIServer(addr string, mgr *MapManager, ms *MetricsServer) *http.Server {
	mux := http.NewServeMux()

	h := func(fn http.HandlerFunc) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			fn(w, r)
		})
	}

	mux.Handle("GET /api/v1/metrics",      h(handleMetrics(ms)))
	mux.Handle("GET /api/v1/blocked",      h(handleListBlocked(mgr)))
	mux.Handle("POST /api/v1/blocked",     h(handleBlockIP(mgr)))
	mux.Handle("DELETE /api/v1/blocked",   h(handleUnblockIP(mgr)))
	mux.Handle("GET /api/v1/attackers",    h(handleTopAttackers(mgr)))
	mux.Handle("GET /api/v1/config",       h(handleGetConfig(mgr)))
	mux.Handle("POST /api/v1/config",      h(handleSetConfig(mgr)))
	mux.Handle("POST /api/v1/whitelist",   h(handleWhitelistIP(mgr)))
	mux.Handle("DELETE /api/v1/whitelist", h(handleUnwhitelistIP(mgr)))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	return &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// ─── Handler helpers ──────────────────────────────────────────────────────────

func jsonOK(w http.ResponseWriter, v any) {
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ─── Route handlers ───────────────────────────────────────────────────────────

func handleMetrics(ms *MetricsServer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonOK(w, ms.Latest())
	}
}

func handleListBlocked(mgr *MapManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := mgr.ListBlockedIPs()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		jsonOK(w, list)
	}
}

func handleBlockIP(mgr *MapManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			IP     string `json:"ip"`
			Reason uint32 `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		if req.Reason == 0 {
			req.Reason = 1
		}
		if err := mgr.BlockIP(req.IP, req.Reason); err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		jsonOK(w, map[string]string{"status": "blocked", "ip": req.IP})
	}
}

func handleUnblockIP(mgr *MapManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if err := mgr.UnblockIP(req.IP); err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		jsonOK(w, map[string]string{"status": "unblocked", "ip": req.IP})
	}
}

func handleTopAttackers(mgr *MapManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		attackers, err := mgr.GetTopAttackers(20)
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		jsonOK(w, attackers)
	}
}

func handleGetConfig(mgr *MapManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := types.Config{
			SYNRateLimit:  1000,
			UDPRateLimit:  5000,
			ICMPRateLimit: 100,
			Enabled:       true,
		}
		for idx, ptr := range [](*uint64){&cfg.SYNRateLimit, &cfg.UDPRateLimit, &cfg.ICMPRateLimit} {
			key := uint32(idx)
			var val uint64
			if err := mgr.objs.ConfigMap.Lookup(key, &val); err == nil && val > 0 {
				*ptr = val
			}
		}
		var enabledVal uint64
		key := uint32(3)
		if err := mgr.objs.ConfigMap.Lookup(key, &enabledVal); err == nil {
			cfg.Enabled = enabledVal != 0
		}
		jsonOK(w, cfg)
	}
}

func handleSetConfig(mgr *MapManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg types.Config
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if cfg.SYNRateLimit == 0 {
			cfg.SYNRateLimit = 1000
		}
		if cfg.UDPRateLimit == 0 {
			cfg.UDPRateLimit = 5000
		}
		if cfg.ICMPRateLimit == 0 {
			cfg.ICMPRateLimit = 100
		}
		if err := mgr.UpdateConfig(cfg); err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		jsonOK(w, map[string]any{"status": "updated", "config": cfg})
	}
}

func handleWhitelistIP(mgr *MapManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if err := mgr.WhitelistIP(req.IP); err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		jsonOK(w, map[string]string{"status": "whitelisted", "ip": req.IP})
	}
}

func handleUnwhitelistIP(mgr *MapManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if err := mgr.UnwhitelistIP(req.IP); err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		jsonOK(w, map[string]string{"status": "removed_from_whitelist", "ip": req.IP})
	}
}

// init checks that sizeofIPStats is non-zero (compile-time sanity check).
func init() {
	if sizeofIPStats() == 0 || metricsSize() == 0 {
		fmt.Fprintln(os.Stderr, "BUG: zero-size structs")
		os.Exit(1)
	}
}
