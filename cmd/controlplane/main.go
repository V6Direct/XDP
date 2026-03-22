// cmd/controlplane/main.go
// DDoS Mitigation Platform - Control Plane
// Loads XDP program, manages BPF maps, exposes REST API + Prometheus metrics.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nsp/ddos-platform/pkg/types"
)

// ─── CLI flags ────────────────────────────────────────────────────────────────

var (
	flagIface      = flag.String("iface", "eth0", "Network interface to attach XDP to")
	flagReplace    = flag.Bool("replace", false, "Replace existing XDP program / unpin maps")
	flagAPIAddr    = flag.String("api", ":8080", "REST API listen address")
	flagMetricsAddr = flag.String("metrics", ":9090", "Prometheus metrics listen address")
	flagDetach     = flag.Bool("detach", false, "Detach XDP and exit")
)

func main() {
	flag.Parse()

	if os.Geteuid() != 0 {
		log.Fatal("controlplane must run as root (required for BPF)")
	}

	if *flagDetach {
		if err := UnpinMaps(); err != nil {
			log.Fatalf("unpin maps: %v", err)
		}
		log.Println("XDP program detached and maps unpinned")
		os.Exit(0)
	}

	log.Printf("Starting DDoS control plane on interface %s", *flagIface)

	// ── Load & attach XDP ──
	objs, err := LoadXDP(*flagIface, *flagReplace)
	if err != nil {
		log.Fatalf("LoadXDP: %v", err)
	}
	defer func() { _ = objs.DetachXDP() }()

	// ── Map manager ──
	mgr := NewMapManager(objs)

	// ── Context with signal handling ──
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("received signal %s, shutting down...", sig)
		cancel()
	}()

	// ── Prometheus metrics server ──
	metricsSrv := NewMetricsServer(*flagMetricsAddr, mgr)
	go metricsSrv.Start(ctx)

	// ── REST API server ──
	apiSrv := newAPIServer(*flagAPIAddr, mgr, metricsSrv)
	go func() {
		log.Printf("REST API listening on %s", *flagAPIAddr)
		if err := apiSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("API server error: %v", err)
		}
	}()
	defer func() {
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutCancel()
		_ = apiSrv.Shutdown(shutCtx)
	}()

	log.Println("Control plane running. Press Ctrl-C to stop.")
	<-ctx.Done()
	log.Println("Control plane stopped.")
}

// ─── REST API ─────────────────────────────────────────────────────────────────

func newAPIServer(addr string, mgr *MapManager, ms *MetricsServer) *http.Server {
	mux := http.NewServeMux()

	// CORS + JSON middleware wrapper
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

	// ── Routes ──
	mux.Handle("GET /api/v1/metrics",    h(handleMetrics(ms)))
	mux.Handle("GET /api/v1/blocked",    h(handleListBlocked(mgr)))
	mux.Handle("POST /api/v1/blocked",   h(handleBlockIP(mgr)))
	mux.Handle("DELETE /api/v1/blocked", h(handleUnblockIP(mgr)))
	mux.Handle("GET /api/v1/attackers",  h(handleTopAttackers(mgr)))
	mux.Handle("GET /api/v1/config",     h(handleGetConfig(mgr)))
	mux.Handle("POST /api/v1/config",    h(handleSetConfig(mgr)))
	mux.Handle("POST /api/v1/whitelist", h(handleWhitelistIP(mgr)))
	mux.Handle("DELETE /api/v1/whitelist", h(handleUnwhitelistIP(mgr)))
	mux.Handle("GET /healthz", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))

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
		// Read current config from BPF map
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
