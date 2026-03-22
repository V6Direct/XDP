// Package integration_test contains end-to-end tests that exercise the full
// web panel ↔ control plane ↔ (mock) BPF stack.
//
// Run with:
//   go test ./integration/ -v -timeout 60s
//
// These tests do NOT require root or a real BPF environment.  The BPF layer
// is replaced by a stub control plane HTTP server.
package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nsp/ddos-platform/cmd/webpanel/backend/api"
	"github.com/nsp/ddos-platform/cmd/webpanel/backend/auth"
	"github.com/nsp/ddos-platform/cmd/webpanel/backend/models"
	"github.com/nsp/ddos-platform/pkg/types"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// ─── Full stack fixture ───────────────────────────────────────────────────────

type stack struct {
	cpSrv    *httptest.Server // mock control plane
	panel    *httptest.Server // web panel
	token    string           // valid admin JWT
	client   *http.Client
}

func newStack(t *testing.T) *stack {
	t.Helper()

	// ── Mock Control Plane ──
	cpMux := http.NewServeMux()
	var storeMu sync.Mutex
	blockedStore := make(map[string]types.BlockedIP)
	whitelistStore := make(map[string]struct{})

	cpMux.HandleFunc("/api/v1/metrics", func(w http.ResponseWriter, r *http.Request) {
		storeMu.Lock()
		blocked := len(blockedStore)
		storeMu.Unlock()
		json.NewEncoder(w).Encode(types.Metrics{
			TotalPackets:   1_000_000,
			DroppedPackets: 10_000,
			PassedPackets:  990_000,
			PPS:            50_000,
			BPS:            3_200_000_000,
			BlockedIPCount: blocked,
			SYNFloods:      5,
			Timestamp:      time.Now(),
		})
	})
	cpMux.HandleFunc("/api/v1/blocked", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			storeMu.Lock()
			list := make([]types.BlockedIP, 0, len(blockedStore))
			for _, b := range blockedStore {
				list = append(list, b)
			}
			storeMu.Unlock()
			json.NewEncoder(w).Encode(list)
		case http.MethodPost:
			var req struct {
				IP     string `json:"ip"`
				Reason uint32 `json:"reason"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			storeMu.Lock()
			blockedStore[req.IP] = types.BlockedIP{
				IP:        req.IP,
				Reason:    types.ReasonString(req.Reason),
				BlockedAt: time.Now(),
			}
			storeMu.Unlock()
			json.NewEncoder(w).Encode(map[string]string{"status": "blocked", "ip": req.IP})
		case http.MethodDelete:
			var req struct{ IP string `json:"ip"` }
			json.NewDecoder(r.Body).Decode(&req)
			storeMu.Lock()
			delete(blockedStore, req.IP)
			storeMu.Unlock()
			json.NewEncoder(w).Encode(map[string]string{"status": "unblocked", "ip": req.IP})
		}
	})
	cpMux.HandleFunc("/api/v1/attackers", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]types.AttackingIP{
			{IP: "8.8.8.8", TotalPackets: 100000, SYNCount: 5000},
		})
	})
	cpMux.HandleFunc("/api/v1/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			json.NewEncoder(w).Encode(types.Config{
				SYNRateLimit: 1000, UDPRateLimit: 5000,
				ICMPRateLimit: 100, Enabled: true,
			})
		case http.MethodPost:
			var cfg types.Config
			json.NewDecoder(r.Body).Decode(&cfg)
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "updated", "config": cfg})
		}
	})
	cpMux.HandleFunc("/api/v1/whitelist", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ IP string `json:"ip"` }
		json.NewDecoder(r.Body).Decode(&req)
		switch r.Method {
		case http.MethodPost:
			storeMu.Lock()
			whitelistStore[req.IP] = struct{}{}
			storeMu.Unlock()
			json.NewEncoder(w).Encode(map[string]string{"status": "whitelisted"})
		case http.MethodDelete:
			storeMu.Lock()
			delete(whitelistStore, req.IP)
			storeMu.Unlock()
			json.NewEncoder(w).Encode(map[string]string{"status": "removed"})
		}
	})
	cpMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok"}`))
	})
	cpSrv := httptest.NewServer(cpMux)

	// ── Web Panel ──
	authMgr := auth.NewManager("integration-test-secret")
	cpClient := api.NewControlPlaneClient(cpSrv.URL)
	alertStore := models.NewAlertStore(200)
	handler := api.NewHandler(authMgr, cpClient, alertStore)

	r := gin.New()
	r.Use(gin.Recovery())
	handler.RegisterRoutes(r)
	panelSrv := httptest.NewServer(r)

	// ── Get admin token ──
	loginBody, _ := json.Marshal(map[string]string{"username": "admin", "password": "changeme"})
	resp, err := http.Post(panelSrv.URL+"/api/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	var lr map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&lr)
	resp.Body.Close()
	token, _ := lr["token"].(string)

	t.Cleanup(func() {
		cpSrv.Close()
		panelSrv.Close()
	})

	return &stack{
		cpSrv:  cpSrv,
		panel:  panelSrv,
		token:  token,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *stack) bearer() string { return "Bearer " + s.token }

func (s *stack) get(t *testing.T, path string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, s.panel.URL+path, nil)
	req.Header.Set("Authorization", s.bearer())
	resp, err := s.client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

func (s *stack) post(t *testing.T, path string, body interface{}) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, s.panel.URL+path, bytes.NewReader(b))
	req.Header.Set("Authorization", s.bearer())
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func (s *stack) del(t *testing.T, path string, body interface{}) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodDelete, s.panel.URL+path, bytes.NewReader(b))
	req.Header.Set("Authorization", s.bearer())
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		t.Fatalf("DELETE %s: %v", path, err)
	}
	return resp
}

// ─── Integration tests ────────────────────────────────────────────────────────

func TestIntegration_LoginAndMetrics(t *testing.T) {
	s := newStack(t)

	resp := s.get(t, "/api/v1/metrics")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics status = %d", resp.StatusCode)
	}

	var m types.Metrics
	json.NewDecoder(resp.Body).Decode(&m)

	if m.TotalPackets == 0 {
		t.Error("TotalPackets should be non-zero")
	}
	if m.PPS == 0 {
		t.Error("PPS should be non-zero")
	}
}

func TestIntegration_BlockAndUnblockFlow(t *testing.T) {
	s := newStack(t)
	const testIP = "203.0.113.99"

	// Block the IP
	resp := s.post(t, "/api/v1/blocked", map[string]interface{}{"ip": testIP, "reason": 1})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("block status = %d", resp.StatusCode)
	}

	// Verify it appears in the blocked list
	resp2 := s.get(t, "/api/v1/blocked")
	defer resp2.Body.Close()
	var list []types.BlockedIP
	json.NewDecoder(resp2.Body).Decode(&list)

	found := false
	for _, b := range list {
		if b.IP == testIP {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("blocked IP %s not found in list: %+v", testIP, list)
	}

	// Unblock it
	resp3 := s.del(t, "/api/v1/blocked", map[string]string{"ip": testIP})
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("unblock status = %d", resp3.StatusCode)
	}

	// Verify it's gone
	resp4 := s.get(t, "/api/v1/blocked")
	defer resp4.Body.Close()
	var list2 []types.BlockedIP
	json.NewDecoder(resp4.Body).Decode(&list2)
	for _, b := range list2 {
		if b.IP == testIP {
			t.Errorf("IP %s should have been unblocked", testIP)
		}
	}
}

func TestIntegration_ConfigUpdateFlow(t *testing.T) {
	s := newStack(t)

	// Get current config
	resp := s.get(t, "/api/v1/config")
	defer resp.Body.Close()
	var cfg types.Config
	json.NewDecoder(resp.Body).Decode(&cfg)
	if cfg.SYNRateLimit == 0 {
		t.Fatal("initial SYNRateLimit should be non-zero")
	}

	// Update config
	newCfg := types.Config{
		SYNRateLimit:  2000,
		UDPRateLimit:  10000,
		ICMPRateLimit: 200,
		Enabled:       true,
	}
	resp2 := s.post(t, "/api/v1/config", newCfg)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("config update status = %d", resp2.StatusCode)
	}
}

func TestIntegration_WhitelistFlow(t *testing.T) {
	s := newStack(t)
	const testIP = "10.0.0.1"

	resp := s.post(t, "/api/v1/whitelist", map[string]string{"ip": testIP})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("whitelist status = %d", resp.StatusCode)
	}

	resp2 := s.del(t, "/api/v1/whitelist", map[string]string{"ip": testIP})
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("unwhitelist status = %d", resp2.StatusCode)
	}
}

func TestIntegration_AttackersEndpoint(t *testing.T) {
	s := newStack(t)

	resp := s.get(t, "/api/v1/attackers")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("attackers status = %d", resp.StatusCode)
	}

	var list []types.AttackingIP
	json.NewDecoder(resp.Body).Decode(&list)
	if len(list) == 0 {
		t.Error("expected at least one attacker entry")
	}
}

func TestIntegration_AlertsGeneratedOnHighPPS(t *testing.T) {
	s := newStack(t)

	// Fetch metrics — the handler checks PPS and may add alerts
	resp := s.get(t, "/api/v1/metrics")
	resp.Body.Close()

	// Fetch alerts
	resp2 := s.get(t, "/api/v1/alerts")
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("alerts status = %d", resp2.StatusCode)
	}
}

func TestIntegration_DashboardAggregation(t *testing.T) {
	s := newStack(t)

	// Prime the dashboard by fetching individual endpoints first
	s.get(t, "/api/v1/metrics").Body.Close()
	s.get(t, "/api/v1/blocked").Body.Close()

	// Now fetch dashboard
	resp := s.get(t, "/api/v1/dashboard")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dashboard status = %d", resp.StatusCode)
	}

	var dash models.DashboardData
	json.NewDecoder(resp.Body).Decode(&dash)
	if dash.Metrics == nil {
		t.Error("dashboard.metrics should not be nil")
	}
}

func TestIntegration_UnauthorizedWithoutToken(t *testing.T) {
	s := newStack(t)

	routes := []string{
		"/api/v1/metrics",
		"/api/v1/blocked",
		"/api/v1/attackers",
		"/api/v1/config",
		"/api/v1/alerts",
		"/api/v1/dashboard",
	}

	for _, route := range routes {
		resp, err := s.client.Get(s.panel.URL + route)
		if err != nil {
			t.Errorf("GET %s: %v", route, err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s without token: status = %d, want 401", route, resp.StatusCode)
		}
	}
}

func TestIntegration_ControlPlaneUnavailable(t *testing.T) {
	// Point panel at a port that nobody is listening on
	authMgr := auth.NewManager("test-secret")

	// Use a URL that will immediately refuse connections.
	// 127.0.0.1:1 is a privileged port that is never listening in CI.
	// Using a closed httptest server guarantees connection refused.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	dead.Close() // now closed: connections will be refused

	cpClient := api.NewControlPlaneClient(dead.URL)
	alertStore := models.NewAlertStore(100)
	handler := api.NewHandler(authMgr, cpClient, alertStore)

	r := gin.New()
	handler.RegisterRoutes(r)
	panelSrv := httptest.NewServer(r)
	defer panelSrv.Close()

	// Get token
	loginBody, _ := json.Marshal(map[string]string{"username": "admin", "password": "changeme"})
	resp, _ := http.Post(panelSrv.URL+"/api/auth/login", "application/json", bytes.NewReader(loginBody))
	var lr map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&lr)
	resp.Body.Close()
	token, _ := lr["token"].(string)

	req, _ := http.NewRequest(http.MethodGet, panelSrv.URL+"/api/v1/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: 3 * time.Second}
	resp2, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp2.Body.Close()

	// Should get 502 Bad Gateway when control plane is down
	if resp2.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502 when CP is down", resp2.StatusCode)
	}
}

func TestIntegration_ConcurrentRequests(t *testing.T) {
	s := newStack(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results := make(chan int, 100)
	for i := 0; i < 100; i++ {
		go func() {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
				s.panel.URL+"/api/v1/metrics", nil)
			req.Header.Set("Authorization", s.bearer())
			resp, err := s.client.Do(req)
			if err != nil {
				results <- 0
				return
			}
			resp.Body.Close()
			results <- resp.StatusCode
		}()
	}

	ok := 0
	for i := 0; i < 100; i++ {
		if code := <-results; code == http.StatusOK {
			ok++
		}
	}
	if ok < 90 {
		t.Errorf("only %d/100 concurrent requests succeeded", ok)
	}
	t.Logf("concurrent: %d/100 OK", ok)
}
