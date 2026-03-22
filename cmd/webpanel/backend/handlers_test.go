package main_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/nsp/ddos-platform/cmd/webpanel/backend/api"
	"github.com/nsp/ddos-platform/cmd/webpanel/backend/auth"
	"github.com/nsp/ddos-platform/cmd/webpanel/backend/models"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// ─── Test helpers ─────────────────────────────────────────────────────────────

// stubControlPlane returns a httptest server that simulates the control plane.
func stubControlPlane(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"total_packets":1000000,
			"dropped_packets":5000,
			"passed_packets":995000,
			"syn_floods":12,
			"udp_amplifications":3,
			"icmp_floods":7,
			"pps":99500.5,
			"bps":512000000,
			"blocked_ip_count":2,
			"top_attackers":[],
			"timestamp":"2024-01-01T00:00:00Z"
		}`))
	})
	mux.HandleFunc("/api/v1/blocked", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`[{"ip":"1.2.3.4","reason":"syn_flood","blocked_at":"2024-01-01T00:00:00Z"}]`))
		case http.MethodPost:
			_, _ = w.Write([]byte(`{"status":"blocked","ip":"1.2.3.4"}`))
		case http.MethodDelete:
			_, _ = w.Write([]byte(`{"status":"unblocked","ip":"1.2.3.4"}`))
		}
	})
	mux.HandleFunc("/api/v1/attackers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"ip":"5.6.7.8","total_packets":50000,"syn_count":1000}]`))
	})
	mux.HandleFunc("/api/v1/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"syn_rate_limit":1000,"udp_rate_limit":5000,"icmp_rate_limit":100,"enabled":true}`))
		case http.MethodPost:
			_, _ = w.Write([]byte(`{"status":"updated"}`))
		}
	})
	mux.HandleFunc("/api/v1/whitelist", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	return httptest.NewServer(mux)
}

// newTestRouter sets up a full Gin router wired to a stub control plane.
func newTestRouter(t *testing.T) (*gin.Engine, *auth.Manager, string) {
	t.Helper()

	stub := stubControlPlane(t)
	t.Cleanup(stub.Close)

	authMgr := auth.NewManager("test-secret")
	cp := api.NewControlPlaneClient(stub.URL)
	alerts := models.NewAlertStore(100)
	handler := api.NewHandler(authMgr, cp, alerts)

	r := gin.New()
	r.Use(gin.Recovery())
	handler.RegisterRoutes(r)

	// Get a valid admin token
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "changeme"})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	token, _ := resp["token"].(string)

	return r, authMgr, token
}

func bearer(token string) string { return "Bearer " + token }

// ─── Auth tests ───────────────────────────────────────────────────────────────

func TestLoginSuccess(t *testing.T) {
	r, _, _ := newTestRouter(t)

	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "changeme"})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("login status = %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if _, ok := resp["token"]; !ok {
		t.Error("response missing 'token' field")
	}
	if _, ok := resp["user"]; !ok {
		t.Error("response missing 'user' field")
	}
}

func TestLoginBadCredentials(t *testing.T) {
	r, _, _ := newTestRouter(t)

	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "wrong"})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestProtectedRouteWithoutToken(t *testing.T) {
	r, _, _ := newTestRouter(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/metrics", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestProtectedRouteWithBadToken(t *testing.T) {
	r, _, _ := newTestRouter(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/metrics", nil)
	req.Header.Set("Authorization", "Bearer not.a.real.token")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

// ─── Metrics ──────────────────────────────────────────────────────────────────

func TestGetMetrics(t *testing.T) {
	r, _, token := newTestRouter(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/metrics", nil)
	req.Header.Set("Authorization", bearer(token))
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}

	var m map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	if _, ok := m["total_packets"]; !ok {
		t.Error("response missing 'total_packets'")
	}
	if _, ok := m["pps"]; !ok {
		t.Error("response missing 'pps'")
	}
}

// ─── Blocked IPs ──────────────────────────────────────────────────────────────

func TestGetBlockedIPs(t *testing.T) {
	r, _, token := newTestRouter(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/blocked", nil)
	req.Header.Set("Authorization", bearer(token))
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	var list []map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if len(list) == 0 {
		t.Error("expected at least one blocked IP")
	}
}

func TestBlockIPAsAdmin(t *testing.T) {
	r, _, token := newTestRouter(t)

	body, _ := json.Marshal(map[string]interface{}{"ip": "9.9.9.9", "reason": 1})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/blocked", bytes.NewReader(body))
	req.Header.Set("Authorization", bearer(token))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
}

func TestBlockIPAsViewer(t *testing.T) {
	r, _, _ := newTestRouter(t)

	// Get viewer token
	body, _ := json.Marshal(map[string]string{"username": "viewer", "password": "readonly"})
	w1 := httptest.NewRecorder()
	req1, _ := http.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req1.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w1, req1)
	var lr map[string]interface{}
	_ = json.Unmarshal(w1.Body.Bytes(), &lr)
	viewerToken, _ := lr["token"].(string)

	// Try to block as viewer
	blockBody, _ := json.Marshal(map[string]interface{}{"ip": "9.9.9.9", "reason": 1})
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest(http.MethodPost, "/api/v1/blocked", bytes.NewReader(blockBody))
	req2.Header.Set("Authorization", bearer(viewerToken))
	req2.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusForbidden {
		t.Fatalf("viewer block: status = %d, want 403", w2.Code)
	}
}

// ─── Attackers ────────────────────────────────────────────────────────────────

func TestGetAttackers(t *testing.T) {
	r, _, token := newTestRouter(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/attackers", nil)
	req.Header.Set("Authorization", bearer(token))
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
}

// ─── Config ───────────────────────────────────────────────────────────────────

func TestGetConfig(t *testing.T) {
	r, _, token := newTestRouter(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/config", nil)
	req.Header.Set("Authorization", bearer(token))
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	var cfg map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &cfg)
	if _, ok := cfg["syn_rate_limit"]; !ok {
		t.Error("response missing 'syn_rate_limit'")
	}
}

func TestSetConfig(t *testing.T) {
	r, _, token := newTestRouter(t)

	body, _ := json.Marshal(map[string]interface{}{
		"syn_rate_limit":  2000,
		"udp_rate_limit":  10000,
		"icmp_rate_limit": 200,
		"enabled":         true,
	})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/config", bytes.NewReader(body))
	req.Header.Set("Authorization", bearer(token))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
}

// ─── Alerts ───────────────────────────────────────────────────────────────────

func TestGetAlerts(t *testing.T) {
	r, _, token := newTestRouter(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/alerts", nil)
	req.Header.Set("Authorization", bearer(token))
	r.ServeHTTP(w, req)

	// Should return 200 even if empty
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

func TestGetDashboard(t *testing.T) {
	r, _, token := newTestRouter(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/dashboard", nil)
	req.Header.Set("Authorization", bearer(token))
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body)
	}
	var dash map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &dash)
	if _, ok := dash["metrics"]; !ok {
		t.Error("dashboard missing 'metrics' field")
	}
}
