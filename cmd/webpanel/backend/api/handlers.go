// Package api implements the Gin HTTP handlers for the DDoS web panel.
package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nsp/ddos-platform/cmd/webpanel/backend/auth"
	"github.com/nsp/ddos-platform/cmd/webpanel/backend/models"
	"github.com/nsp/ddos-platform/pkg/types"
)

// ─── Control plane client ─────────────────────────────────────────────────────

// ControlPlaneClient talks to the controlplane REST API over HTTP.
type ControlPlaneClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewControlPlaneClient creates a client pointed at the control plane API.
func NewControlPlaneClient(baseURL string) *ControlPlaneClient {
	return &ControlPlaneClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (c *ControlPlaneClient) get(path string, out any) error {
	resp, err := c.httpClient.Get(c.baseURL + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *ControlPlaneClient) post(path string, body any, out any) error {
	b, _ := json.Marshal(body)
	resp, err := c.httpClient.Post(c.baseURL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *ControlPlaneClient) doDelete(path string, body any, out any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodDelete, c.baseURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

// ─── Handler ──────────────────────────────────────────────────────────────────

// Handler holds all handler dependencies.
type Handler struct {
	authMgr   *auth.Manager
	cp        *ControlPlaneClient
	alerts    *models.AlertStore
	mu        sync.RWMutex
	dashboard *models.DashboardData
}

// NewHandler creates all API handlers wired to the given dependencies.
func NewHandler(authMgr *auth.Manager, cp *ControlPlaneClient, alerts *models.AlertStore) *Handler {
	return &Handler{
		authMgr: authMgr,
		cp:      cp,
		alerts:  alerts,
		dashboard: &models.DashboardData{
			Metrics:      &types.Metrics{},
			BlockedIPs:   []types.BlockedIP{},
			TopAttackers: []types.AttackingIP{},
			Alerts:       []types.Alert{},
			UpdatedAt:    time.Now(),
		},
	}
}

// RegisterRoutes mounts all routes onto the given Gin engine.
func (h *Handler) RegisterRoutes(r *gin.Engine) {
	r.POST("/api/auth/login", h.Login)

	api := r.Group("/api/v1", h.authMiddleware())
	{
		api.GET("/dashboard",    h.GetDashboard)
		api.GET("/metrics",      h.GetMetrics)
		api.GET("/blocked",      h.GetBlocked)
		api.POST("/blocked",     h.BlockIP)
		api.DELETE("/blocked",   h.UnblockIP)
		api.GET("/attackers",    h.GetAttackers)
		api.GET("/alerts",       h.GetAlerts)
		api.GET("/config",       h.GetConfig)
		api.POST("/config",      h.SetConfig)
		api.POST("/whitelist",   h.WhitelistIP)
		api.DELETE("/whitelist", h.UnwhitelistIP)
	}
}

// ─── Auth handlers ────────────────────────────────────────────────────────────

// Login authenticates a user and returns a JWT.
// POST /api/auth/login
func (h *Handler) Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	token, user, err := h.authMgr.Authenticate(req.Username, req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	c.JSON(http.StatusOK, models.LoginResponse{
		Token:     token,
		ExpiresAt: time.Now().Add(12 * time.Hour),
		User:      *user,
	})
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

// GetDashboard returns a full dashboard snapshot.
// GET /api/v1/dashboard
func (h *Handler) GetDashboard(c *gin.Context) {
	h.mu.RLock()
	data := *h.dashboard
	h.mu.RUnlock()
	c.JSON(http.StatusOK, data)
}

// GetMetrics proxies the control plane metrics endpoint.
// GET /api/v1/metrics
func (h *Handler) GetMetrics(c *gin.Context) {
	var m types.Metrics
	if err := h.cp.get("/api/v1/metrics", &m); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("control plane: %v", err)})
		return
	}
	h.mu.Lock()
	h.dashboard.Metrics = &m
	h.dashboard.UpdatedAt = time.Now()
	h.mu.Unlock()
	h.checkAndAlert(&m)
	c.JSON(http.StatusOK, m)
}

// ─── Blocked IPs ──────────────────────────────────────────────────────────────

// GetBlocked returns all currently blocked IPs.
// GET /api/v1/blocked
func (h *Handler) GetBlocked(c *gin.Context) {
	var list []types.BlockedIP
	if err := h.cp.get("/api/v1/blocked", &list); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	h.mu.Lock()
	h.dashboard.BlockedIPs = list
	h.mu.Unlock()
	c.JSON(http.StatusOK, list)
}

// BlockIP manually blocks an IP (admin only).
// POST /api/v1/blocked
func (h *Handler) BlockIP(c *gin.Context) {
	claims := mustClaims(c)
	if claims.Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin role required"})
		return
	}
	var req struct {
		IP     string `json:"ip" binding:"required"`
		Reason uint32 `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var resp any
	if err := h.cp.post("/api/v1/blocked", req, &resp); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	h.alerts.Add(types.Alert{
		Level:     "info",
		Type:      "manual_block",
		Message:   fmt.Sprintf("IP %s manually blocked by %s", req.IP, claims.Username),
		SourceIP:  req.IP,
		Timestamp: time.Now(),
	})
	c.JSON(http.StatusOK, resp)
}

// UnblockIP removes a block (admin only).
// DELETE /api/v1/blocked
func (h *Handler) UnblockIP(c *gin.Context) {
	claims := mustClaims(c)
	if claims.Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin role required"})
		return
	}
	var req struct {
		IP string `json:"ip" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var resp any
	if err := h.cp.doDelete("/api/v1/blocked", req, &resp); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// ─── Attackers ────────────────────────────────────────────────────────────────

// GetAttackers returns the top attacking IPs.
// GET /api/v1/attackers
func (h *Handler) GetAttackers(c *gin.Context) {
	var list []types.AttackingIP
	if err := h.cp.get("/api/v1/attackers", &list); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	h.mu.Lock()
	h.dashboard.TopAttackers = list
	h.mu.Unlock()
	c.JSON(http.StatusOK, list)
}

// ─── Alerts ───────────────────────────────────────────────────────────────────

// GetAlerts returns recent security alerts.
// GET /api/v1/alerts
func (h *Handler) GetAlerts(c *gin.Context) {
	alerts := h.alerts.List()
	h.mu.Lock()
	h.dashboard.Alerts = alerts
	h.mu.Unlock()
	c.JSON(http.StatusOK, alerts)
}

// ─── Config ───────────────────────────────────────────────────────────────────

// GetConfig returns current XDP rate-limit config.
// GET /api/v1/config
func (h *Handler) GetConfig(c *gin.Context) {
	var cfg types.Config
	if err := h.cp.get("/api/v1/config", &cfg); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, cfg)
}

// SetConfig updates XDP rate-limit thresholds (admin only).
// POST /api/v1/config
func (h *Handler) SetConfig(c *gin.Context) {
	claims := mustClaims(c)
	if claims.Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin role required"})
		return
	}
	var cfg types.Config
	if err := c.ShouldBindJSON(&cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var resp any
	if err := h.cp.post("/api/v1/config", cfg, &resp); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// WhitelistIP adds an IP to the bypass list (admin only).
// POST /api/v1/whitelist
func (h *Handler) WhitelistIP(c *gin.Context) {
	claims := mustClaims(c)
	if claims.Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin role required"})
		return
	}
	var req struct {
		IP string `json:"ip" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var resp any
	if err := h.cp.post("/api/v1/whitelist", req, &resp); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// UnwhitelistIP removes an IP from the bypass list (admin only).
// DELETE /api/v1/whitelist
func (h *Handler) UnwhitelistIP(c *gin.Context) {
	claims := mustClaims(c)
	if claims.Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin role required"})
		return
	}
	var req struct {
		IP string `json:"ip" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var resp any
	if err := h.cp.doDelete("/api/v1/whitelist", req, &resp); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// ─── Middleware ───────────────────────────────────────────────────────────────

func (h *Handler) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing Authorization header"})
			return
		}
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid Authorization header format"})
			return
		}
		claims, err := h.authMgr.Validate(parts[1])
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		c.Set("claims", claims)
		c.Next()
	}
}

func mustClaims(c *gin.Context) *auth.Claims {
	v, _ := c.Get("claims")
	return v.(*auth.Claims)
}

// ─── Internal alert generation ────────────────────────────────────────────────

func (h *Handler) checkAndAlert(m *types.Metrics) {
	if m.PPS > 100000 {
		h.alerts.Add(types.Alert{
			Level:     "critical",
			Type:      "high_pps",
			Message:   fmt.Sprintf("Extreme packet rate: %.0f pps", m.PPS),
			Timestamp: time.Now(),
		})
	} else if m.PPS > 50000 {
		h.alerts.Add(types.Alert{
			Level:     "warning",
			Type:      "high_pps",
			Message:   fmt.Sprintf("High packet rate: %.0f pps", m.PPS),
			Timestamp: time.Now(),
		})
	}
	if m.SYNFloods > 0 {
		h.alerts.Add(types.Alert{
			Level:     "warning",
			Type:      "syn_flood",
			Message:   fmt.Sprintf("SYN flood events: %d", m.SYNFloods),
			Timestamp: time.Now(),
		})
	}
	if m.UDPAmplifications > 0 {
		h.alerts.Add(types.Alert{
			Level:     "warning",
			Type:      "udp_amplification",
			Message:   fmt.Sprintf("UDP amplification events: %d", m.UDPAmplifications),
			Timestamp: time.Now(),
		})
	}
}
