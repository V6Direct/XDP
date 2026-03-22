// Package models defines domain types for the web panel backend.
package models

import (
	"time"

	"github.com/nsp/ddos-platform/pkg/types"
)

// User represents a web panel operator.
type User struct {
	ID           uint      `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"` // admin | viewer
	CreatedAt    time.Time `json:"created_at"`
	LastLogin    time.Time `json:"last_login"`
}

// LoginRequest is the body for POST /auth/login.
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse is returned on successful authentication.
type LoginResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	User      User      `json:"user"`
}

// DashboardData aggregates all data needed by the frontend dashboard.
type DashboardData struct {
	Metrics     *types.Metrics  `json:"metrics"`
	BlockedIPs  []types.BlockedIP  `json:"blocked_ips"`
	TopAttackers []types.AttackingIP `json:"top_attackers"`
	Alerts      []types.Alert   `json:"alerts"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// AlertStore is an in-memory ring buffer of recent alerts.
type AlertStore struct {
	alerts []types.Alert
	max    int
	seq    uint64
}

// NewAlertStore creates an AlertStore with given capacity.
func NewAlertStore(maxAlerts int) *AlertStore {
	return &AlertStore{
		alerts: make([]types.Alert, 0, maxAlerts),
		max:    maxAlerts,
	}
}

// Add appends an alert, evicting the oldest if at capacity.
func (a *AlertStore) Add(alert types.Alert) {
	a.seq++
	alert.ID = time.Now().Format("20060102150405") + "-" + itoa(a.seq)
	if len(a.alerts) >= a.max {
		a.alerts = append(a.alerts[1:], alert)
	} else {
		a.alerts = append(a.alerts, alert)
	}
}

// List returns a copy of all current alerts (newest first).
func (a *AlertStore) List() []types.Alert {
	out := make([]types.Alert, len(a.alerts))
	for i, v := range a.alerts {
		out[len(a.alerts)-1-i] = v
	}
	return out
}

func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}
