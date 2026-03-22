// Package auth provides JWT-based authentication for the web panel.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/nsp/ddos-platform/cmd/webpanel/backend/models"
)

const tokenExpiry = 12 * time.Hour

// Claims embeds standard JWT claims plus app-specific fields.
type Claims struct {
	UserID   uint   `json:"uid"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// Manager handles token signing and user credential management.
type Manager struct {
	secretKey []byte
	mu        sync.RWMutex
	users     map[string]*models.User // keyed by username
	passwords map[string]string       // username -> sha256 hex hash
}

// NewManager creates an auth Manager. If jwtSecret is empty a random key is generated.
func NewManager(jwtSecret string) *Manager {
	secret := []byte(jwtSecret)
	if len(secret) == 0 {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		secret = []byte(hex.EncodeToString(b))
	}
	m := &Manager{
		secretKey: secret,
		users:     make(map[string]*models.User),
		passwords: make(map[string]string),
	}
	// Seed default accounts – override via AddUser in production.
	_ = m.AddUser("admin", "changeme", "admin")
	_ = m.AddUser("viewer", "readonly", "viewer")
	return m
}

// AddUser creates a new user with the given credentials.
func (m *Manager) AddUser(username, password, role string) error {
	if username == "" || password == "" {
		return errors.New("username and password required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	m.users[username] = &models.User{
		ID:        uint(len(m.users) + 1),
		Username:  username,
		Role:      role,
		CreatedAt: time.Now(),
	}
	m.passwords[username] = hashPassword(password)
	return nil
}

// Authenticate validates credentials and returns a signed JWT on success.
func (m *Manager) Authenticate(username, password string) (string, *models.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, ok := m.users[username]
	if !ok {
		return "", nil, errors.New("invalid credentials")
	}
	if m.passwords[username] != hashPassword(password) {
		return "", nil, errors.New("invalid credentials")
	}

	user.LastLogin = time.Now()
	now := time.Now()
	claims := &Claims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenExpiry)),
			Issuer:    "ddos-panel",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(m.secretKey)
	if err != nil {
		return "", nil, fmt.Errorf("sign token: %w", err)
	}
	return signed, user, nil
}

// Validate parses and validates a JWT string, returning its claims.
func (m *Manager) Validate(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.secretKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}
	return claims, nil
}

// hashPassword produces a deterministic sha256 hex digest of the password.
// NOTE: Production deployments MUST replace this with bcrypt.
func hashPassword(password string) string {
	h := sha256.Sum256([]byte(password))
	return hex.EncodeToString(h[:])
}
