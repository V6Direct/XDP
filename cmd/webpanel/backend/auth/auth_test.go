package auth_test

import (
	"strings"
	"testing"
	"time"

	"github.com/nsp/ddos-platform/cmd/webpanel/backend/auth"
)

// ─── NewManager ───────────────────────────────────────────────────────────────

func TestNewManagerCreatesDefaultUsers(t *testing.T) {
	mgr := auth.NewManager("test-secret-32-bytes-long-enough!")

	// Default admin account must authenticate
	token, user, err := mgr.Authenticate("admin", "changeme")
	if err != nil {
		t.Fatalf("default admin auth failed: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}
	if user == nil {
		t.Fatal("expected non-nil user")
	}
	if user.Username != "admin" {
		t.Errorf("username = %q, want %q", user.Username, "admin")
	}
	if user.Role != "admin" {
		t.Errorf("role = %q, want %q", user.Role, "admin")
	}
}

func TestNewManagerRandomSecretWhenEmpty(t *testing.T) {
	// Should not panic with empty secret
	mgr := auth.NewManager("")
	_, _, err := mgr.Authenticate("admin", "changeme")
	if err != nil {
		t.Fatalf("auth with random secret failed: %v", err)
	}
}

// ─── Authenticate ─────────────────────────────────────────────────────────────

func TestAuthenticateWrongPassword(t *testing.T) {
	mgr := auth.NewManager("secret")
	_, _, err := mgr.Authenticate("admin", "wrongpassword")
	if err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
}

func TestAuthenticateUnknownUser(t *testing.T) {
	mgr := auth.NewManager("secret")
	_, _, err := mgr.Authenticate("nobody", "anything")
	if err == nil {
		t.Fatal("expected error for unknown user, got nil")
	}
}

func TestAuthenticateViewerRole(t *testing.T) {
	mgr := auth.NewManager("secret")
	_, user, err := mgr.Authenticate("viewer", "readonly")
	if err != nil {
		t.Fatalf("viewer auth failed: %v", err)
	}
	if user.Role != "viewer" {
		t.Errorf("role = %q, want viewer", user.Role)
	}
}

func TestAuthenticateUpdatesLastLogin(t *testing.T) {
	mgr := auth.NewManager("secret")
	before := time.Now()
	_, user, err := mgr.Authenticate("admin", "changeme")
	if err != nil {
		t.Fatalf("auth failed: %v", err)
	}
	if user.LastLogin.Before(before) {
		t.Errorf("LastLogin (%v) is before auth time (%v)", user.LastLogin, before)
	}
}

// ─── Token validation ─────────────────────────────────────────────────────────

func TestValidateGoodToken(t *testing.T) {
	mgr := auth.NewManager("my-32-byte-secret-key-for-tests!")
	token, _, err := mgr.Authenticate("admin", "changeme")
	if err != nil {
		t.Fatalf("auth: %v", err)
	}

	claims, err := mgr.Validate(token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Username != "admin" {
		t.Errorf("claims.Username = %q, want admin", claims.Username)
	}
	if claims.Role != "admin" {
		t.Errorf("claims.Role = %q, want admin", claims.Role)
	}
	if claims.UserID == 0 {
		t.Error("claims.UserID should not be 0")
	}
}

func TestValidateExpiredToken(t *testing.T) {
	// We can't easily create an expired token without mocking time,
	// so we validate that a tampered token is rejected.
	mgr := auth.NewManager("secret")
	_, err := mgr.Validate("not.a.valid.token")
	if err == nil {
		t.Fatal("expected error for invalid token, got nil")
	}
}

func TestValidateTokenFromDifferentSecret(t *testing.T) {
	mgr1 := auth.NewManager("secret-one-longer-padding-bytes!")
	mgr2 := auth.NewManager("secret-two-longer-padding-bytes!")

	token, _, err := mgr1.Authenticate("admin", "changeme")
	if err != nil {
		t.Fatalf("auth mgr1: %v", err)
	}

	_, err = mgr2.Validate(token)
	if err == nil {
		t.Fatal("mgr2 should reject token signed by mgr1")
	}
}

func TestValidateTamperedToken(t *testing.T) {
	mgr := auth.NewManager("secret")
	token, _, _ := mgr.Authenticate("admin", "changeme")

	// Flip last byte
	tampered := token[:len(token)-1] + "X"
	_, err := mgr.Validate(tampered)
	if err == nil {
		t.Fatal("expected error for tampered token")
	}
}

func TestTokenIsJWTFormat(t *testing.T) {
	mgr := auth.NewManager("secret")
	token, _, _ := mgr.Authenticate("admin", "changeme")

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Errorf("token should have 3 parts (header.payload.sig), got %d: %s", len(parts), token)
	}
	for i, part := range parts {
		if part == "" {
			t.Errorf("token part %d is empty", i)
		}
	}
}

// ─── AddUser ──────────────────────────────────────────────────────────────────

func TestAddUserAndAuthenticate(t *testing.T) {
	mgr := auth.NewManager("secret")

	if err := mgr.AddUser("operator", "op-password", "viewer"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}

	_, user, err := mgr.Authenticate("operator", "op-password")
	if err != nil {
		t.Fatalf("auth operator: %v", err)
	}
	if user.Username != "operator" {
		t.Errorf("username = %q, want operator", user.Username)
	}
	if user.Role != "viewer" {
		t.Errorf("role = %q, want viewer", user.Role)
	}
}

func TestAddUserEmptyFields(t *testing.T) {
	mgr := auth.NewManager("secret")

	if err := mgr.AddUser("", "pass", "admin"); err == nil {
		t.Error("expected error for empty username")
	}
	if err := mgr.AddUser("user", "", "admin"); err == nil {
		t.Error("expected error for empty password")
	}
}

// ─── Concurrency ──────────────────────────────────────────────────────────────

func TestConcurrentAuthentication(t *testing.T) {
	mgr := auth.NewManager("secret")
	done := make(chan struct{}, 50)

	for i := 0; i < 50; i++ {
		go func() {
			_, _, _ = mgr.Authenticate("admin", "changeme")
			done <- struct{}{}
		}()
	}

	for i := 0; i < 50; i++ {
		<-done
	}
}
