package api

import (
	"context"
	"testing"
	"time"

	"github.com/tntrock/certower/internal/auth"
	"github.com/tntrock/certower/internal/store"
)

func TestChangeOwnPassword(t *testing.T) {
	e := newEnv(t)
	tok := e.user("ops@example.com", false)
	var other loginResponse
	e.do("", "POST", "/api/v1/auth/login", loginRequest{Email: "ops@example.com", Password: "long enough password"}, 200, &other)

	e.do(tok, "POST", "/api/v1/me/password", changePasswordRequest{CurrentPassword: "wrong", NewPassword: "a brand new password"}, 400, nil)
	e.do(tok, "POST", "/api/v1/me/password", changePasswordRequest{CurrentPassword: "long enough password", NewPassword: "short"}, 400, nil)
	e.do(tok, "POST", "/api/v1/me/password", changePasswordRequest{CurrentPassword: "long enough password", NewPassword: "a brand new password"}, 204, nil)

	// This session survives; the other is signed out.
	e.do(tok, "GET", "/api/v1/me", nil, 200, nil)
	e.do(other.Token, "GET", "/api/v1/me", nil, 401, nil)
	e.do("", "POST", "/api/v1/auth/login", loginRequest{Email: "ops@example.com", Password: "long enough password"}, 401, nil)
	e.do("", "POST", "/api/v1/auth/login", loginRequest{Email: "ops@example.com", Password: "a brand new password"}, 200, nil)

	// SSO-only accounts have no password to change.
	ctx := context.Background()
	sso, _ := e.st.CreateOIDCUser(ctx, "sso@example.com", "", "https://idp.example.com", "s1")
	ssoTok, hash := auth.NewToken(auth.SessionPrefix)
	e.st.CreateSession(ctx, sso.ID, hash, time.Now().Add(time.Hour))
	e.do(ssoTok, "POST", "/api/v1/me/password", changePasswordRequest{CurrentPassword: "", NewPassword: "a brand new password"}, 400, nil)
}

func TestAdministerUsers(t *testing.T) {
	e := newEnv(t)
	admin := e.user("admin@example.com", true)
	ops := e.user("ops@example.com", false)
	var me meResponse
	e.do(admin, "GET", "/api/v1/me", nil, 200, &me)
	u, _ := e.st.GetUserByEmail(context.Background(), "ops@example.com")
	path := "/api/v1/users/" + u.ID
	yes, no := true, false

	e.do(ops, "PATCH", path, updateUserRequest{Disabled: &yes}, 403, nil)
	e.do(admin, "PATCH", "/api/v1/users/"+me.User.ID, updateUserRequest{Disabled: &yes}, 400, nil)
	e.do(admin, "PATCH", "/api/v1/users/"+me.User.ID, updateUserRequest{IsSuperuser: &no}, 400, nil)
	e.do(admin, "PATCH", "/api/v1/users/nonexistent", updateUserRequest{Disabled: &yes}, 404, nil)

	// Disabling signs the user out and blocks login.
	var got store.User
	e.do(admin, "PATCH", path, updateUserRequest{Disabled: &yes}, 200, &got)
	if !got.Disabled {
		t.Fatalf("not disabled: %+v", got)
	}
	e.do(ops, "GET", "/api/v1/me", nil, 401, nil)
	e.do("", "POST", "/api/v1/auth/login", loginRequest{Email: "ops@example.com", Password: "long enough password"}, 401, nil)

	// Re-enable and reset the password.
	pw := "reset by the admin"
	e.do(admin, "PATCH", path, updateUserRequest{Disabled: &no, Password: &pw}, 200, &got)
	if got.Disabled {
		t.Fatal("still disabled")
	}
	e.do("", "POST", "/api/v1/auth/login", loginRequest{Email: "ops@example.com", Password: "long enough password"}, 401, nil)
	e.do("", "POST", "/api/v1/auth/login", loginRequest{Email: "ops@example.com", Password: pw}, 200, nil)
	short := "short"
	e.do(admin, "PATCH", path, updateUserRequest{Password: &short}, 400, nil)

	// Promote to instance administrator.
	e.do(admin, "PATCH", path, updateUserRequest{IsSuperuser: &yes}, 200, &got)
	if !got.IsSuperuser || !got.HasPassword {
		t.Fatalf("promote: %+v", got)
	}

	var users []store.User
	e.do(admin, "GET", "/api/v1/users", nil, 200, &users)
	if len(users) != 2 {
		t.Fatalf("users = %d", len(users))
	}
}
