package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/tntrock/certower/internal/auth"
	"github.com/tntrock/certower/internal/store"
)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token     string      `json:"token"`
	ExpiresAt time.Time   `json:"expiresAt"`
	User      *store.User `json:"user"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decode(w, r, &req) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	ip := s.clientIP(r)
	if wait := s.logins.check(email, ip); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, "too_many_attempts", "too many failed logins; try again later")
		return
	}
	u, err := s.store.GetUserByEmail(r.Context(), email)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internal(w, err)
		return
	}
	hash := ""
	if u != nil && !u.Disabled {
		hash = u.PasswordHash
	}
	// Always verify, so unknown accounts take as long as wrong passwords.
	if !auth.VerifyPassword(hash, req.Password) {
		s.logins.fail(email, ip)
		s.log.Warn("failed login", "email", email, "ip", ip)
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
		return
	}
	s.logins.succeed(email)

	token, tokenHash := auth.NewToken(auth.SessionPrefix)
	expires := time.Now().Add(s.SessionTTL).UTC()
	if err := s.store.CreateSession(r.Context(), u.ID, tokenHash, expires); err != nil {
		s.internal(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   s.SecureCookies,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, loginResponse{Token: token, ExpiresAt: expires, User: u})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, p *principal) {
	if p.user != nil {
		if err := s.store.DeleteSession(r.Context(), auth.HashToken(p.token)); err != nil {
			s.internal(w, err)
			return
		}
	}
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.SecureCookies, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

type meResponse struct {
	Type           string                `json:"type"`
	User           *store.User           `json:"user,omitempty"`
	ServiceAccount *store.ServiceAccount `json:"serviceAccount,omitempty"`
	Bindings       []store.RoleBinding   `json:"bindings"`
}

func (s *Server) me(w http.ResponseWriter, r *http.Request, p *principal) {
	typ, _ := p.actor()
	writeJSON(w, http.StatusOK, meResponse{Type: typ, User: p.user, ServiceAccount: p.sa, Bindings: nonNil(p.bindings)})
}

// nonNil makes empty lists encode as [] rather than null.
func nonNil[T any](xs []T) []T {
	if xs == nil {
		return []T{}
	}
	return xs
}
