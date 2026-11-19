package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/tntrock/certower/internal/auth"
	"github.com/tntrock/certower/internal/store"
)

type changePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

// changePassword lets a person change their own password. Their other
// sessions are signed out.
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request, p *principal) {
	if p.user == nil {
		writeError(w, http.StatusForbidden, "forbidden", "only people have passwords")
		return
	}
	var req changePasswordRequest
	if !decode(w, r, &req) {
		return
	}
	u, ip := p.user, s.clientIP(r)
	if !u.HasPassword {
		writeError(w, http.StatusBadRequest, "no_password", "this account signs in through single sign-on")
		return
	}
	// Guessing the current password from a stolen session is still guessing.
	if wait := s.logins.check(u.Email, ip); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, "too_many_attempts", "too many failed attempts; try again later")
		return
	}
	if !auth.VerifyPassword(u.PasswordHash, req.CurrentPassword) {
		s.logins.fail(u.Email, ip)
		writeError(w, http.StatusBadRequest, "wrong_password", "the current password is wrong")
		return
	}
	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusBadRequest, "weak_password", err.Error())
		return
	}
	if err := s.store.SetUserPassword(r.Context(), u.ID, hash); err != nil {
		s.internal(w, err)
		return
	}
	if err := s.store.DeleteUserSessions(r.Context(), u.ID, auth.HashToken(p.token)); err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, p, "", "", "user.password_change", "user", u.ID, nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

type updateUserRequest struct {
	Disabled    *bool   `json:"disabled,omitempty"`
	IsSuperuser *bool   `json:"isSuperuser,omitempty"`
	Password    *string `json:"password,omitempty"`
}

// updateUser lets instance administrators disable accounts, grant or remove
// instance administration, and reset passwords. Disabling an account or
// resetting its password signs it out everywhere.
func (s *Server) updateUser(w http.ResponseWriter, r *http.Request, p *principal) {
	if !p.superuser() {
		writeError(w, http.StatusForbidden, "forbidden", "only instance administrators can change users")
		return
	}
	u, err := s.store.GetUser(r.Context(), r.PathValue("user"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "user not found")
		return
	} else if err != nil {
		s.internal(w, err)
		return
	}
	var req updateUserRequest
	if !decode(w, r, &req) {
		return
	}
	disabled, superuser := u.Disabled, u.IsSuperuser
	if req.Disabled != nil {
		disabled = *req.Disabled
	}
	if req.IsSuperuser != nil {
		superuser = *req.IsSuperuser
	}
	if u.ID == p.user.ID && (disabled || !superuser) {
		writeError(w, http.StatusBadRequest, "self_lockout", "you cannot disable your own account or remove your own administrator rights")
		return
	}
	var hash string
	if req.Password != nil {
		if hash, err = auth.HashPassword(*req.Password); err != nil {
			writeError(w, http.StatusBadRequest, "weak_password", err.Error())
			return
		}
	}

	err = s.store.InTx(r.Context(), func(tx *store.Store) error {
		if err := tx.SetUserFlags(r.Context(), u.ID, disabled, superuser); err != nil {
			return err
		}
		if hash != "" {
			if err := tx.SetUserPassword(r.Context(), u.ID, hash); err != nil {
				return err
			}
		}
		if disabled || hash != "" {
			return tx.DeleteUserSessions(r.Context(), u.ID, nil)
		}
		return nil
	})
	if err != nil {
		s.internal(w, err)
		return
	}
	after, err := s.store.GetUser(r.Context(), u.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	// The audit record says a password was reset, never what it is.
	s.audit(r, p, "", "", "user.update", "user", u.ID,
		map[string]any{"disabled": u.Disabled, "isSuperuser": u.IsSuperuser},
		map[string]any{"disabled": after.Disabled, "isSuperuser": after.IsSuperuser, "passwordReset": hash != ""})
	writeJSON(w, http.StatusOK, after)
}
