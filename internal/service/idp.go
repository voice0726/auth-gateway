package service

import (
	"net/http"

	"github.com/voice0726/auth-gateway/internal/model"
)

type IdentityProvider interface {
	Authenticate(w http.ResponseWriter, r *http.Request, state string)
	Callback(w http.ResponseWriter, r *http.Request, sessionID string) (model.Session, string, error)
	Logout(w http.ResponseWriter, r *http.Request, sess model.Session, state string, redirect string) (bool, error)
}
