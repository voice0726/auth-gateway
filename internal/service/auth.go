package service

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/voice0726/auth-gateway/internal/config"
	"github.com/voice0726/auth-gateway/internal/model"
)

var ErrNotAuthenticated = errors.New("not authenticated")

type AuthService struct {
	cfg        config.Config
	idp        IdentityProvider
	sessionSrv SessionService
	stateSrv   LoginStateService
}

func NewAuthService(cfg config.Config, identityProvider IdentityProvider, sessionSrv SessionService, stateSrv LoginStateService) *AuthService {
	return &AuthService{
		cfg:        cfg,
		idp:        identityProvider,
		sessionSrv: sessionSrv,
		stateSrv:   stateSrv,
	}
}

func (s *AuthService) StartLogin(w http.ResponseWriter, r *http.Request, redirect string) error {
	if redirect == "" {
		redirect = s.cfg.FrontendRedirectURL
	}
	state := uuid.NewString()
	if err := s.stateSrv.Set(state, redirect, time.Now().Add(s.cfg.StateTTL)); err != nil {
		return err
	}
	s.idp.Authenticate(w, r, state)
	return nil
}

func (s *AuthService) HandleCallback(w http.ResponseWriter, r *http.Request, sessionID string) (string, model.Session, error) {
	sess, state, err := s.idp.Callback(w, r, sessionID)
	if err != nil {
		return "", model.Session{}, err
	}
	redirect, err := s.stateSrv.Get(state)
	if err != nil {
		return "", model.Session{}, err
	}
	_ = s.stateSrv.Delete(state)
	if err := s.sessionSrv.Create(sess); err != nil {
		return "", model.Session{}, err
	}
	return redirect, sess, nil
}

func (s *AuthService) HandleLogout(w http.ResponseWriter, r *http.Request, sessionID string, redirect string) (bool, error) {
	if redirect == "" {
		redirect = s.cfg.FrontendRedirectURL
	}
	sess, err := s.sessionSrv.Get(sessionID)
	if err != nil {
		_ = s.sessionSrv.Delete(sessionID)
		return false, nil
	}
	_ = s.sessionSrv.Delete(sessionID)
	state := uuid.NewString()
	return s.idp.Logout(w, r, sess, state, redirect), nil
}

func (s *AuthService) GetSession(sessionID string) (model.Session, error) {
	return s.sessionSrv.Get(sessionID)
}
