package service

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/voice0726/auth-gateway/internal/config"
	"github.com/voice0726/auth-gateway/internal/model"
)

var ErrNotAuthenticated = errors.New("not authenticated")

type AuthService struct {
	cfg        config.Config
	idp        IdentityProvider
	sessionSrv SessionService
	stateSrv   LoginStateService
	logger     *zap.Logger
}

func NewAuthService(cfg config.Config, identityProvider IdentityProvider, sessionSrv SessionService, stateSrv LoginStateService, logger *zap.Logger) *AuthService {
	return &AuthService{
		cfg:        cfg,
		idp:        identityProvider,
		sessionSrv: sessionSrv,
		stateSrv:   stateSrv,
		logger:     logger,
	}
}

func (s *AuthService) StartLogin(w http.ResponseWriter, r *http.Request, redirect string) error {
	hasRedirect := redirect != ""
	redirect = SafeRedirect(redirect, LoginRedirectFallback)
	state := uuid.NewString()
	s.logger.Debug("login start",
		zap.Bool("has_redirect", hasRedirect),
	)
	if err := s.stateSrv.Set(state, redirect, time.Now().Add(s.cfg.StateTTL)); err != nil {
		return err
	}
	s.idp.Authenticate(w, r, state)
	return nil
}

func (s *AuthService) HandleCallback(w http.ResponseWriter, r *http.Request, sessionID string) (string, model.Session, error) {
	s.logger.Debug("callback start")
	sess, state, err := s.idp.Callback(w, r, sessionID)
	if err != nil {
		return "", model.Session{}, err
	}
	redirect, err := s.stateSrv.Get(state)
	if err != nil {
		return "", model.Session{}, err
	}
	redirect = SafeRedirect(redirect, LoginRedirectFallback)
	_ = s.stateSrv.Delete(state)
	if err := s.sessionSrv.Create(sess); err != nil {
		return "", model.Session{}, err
	}
	s.logger.Debug("callback completed")
	return redirect, sess, nil
}

func (s *AuthService) HandleLogout(w http.ResponseWriter, r *http.Request, sessionID string, redirect string) (bool, error) {
	if err := s.sessionSrv.Delete(sessionID); err != nil {
		return false, err
	}
	s.logger.Debug("logout completed")
	return false, nil
}

func (s *AuthService) GetSession(sessionID string) (model.Session, error) {
	return s.sessionSrv.Get(sessionID)
}
