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
	if redirect == "" {
		redirect = s.cfg.FrontendPostLogoutURL
	}
	state := uuid.NewString()
	s.logger.Debug("login start",
		zap.String("redirect", redirect),
		zap.String("state_prefix", statePrefix(state)),
	)
	if err := s.stateSrv.Set(state, redirect, time.Now().Add(s.cfg.StateTTL)); err != nil {
		return err
	}
	s.idp.Authenticate(w, r, state)
	return nil
}

func (s *AuthService) HandleCallback(w http.ResponseWriter, r *http.Request, sessionID string) (string, model.Session, error) {
	s.logger.Debug("callback start",
		zap.String("session_id_prefix", statePrefix(sessionID)),
	)
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
	s.logger.Debug("callback completed",
		zap.String("redirect", redirect),
		zap.String("session_id_prefix", statePrefix(sessionID)),
	)
	return redirect, sess, nil
}

func (s *AuthService) HandleLogout(w http.ResponseWriter, r *http.Request, sessionID string, redirect string) (bool, error) {
	if redirect == "" {
		redirect = s.cfg.FrontendPostLogoutURL
	}
	s.logger.Debug("logout start",
		zap.String("redirect", redirect),
		zap.String("session_id_prefix", statePrefix(sessionID)),
	)
	sess, err := s.sessionSrv.Get(sessionID)
	if err != nil {
		_ = s.sessionSrv.Delete(sessionID)
		s.logger.Debug("logout session not found",
			zap.String("session_id_prefix", statePrefix(sessionID)),
		)
		return false, nil
	}
	_ = s.sessionSrv.Delete(sessionID)
	state := uuid.NewString()
	ok := s.idp.Logout(w, r, sess, state, redirect)
	s.logger.Debug("logout completed",
		zap.Bool("idp_redirected", ok),
		zap.String("state_prefix", statePrefix(state)),
	)
	return ok, nil
}

func (s *AuthService) GetSession(sessionID string) (model.Session, error) {
	return s.sessionSrv.Get(sessionID)
}

func statePrefix(value string) string {
	if len(value) <= 8 {
		return value
	}
	return value[:8]
}
