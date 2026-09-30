package auth

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/zitadel/oidc/v3/pkg/crypto"
	"go.uber.org/zap"

	"github.com/voice0726/auth-gateway/internal/config"
	"github.com/voice0726/auth-gateway/internal/model"
	"github.com/voice0726/auth-gateway/internal/service"
)

var errInvalidSession = errors.New("invalid session")

// Handler handles OAuth/OIDC flows and session management.
type Handler struct {
	cfg     config.Config
	service *service.AuthService
	logger  *zap.Logger
}

func NewHandler(cfg config.Config, service *service.AuthService, logger *zap.Logger) (*Handler, error) {
	return &Handler{
		cfg:     cfg,
		service: service,
		logger:  logger,
	}, nil
}

func (s *Handler) Login(c echo.Context) error {
	redirect := c.QueryParam("redirect")
	if err := s.service.StartLogin(c.Response().Writer, c.Request(), redirect); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "state store failed")
	}
	return nil
}

func (s *Handler) Callback(c echo.Context) error {
	// Ignore React Server Components prefetch requests to avoid consuming OIDC state twice.
	if c.QueryParam("_rsc") != "" {
		return c.NoContent(http.StatusNoContent)
	}
	sessionID := uuid.NewString()
	redirect, sess, err := s.service.HandleCallback(c.Response().Writer, c.Request(), sessionID)
	if err != nil {
		if c.Response().Committed {
			return nil
		}
		if errors.Is(err, service.ErrNotAuthenticated) {
			return echo.NewHTTPError(http.StatusUnauthorized, "not authenticated")
		}
		if errors.Is(err, service.ErrStateNotFound) || errors.Is(err, service.ErrStateExpired) {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid state")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "callback failed")
	}
	if err := s.setSessionCookie(c, sessionID, sess.ExpiresAt); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "set cookie failed")
	}
	return c.Redirect(http.StatusFound, redirect)
}

func (s *Handler) Logout(c echo.Context) error {
	redirect := c.QueryParam("redirect")
	s.logger.Debug("logout request received",
		zap.Bool("has_redirect", redirect != ""),
	)

	sessionID, err := s.sessionIDFromRequest(c.Request())
	if err != nil {
		s.logger.Debug("logout request missing session")
		s.clearSessionCookie(c)
		return c.NoContent(http.StatusNoContent)
	}

	ok, err := s.service.HandleLogout(c.Response().Writer, c.Request(), sessionID, redirect)
	if err != nil {
		s.logger.Debug("logout request failed")
		return echo.NewHTTPError(http.StatusInternalServerError, "logout failed")
	}
	s.clearSessionCookie(c)
	if ok {
		s.logger.Debug("logout request completed", zap.Bool("idp_redirected", ok))
		return nil
	}
	s.logger.Debug("logout request completed without redirect", zap.Bool("idp_redirected", ok))
	return c.NoContent(http.StatusNoContent)
}

func (s *Handler) Me(c echo.Context) error {
	// NOTE: フロント向けに最小限の情報を返す想定のため、内部向けとは分けている。
	return s.respondSession(c)
}

func (s *Handler) InternalSession(c echo.Context) error {
	// NOTE: 内部向けに追加情報を返す可能性があるため、フロント向けとは分けている。
	return s.respondSession(c)
}

func sessionResponse(sess model.Session) map[string]any {
	return map[string]any{
		"user_id": sess.UserID,
		"roles":   sess.RolesSlice(),
		"email":   sess.Email,
		"name":    sess.Name,
	}
}

func (s *Handler) respondSession(c echo.Context) error {
	sess, err := s.sessionFromRequest(c.Request())
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
	}
	return c.JSON(http.StatusOK, sessionResponse(sess))
}

func (s *Handler) sessionFromRequest(r *http.Request) (model.Session, error) {
	sessionID, err := s.sessionIDFromRequest(r)
	if err != nil {
		return model.Session{}, err
	}
	sess, err := s.service.GetSession(sessionID)
	if err != nil {
		return model.Session{}, errInvalidSession
	}
	return sess, nil
}

func (s *Handler) sessionIDFromRequest(r *http.Request) (string, error) {
	cookie, err := r.Cookie(s.cfg.CookieName)
	if err != nil {
		return "", errInvalidSession
	}
	sessionID, err := crypto.DecryptAES(cookie.Value, s.cfg.SessionSecret)
	if err != nil {
		return "", errInvalidSession
	}
	return sessionID, nil
}

func (s *Handler) setSessionCookie(c echo.Context, sessionID string, expiresAt time.Time) error {
	value, err := crypto.EncryptAES(sessionID, s.cfg.SessionSecret)
	if err != nil {
		return err
	}
	cookie := &http.Cookie{
		Name:     s.cfg.CookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: s.cfg.CookieSameSite,
	}
	if s.cfg.CookieDomain != "" {
		cookie.Domain = s.cfg.CookieDomain
	}
	if !expiresAt.IsZero() {
		cookie.Expires = expiresAt
		cookie.MaxAge = int(time.Until(expiresAt).Seconds())
	}
	c.SetCookie(cookie)
	return nil
}

func (s *Handler) clearSessionCookie(c echo.Context) {
	cookie := &http.Cookie{
		Name:     s.cfg.CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: s.cfg.CookieSameSite,
		MaxAge:   -1,
	}
	if s.cfg.CookieDomain != "" {
		cookie.Domain = s.cfg.CookieDomain
	}
	c.SetCookie(cookie)
}
