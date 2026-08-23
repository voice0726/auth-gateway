package zitadel

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/zitadel-go/v3/pkg/authentication"
	openid "github.com/zitadel/zitadel-go/v3/pkg/authentication/oidc"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
	"golang.org/x/oauth2"

	"github.com/voice0726/auth-gateway/internal/config"
	"github.com/voice0726/auth-gateway/internal/model"
	"github.com/voice0726/auth-gateway/internal/service"
)

type Client struct {
	cfg     config.Config
	handler authentication.Handler[*openid.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]]
}

func NewClient(cfg config.Config) (*Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	handler, err := newClient(ctx, cfg)
	if err != nil {
		return nil, err
	}

	return &Client{
		cfg:     cfg,
		handler: handler,
	}, nil
}

func newClient(ctx context.Context, cfg config.Config) (authentication.Handler[*openid.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]], error) {
	cookieOpts := []httphelper.CookieHandlerOpt{
		httphelper.WithSameSite(cfg.CookieSameSite),
	}
	if !cfg.CookieSecure {
		cookieOpts = append(cookieOpts, httphelper.WithUnsecure())
	}
	if cfg.CookieDomain != "" {
		cookieOpts = append(cookieOpts, httphelper.WithDomain(cfg.CookieDomain))
	}

	cookieHandler := httphelper.NewCookieHandler([]byte(cfg.SessionSecret), []byte(cfg.SessionSecret), cookieOpts...)

	initializer := openid.WithCodeFlow[*openid.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo], *oidc.IDTokenClaims, *oidc.UserInfo](
		openid.PKCEAuthentication(cfg.ZitadelClientID, cfg.ZitadelRedirectURI, cfg.ZitadelScopes, cookieHandler),
	)
	return initializer(ctx, zitadel.New(cfg.ZitadelIssuer, zitadelOptions(cfg)...))
}

func zitadelOptions(cfg config.Config) []zitadel.Option {
	options := make([]zitadel.Option, 0, 2)
	if cfg.ZitadelInsecure {
		port := "80"
		if cfg.ZitadelPort > 0 {
			port = strconv.Itoa(cfg.ZitadelPort)
		}
		options = append(options, zitadel.WithInsecure(port))
		return options
	}
	if cfg.ZitadelPort > 0 && cfg.ZitadelPort != 443 {
		options = append(options, zitadel.WithPort(uint16(cfg.ZitadelPort)))
	}
	return options
}

func (c *Client) Authenticate(w http.ResponseWriter, r *http.Request, state string) {
	c.handler.Authenticate(w, r, state)
}

func (c *Client) Callback(w http.ResponseWriter, r *http.Request, sessionID string) (model.Session, string, error) {
	authCtx, state := c.handler.Callback(w, r)
	if authCtx == nil || !authCtx.IsAuthenticated() {
		return model.Session{}, state, service.ErrNotAuthenticated
	}
	sess, err := c.buildSession(sessionID, authCtx)
	if err != nil {
		return model.Session{}, state, err
	}
	return sess, state, nil
}

func (c *Client) Logout(w http.ResponseWriter, r *http.Request, sess model.Session, state string, redirect string) (bool, error) {
	if sess.IDToken == "" {
		return false, errors.New("id token is empty")
	}
	ctx := &openid.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]{
		Tokens: &oidc.Tokens[*oidc.IDTokenClaims]{
			Token: &oauth2.Token{
				AccessToken:  sess.AccessToken,
				RefreshToken: sess.RefreshToken,
				Expiry:       sess.ExpiresAt,
			},
			IDToken: sess.IDToken,
		},
	}
	c.handler.Logout(w, r, ctx, state, redirect)
	return true, nil
}

func (c *Client) buildSession(id string, authCtx *openid.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]) (model.Session, error) {
	sess := model.Session{ID: id}
	if authCtx == nil {
		return sess, nil
	}

	userInfo := authCtx.GetUserInfo()
	tokens := authCtx.GetTokens()

	claims := map[string]any{}
	if userInfo != nil && userInfo.Claims != nil {
		for k, v := range userInfo.Claims {
			claims[k] = v
		}
	}
	if tokens != nil && tokens.IDTokenClaims != nil && tokens.IDTokenClaims.Claims != nil {
		for k, v := range tokens.IDTokenClaims.Claims {
			claims[k] = v
		}
	}

	userID := ""
	if userInfo != nil {
		userID = userInfo.Subject
	}
	if userID == "" && tokens != nil && tokens.IDTokenClaims != nil {
		userID = tokens.IDTokenClaims.Subject
	}

	name := ""
	email := ""
	if userInfo != nil {
		name = userInfo.Name
		if name == "" {
			name = userInfo.PreferredUsername
		}
		email = userInfo.Email
	}

	sess.UserID = userID
	sess.Name = name
	sess.Email = email
	if err := sess.SetRoles(extractRoles(claims)); err != nil {
		return model.Session{}, err
	}
	if err := sess.SetClaims(claims); err != nil {
		return model.Session{}, err
	}
	if tokens != nil {
		sess.AccessToken = tokens.AccessToken
		sess.RefreshToken = tokens.RefreshToken
		sess.IDToken = tokens.IDToken
		sess.ExpiresAt = tokens.Expiry
	}
	if c.cfg.SessionTTL > 0 {
		maxExpiry := time.Now().Add(c.cfg.SessionTTL)
		if sess.ExpiresAt.IsZero() || maxExpiry.Before(sess.ExpiresAt) {
			sess.ExpiresAt = maxExpiry
		}
	}
	return sess, nil
}

func extractRoles(claims map[string]any) []string {
	for _, key := range []string{"roles", "role", "urn:zitadel:iam:org:project:roles"} {
		value, ok := claims[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case []string:
			return uniqueStrings(typed)
		case []any:
			roles := make([]string, 0, len(typed))
			for _, item := range typed {
				if str, ok := item.(string); ok {
					roles = append(roles, str)
				}
			}
			return uniqueStrings(roles)
		case map[string]any:
			roles := make([]string, 0, len(typed))
			for role := range typed {
				roles = append(roles, role)
			}
			return uniqueStrings(roles)
		case string:
			if typed != "" {
				return []string{typed}
			}
		}
	}
	return nil
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
