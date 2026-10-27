package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/voice0726/auth-gateway/internal/config"
	authhandler "github.com/voice0726/auth-gateway/internal/handler/auth"
	"github.com/voice0726/auth-gateway/internal/model"
	"github.com/voice0726/auth-gateway/internal/service"
	"go.uber.org/zap"
)

// rejectingIDP は、OIDC ライブラリが state 不一致などで自らエラー応答を書く場合を再現する。
type rejectingIDP struct{}

func (rejectingIDP) Authenticate(http.ResponseWriter, *http.Request, string) {}
func (rejectingIDP) Callback(w http.ResponseWriter, _ *http.Request, _ string) (model.Session, string, error) {
	http.Error(w, "idp error", http.StatusInternalServerError)
	return model.Session{}, "", service.ErrNotAuthenticated
}

func TestCallbackKeepsResponseWrittenByIdentityProvider(t *testing.T) {
	cfg := config.Config{AppID: "react", FrontendOrigin: "https://react.example.test", CookieName: "react_session", SessionSecret: "0123456789abcdef", InternalToken: "react-test-token"}
	svc := service.NewAuthService(cfg, rejectingIDP{}, nil, nil, zap.NewNop())
	handler, err := authhandler.NewHandler(cfg, svc, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	e := echo.New()
	registerRoutes(e, []appRoutes{newAppRoutes(cfg, handler)})
	r := httptest.NewRequest(http.MethodGet, "/auth/callback?state=oauth-state", nil)
	r.Header.Set("X-App-Id", cfg.AppID)
	w := httptest.NewRecorder()

	e.ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError || w.Body.String() != "idp error\n" {
		t.Fatalf("status=%d body=%q, want the identity provider response only", w.Code, w.Body.String())
	}
}
