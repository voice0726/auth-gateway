package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/voice0726/auth-gateway/internal/config"
	authhandler "github.com/voice0726/auth-gateway/internal/handler/auth"
	"github.com/voice0726/auth-gateway/internal/model"
	"github.com/voice0726/auth-gateway/internal/service"
	"github.com/zitadel/oidc/v3/pkg/crypto"
	"go.uber.org/zap"
)

type appSessions struct {
	records    map[string]model.Session
	failDelete bool
}

func (s *appSessions) Create(v model.Session) error { s.records[v.ID] = v; return nil }
func (s *appSessions) Get(id string) (model.Session, error) {
	v, ok := s.records[id]
	if !ok {
		return v, model.ErrSessionNotFound
	}
	return v, nil
}
func (s *appSessions) Delete(id string) error {
	if s.failDelete {
		return service.ErrNotAuthenticated
	}
	delete(s.records, id)
	return nil
}

func TestApplicationSessionAndLogoutIsolation(t *testing.T) {
	e := echo.New()
	configs := []config.Config{
		{AppID: "react", FrontendOrigin: "https://react.example.test", CookieName: "react_session", SessionSecret: "0123456789abcdef", InternalToken: "react-test-token"},
		{AppID: "tanstack", FrontendOrigin: "https://tanstack.example.test", CookieName: "tanstack_session", SessionSecret: "fedcba9876543210", InternalToken: "tanstack-test-token"},
	}
	stores := []*appSessions{}
	cookies := []*http.Cookie{}
	apps := []appRoutes{}
	for _, cfg := range configs {
		id := cfg.AppID + "-session"
		store := &appSessions{records: map[string]model.Session{id: {ID: id, UserID: "same-user", ExpiresAt: time.Now().Add(time.Hour)}}}
		stores = append(stores, store)
		// IDPを渡さず、ログアウトが本人確認基盤に依存しないことも検証する。
		svc := service.NewAuthService(cfg, nil, store, nil, zap.NewNop())
		handler, err := authhandler.NewHandler(cfg, svc, zap.NewNop())
		if err != nil {
			t.Fatal(err)
		}
		apps = append(apps, newAppRoutes(cfg, handler))
		value, err := crypto.EncryptAES(id, cfg.SessionSecret)
		if err != nil {
			t.Fatal(err)
		}
		cookies = append(cookies, &http.Cookie{Name: cfg.CookieName, Value: value})
	}
	registerRoutes(e, apps)
	request := func(method, path, appID, origin, token string, cookie *http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, nil)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		r.Header.Set("Origin", origin)
		r.Header.Set("X-Internal-Token", token)
		if appID != "" {
			r.Header.Set("X-App-Id", appID)
		}
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		return w
	}
	for i, cfg := range configs {
		w := request("GET", "/auth/me", cfg.AppID, "", "", cookies[i])
		if w.Code != 200 {
			t.Fatalf("own session: %d", w.Code)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("auth response must not be cacheable: %q", w.Header().Get("Cache-Control"))
		}
		w = request("GET", "/internal/session", "", "", cfg.InternalToken, cookies[i])
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("own internal session: %d", w.Code)
		}
		other := 1 - i
		// 他アプリのトークンはそのアプリの設定で検証され、このアプリの Cookie は復号できない。
		if w := request("GET", "/internal/session", "", "", configs[other].InternalToken, cookies[i]); w.Code != 401 {
			t.Fatalf("foreign backend token: %d", w.Code)
		}
		// X-App-Id は内部APIの認証に使わない。
		if w := request("GET", "/internal/session", cfg.AppID, "", "", cookies[i]); w.Code != 401 {
			t.Fatalf("internal session without token: %d", w.Code)
		}
		forged := &http.Cookie{Name: cfg.CookieName, Value: cookies[other].Value}
		if w := request("GET", "/auth/me", cfg.AppID, "", "", forged); w.Code != 401 {
			t.Fatalf("renamed foreign cookie: %d", w.Code)
		}
		if w := request("POST", "/auth/logout", cfg.AppID, configs[other].FrontendOrigin, "", cookies[i]); w.Code != 403 {
			t.Fatalf("foreign logout origin: %d", w.Code)
		}
		// 他アプリの識別子を名乗っても、そのアプリの Cookie 名・鍵が必要。
		if w := request("GET", "/auth/me", configs[other].AppID, "", "", cookies[i]); w.Code != 401 {
			t.Fatalf("cookie used under another application id: %d", w.Code)
		}
	}
	stores[0].failDelete = true
	w := request("POST", "/auth/logout", "react", configs[0].FrontendOrigin, "", cookies[0])
	if w.Code != 500 || len(w.Result().Cookies()) != 0 {
		t.Fatal("failed deletion must not report successful logout or clear cookie")
	}
	stores[0].failDelete = false
	w = request("POST", "/auth/logout", "react", configs[0].FrontendOrigin, "", cookies[0])
	if w.Code != 204 {
		t.Fatalf("logout: %d", w.Code)
	}
	cleared := w.Result().Cookies()
	if len(cleared) != 1 || cleared[0].Name != configs[0].CookieName || cleared[0].MaxAge != -1 || cleared[0].Domain != "" {
		t.Fatalf("logout cookie: %#v", cleared)
	}
	if w := request("GET", "/auth/me", "react", "", "", cookies[0]); w.Code != 401 {
		t.Fatalf("logged out session: %d", w.Code)
	}
	if w := request("GET", "/auth/me", "tanstack", "", "", cookies[1]); w.Code != 200 {
		t.Fatalf("other app must remain logged in: %d", w.Code)
	}
	for _, appID := range []string{"", "unknown", "REACT", "react,tanstack"} {
		if w := request("GET", "/auth/me", appID, "", "", cookies[1]); w.Code != 400 {
			t.Fatalf("missing or unknown application id %q: %d", appID, w.Code)
		}
	}
	for _, path := range []string{"/auth/react/me", "/internal/react/session"} {
		if w := request("GET", path, "react", "", configs[0].InternalToken, cookies[1]); w.Code != 404 {
			t.Fatalf("path-scoped API must not exist: %s %d", path, w.Code)
		}
	}
}

func TestInternalTokenLookup(t *testing.T) {
	apps := []appRoutes{{id: "a", internalToken: "token-a"}, {id: "b", internalToken: "token-b"}, {id: "unset"}}
	if app, ok := appByInternalToken(apps, "token-b"); !ok || app.id != "b" {
		t.Fatalf("got %q %v", app.id, ok)
	}
	for _, token := range []string{"", "token", "token-a ", "TOKEN-A"} {
		if _, ok := appByInternalToken(apps, token); ok {
			t.Fatalf("token %q accepted", token)
		}
	}
}
