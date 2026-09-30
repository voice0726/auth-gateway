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
		registerApplicationRoutes(e, cfg, handler)
		value, err := crypto.EncryptAES(id, cfg.SessionSecret)
		if err != nil {
			t.Fatal(err)
		}
		cookies = append(cookies, &http.Cookie{Name: cfg.CookieName, Value: value})
	}
	request := func(method, path, origin, token string, cookie *http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, nil)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		r.Header.Set("Origin", origin)
		r.Header.Set("X-Internal-Token", token)
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		return w
	}
	for i, cfg := range configs {
		if w := request("GET", "/auth/"+cfg.AppID+"/me", "", "", cookies[i]); w.Code != 200 {
			t.Fatalf("own session: %d", w.Code)
		}
		if w := request("GET", "/internal/"+cfg.AppID+"/session", "", cfg.InternalToken, cookies[i]); w.Code != 200 {
			t.Fatalf("own internal session: %d", w.Code)
		}
		other := 1 - i
		if w := request("GET", "/internal/"+cfg.AppID+"/session", "", configs[other].InternalToken, cookies[i]); w.Code != 401 {
			t.Fatalf("foreign backend token: %d", w.Code)
		}
		forged := &http.Cookie{Name: cfg.CookieName, Value: cookies[other].Value}
		if w := request("GET", "/auth/"+cfg.AppID+"/me", "", "", forged); w.Code != 401 {
			t.Fatalf("renamed foreign cookie: %d", w.Code)
		}
		if w := request("POST", "/auth/"+cfg.AppID+"/logout", configs[other].FrontendOrigin, "", cookies[i]); w.Code != 403 {
			t.Fatalf("foreign logout origin: %d", w.Code)
		}
	}
	stores[0].failDelete = true
	w := request("POST", "/auth/react/logout", configs[0].FrontendOrigin, "", cookies[0])
	if w.Code != 500 || len(w.Result().Cookies()) != 0 {
		t.Fatal("failed deletion must not report successful logout or clear cookie")
	}
	stores[0].failDelete = false
	w = request("POST", "/auth/react/logout", configs[0].FrontendOrigin, "", cookies[0])
	if w.Code != 204 {
		t.Fatalf("logout: %d", w.Code)
	}
	cleared := w.Result().Cookies()
	if len(cleared) != 1 || cleared[0].Name != configs[0].CookieName || cleared[0].MaxAge != -1 || cleared[0].Domain != "" {
		t.Fatalf("logout cookie: %#v", cleared)
	}
	if w := request("GET", "/auth/react/me", "", "", cookies[0]); w.Code != 401 {
		t.Fatalf("logged out session: %d", w.Code)
	}
	if w := request("GET", "/auth/tanstack/me", "", "", cookies[1]); w.Code != 200 {
		t.Fatalf("other app must remain logged in: %d", w.Code)
	}
	for _, path := range []string{"/auth/me", "/internal/session", "/auth/unknown/me"} {
		if w := request("GET", path, "", "", cookies[1]); w.Code != 404 {
			t.Fatalf("unscoped or unknown app: %s %d", path, w.Code)
		}
	}
}
