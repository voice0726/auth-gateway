package service

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/voice0726/auth-gateway/internal/config"
	"github.com/voice0726/auth-gateway/internal/model"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type logTestIDP struct{}

func (logTestIDP) Authenticate(http.ResponseWriter, *http.Request, string) {}
func (logTestIDP) Callback(http.ResponseWriter, *http.Request, string) (model.Session, string, error) {
	return model.Session{}, "oauth-state-secret", nil
}
func (logTestIDP) Logout(http.ResponseWriter, *http.Request, model.Session, string, string) (bool, error) {
	return false, nil
}

type logTestState struct{}

func (logTestState) Set(string, string, time.Time) error { return nil }
func (logTestState) Get(string) (string, error)          { return "/dashboard", nil }
func (logTestState) Delete(string) error                 { return nil }

type logTestSession struct{}

func (logTestSession) Create(model.Session) error        { return nil }
func (logTestSession) Get(string) (model.Session, error) { return model.Session{}, nil }
func (logTestSession) Delete(string) error               { return nil }

func TestAuthServiceLogsContainNoOAuthOrSessionSecrets(t *testing.T) {
	var logs bytes.Buffer
	logger := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(&logs), zap.DebugLevel))
	service := NewAuthService(config.Config{StateTTL: time.Hour}, logTestIDP{}, logTestSession{}, logTestState{}, logger)
	secretRedirect := "/dashboard?secret=redirect-secret"
	req := httptest.NewRequest(http.MethodGet, "/auth/login?redirect="+secretRedirect, nil)
	req.Header.Set("Referer", "https://example.test/referrer-secret")
	req.Header.Set("User-Agent", "browser-secret")
	if err := service.StartLogin(httptest.NewRecorder(), req, secretRedirect); err != nil {
		t.Fatal(err)
	}
	callback := httptest.NewRequest(http.MethodGet, "/auth/callback?state=oauth-state-secret&code=authorization-secret", nil)
	if _, _, err := service.HandleCallback(httptest.NewRecorder(), callback, "session-secret"); err != nil {
		t.Fatal(err)
	}
	logout := httptest.NewRequest(http.MethodPost, "/auth/logout?redirect=/login", nil)
	if _, err := service.HandleLogout(httptest.NewRecorder(), logout, "session-secret", "/login"); err != nil {
		t.Fatal(err)
	}

	output := logs.String()
	for _, secret := range []string{"redirect-secret", "referrer-secret", "browser-secret", "oauth-state-secret", "authorization-secret", "session-secret"} {
		if strings.Contains(output, secret) {
			t.Fatalf("log contains secret %q: %s", secret, output)
		}
	}
	for _, field := range []string{"state_prefix", "raw_query", "referer", "user_agent", "session_id", "cookie", "token", "password"} {
		if strings.Contains(output, `"`+field+`"`) {
			t.Fatalf("log contains sensitive field %q: %s", field, output)
		}
	}
}
