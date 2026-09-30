package service

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/voice0726/auth-gateway/internal/config"
	"go.uber.org/zap"
)

type alteredRedirectState struct{ redirect string }

func (s alteredRedirectState) Set(string, string, time.Time) error { return nil }
func (s alteredRedirectState) Get(string) (string, error)          { return s.redirect, nil }
func (s alteredRedirectState) Delete(string) error                 { return nil }

func TestHandleCallbackSanitizesStateStoreRedirect(t *testing.T) {
	for _, redirect := range []string{"https://evil.example/steal", "//evil.example", "/"} {
		t.Run(redirect, func(t *testing.T) {
			service := NewAuthService(config.Config{}, logTestIDP{}, logTestSession{}, alteredRedirectState{redirect: redirect}, zap.NewNop())
			got, _, err := service.HandleCallback(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/callback?state=oauth-state", nil), "session-id")
			if err != nil {
				t.Fatal(err)
			}
			if got != LoginRedirectFallback {
				t.Fatalf("redirect=%q, want %q", got, LoginRedirectFallback)
			}
		})
	}
}
