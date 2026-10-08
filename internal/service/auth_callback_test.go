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

func TestRedirectFallsBackToApplicationDefault(t *testing.T) {
	cfg := config.Config{DefaultRedirect: "/tickets", StateTTL: time.Hour}
	service := NewAuthService(cfg, logTestIDP{}, logTestSession{}, alteredRedirectState{redirect: "https://evil.example"}, zap.NewNop())
	got, _, err := service.HandleCallback(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/callback?state=oauth-state", nil), "session-id")
	if err != nil || got != "/tickets" {
		t.Fatalf("callback redirect=%q err=%v, want /tickets", got, err)
	}
	var stored string
	service = NewAuthService(cfg, logTestIDP{}, logTestSession{}, &recordingState{redirect: &stored}, zap.NewNop())
	if err := service.StartLogin(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/login", nil), ""); err != nil {
		t.Fatal(err)
	}
	if stored != "/tickets" {
		t.Fatalf("stored redirect=%q, want /tickets", stored)
	}
}

type recordingState struct{ redirect *string }

func (s *recordingState) Set(_ string, redirect string, _ time.Time) error {
	*s.redirect = redirect
	return nil
}
func (s *recordingState) Get(string) (string, error) { return *s.redirect, nil }
func (s *recordingState) Delete(string) error        { return nil }
