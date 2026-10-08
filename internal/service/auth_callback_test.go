package service

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/voice0726/auth-gateway/internal/config"
	"github.com/voice0726/auth-gateway/internal/model"
	"go.uber.org/zap"
)

type alteredRedirectState struct{ redirect string }

func (s alteredRedirectState) Set(string, string, time.Time) error { return nil }
func (s alteredRedirectState) Consume(string) (string, error)      { return s.redirect, nil }

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
func (s *recordingState) Consume(string) (string, error) { return *s.redirect, nil }

type countingSession struct{ created int }

func (s *countingSession) Create(model.Session) error        { s.created++; return nil }
func (s *countingSession) Get(string) (model.Session, error) { return model.Session{}, nil }
func (s *countingSession) Delete(string) error               { return nil }

type failingConsume struct{ err error }

func (s failingConsume) Set(string, string, time.Time) error { return nil }
func (s failingConsume) Consume(string) (string, error)      { return "", s.err }

func TestHandleCallbackCreatesSessionOnlyAfterStateIsConsumed(t *testing.T) {
	callback := func() *http.Request {
		return httptest.NewRequest(http.MethodGet, "/auth/callback?state=oauth-state", nil)
	}
	for _, err := range []error{ErrStateNotFound, ErrStateExpired, errors.New("database unavailable")} {
		sessions := &countingSession{}
		service := NewAuthService(config.Config{}, logTestIDP{}, sessions, failingConsume{err: err}, zap.NewNop())
		if _, _, got := service.HandleCallback(httptest.NewRecorder(), callback(), "session-id"); !errors.Is(got, err) {
			t.Fatalf("error=%v, want %v", got, err)
		}
		if sessions.created != 0 {
			t.Fatalf("session created after state failure %v", err)
		}
	}
	sessions := &countingSession{}
	service := NewAuthService(config.Config{}, logTestIDP{}, sessions, alteredRedirectState{redirect: "/tickets"}, zap.NewNop())
	if _, _, err := service.HandleCallback(httptest.NewRecorder(), callback(), "session-id"); err != nil || sessions.created != 1 {
		t.Fatalf("created=%d err=%v, want one session", sessions.created, err)
	}
}
