package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func loginStatus(e *echo.Echo, appID string) int {
	r := httptest.NewRequest(http.MethodGet, "/login", nil)
	r.Header.Set(appIDHeader, appID)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	return w.Code
}

func newLimitedEcho() *echo.Echo {
	e := echo.New()
	e.GET("/login", func(c echo.Context) error { return c.NoContent(http.StatusOK) }, loginRateLimit([]string{"react", "tanstack"}))
	return e
}

func TestLoginRateLimitIsPerApp(t *testing.T) {
	e := newLimitedEcho()

	for i := 0; i < loginBurst; i++ {
		if got := loginStatus(e, "react"); got != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i, got)
		}
	}
	if got := loginStatus(e, "react"); got != http.StatusTooManyRequests {
		t.Fatalf("over burst: got %d, want 429", got)
	}
	if got := loginStatus(e, "tanstack"); got != http.StatusOK {
		t.Fatalf("other app: got %d, want 200", got)
	}
}

func TestLoginRateLimitSharesOneBucketForUnknownApps(t *testing.T) {
	e := newLimitedEcho()

	for i := 0; i < loginBurst; i++ {
		loginStatus(e, "unknown-"+string(rune('a'+i%26)))
	}
	// 登録外の値を変えても別バケットにならない。
	if got := loginStatus(e, "another-unknown"); got != http.StatusTooManyRequests {
		t.Fatalf("rotating unknown app id: got %d, want 429", got)
	}
	if got := loginStatus(e, "react"); got != http.StatusOK {
		t.Fatalf("known app must keep its own bucket: got %d, want 200", got)
	}
}
