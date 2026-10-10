package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func loginStatus(e *echo.Echo, forwardedFor string) int {
	r := httptest.NewRequest(http.MethodGet, "/login", nil)
	if forwardedFor != "" {
		r.Header.Set(echo.HeaderXForwardedFor, forwardedFor)
	}
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	return w.Code
}

func TestLoginRateLimitIsPerClientIP(t *testing.T) {
	e := echo.New()
	e.GET("/login", func(c echo.Context) error { return c.NoContent(http.StatusOK) }, loginRateLimit())

	for i := 0; i < loginBurst; i++ {
		if got := loginStatus(e, "203.0.113.1"); got != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i, got)
		}
	}
	if got := loginStatus(e, "203.0.113.1"); got != http.StatusTooManyRequests {
		t.Fatalf("over burst: got %d, want 429", got)
	}
	if got := loginStatus(e, "203.0.113.2"); got != http.StatusOK {
		t.Fatalf("other client: got %d, want 200", got)
	}
}

func TestLoginRateLimitIgnoresSpoofedForwardedFor(t *testing.T) {
	e := echo.New()
	e.GET("/login", func(c echo.Context) error { return c.NoContent(http.StatusOK) }, loginRateLimit())

	for i := 0; i < loginBurst; i++ {
		loginStatus(e, "198.51.100.9, 203.0.113.1")
	}
	// 先頭の値を変えても、末尾の接続元 IP が同じなら同一クライアントとして数える。
	if got := loginStatus(e, "192.0.2.77, 203.0.113.1"); got != http.StatusTooManyRequests {
		t.Fatalf("spoofed prefix: got %d, want 429", got)
	}
}
