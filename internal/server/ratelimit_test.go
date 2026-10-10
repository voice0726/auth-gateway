package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

var limitTestApps = []appRoutes{
	{id: "react", internalToken: "react-token"},
	{id: "tanstack", internalToken: "tanstack-token"},
}

type loginReq struct{ appID, token, clientIP string }

func loginStatus(e *echo.Echo, q loginReq) int {
	r := httptest.NewRequest(http.MethodGet, "/login", nil)
	r.Header.Set(appIDHeader, q.appID)
	if q.token != "" {
		r.Header.Set("X-Internal-Token", q.token)
	}
	if q.clientIP != "" {
		r.Header.Set(clientIPHeader, q.clientIP)
	}
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	return w.Code
}

func newLimitedEcho() *echo.Echo {
	e := echo.New()
	e.GET("/login", func(c echo.Context) error { return c.NoContent(http.StatusOK) }, loginRateLimit(limitTestApps))
	return e
}

func exhaust(e *echo.Echo, q loginReq) {
	for i := 0; i < loginBurst; i++ {
		loginStatus(e, q)
	}
}

func TestLoginRateLimitIsPerApp(t *testing.T) {
	e := newLimitedEcho()
	exhaust(e, loginReq{appID: "react"})

	if got := loginStatus(e, loginReq{appID: "react"}); got != http.StatusTooManyRequests {
		t.Fatalf("over burst: got %d, want 429", got)
	}
	if got := loginStatus(e, loginReq{appID: "tanstack"}); got != http.StatusOK {
		t.Fatalf("other app: got %d, want 200", got)
	}
}

func TestLoginRateLimitSharesOneBucketForUnknownApps(t *testing.T) {
	e := newLimitedEcho()
	for i := 0; i < loginBurst; i++ {
		loginStatus(e, loginReq{appID: "unknown-" + string(rune('a'+i%26))})
	}
	if got := loginStatus(e, loginReq{appID: "another-unknown"}); got != http.StatusTooManyRequests {
		t.Fatalf("rotating unknown app id: got %d, want 429", got)
	}
	if got := loginStatus(e, loginReq{appID: "react"}); got != http.StatusOK {
		t.Fatalf("known app must keep its own bucket: got %d, want 200", got)
	}
}

func TestLoginRateLimitCountsTrustedClientsSeparately(t *testing.T) {
	e := newLimitedEcho()
	attacker := loginReq{appID: "react", token: "react-token", clientIP: "203.0.113.1"}
	exhaust(e, attacker)

	if got := loginStatus(e, attacker); got != http.StatusTooManyRequests {
		t.Fatalf("attacker over burst: got %d, want 429", got)
	}
	other := loginReq{appID: "react", token: "react-token", clientIP: "203.0.113.2"}
	if got := loginStatus(e, other); got != http.StatusOK {
		t.Fatalf("other client behind proxy: got %d, want 200", got)
	}
	if got := loginStatus(e, loginReq{appID: "react"}); got != http.StatusOK {
		t.Fatalf("app bucket must be untouched by trusted clients: got %d, want 200", got)
	}
}

func TestLoginRateLimitIgnoresClientIPWithoutValidToken(t *testing.T) {
	cases := map[string]loginReq{
		"no token":   {appID: "react", clientIP: "203.0.113.1"},
		"bad token":  {appID: "react", token: "wrong", clientIP: "203.0.113.1"},
		"other app":  {appID: "react", token: "tanstack-token", clientIP: "203.0.113.1"},
		"invalid ip": {appID: "react", token: "react-token", clientIP: "not-an-ip"},
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			e := newLimitedEcho()
			exhaust(e, q)
			// 偽装した IP を変えても、アプリ単位のバケットで数える。
			forged := q
			forged.clientIP += "9"
			if got := loginStatus(e, forged); got != http.StatusTooManyRequests {
				t.Fatalf("got %d, want 429", got)
			}
		})
	}
}
