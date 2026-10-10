package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func newLoginRoutesEcho() (*echo.Echo, *int) {
	e := echo.New()
	calls := 0
	apps := append([]appRoutes(nil), limitTestApps...)
	for i := range apps {
		apps[i].login = func(c echo.Context) error {
			calls++
			return c.NoContent(http.StatusOK)
		}
		apps[i].callback = func(c echo.Context) error { return c.NoContent(http.StatusOK) }
	}
	registerRoutes(e, apps)
	return e, &calls
}

func authLoginResponse(e *echo.Echo, q loginReq) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	r.Header.Set(appIDHeader, q.appID)
	r.Header.Set(proxyTokenHeader, q.token)
	r.Header.Set(clientIPHeader, q.clientIP)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	return w
}

func TestLoginRejectsProxyTokenMismatchBeforeRateLimit(t *testing.T) {
	for _, token := range []string{"", "wrong", "tanstack-proxy", "react-token", "react-proxy ", "REACT-PROXY"} {
		t.Run(token, func(t *testing.T) {
			e, calls := newLoginRoutesEcho()
			for i := 0; i <= loginBurst; i++ {
				w := authLoginResponse(e, loginReq{appID: "react", token: token, clientIP: "203.0.113.1"})
				if w.Code != http.StatusForbidden {
					t.Fatalf("request %d: got %d, want 403", i, w.Code)
				}
				if w.Header().Get(echo.HeaderCacheControl) != "no-store" {
					t.Fatal("forbidden login must not be cacheable")
				}
			}
			if *calls != 0 {
				t.Fatalf("rejected requests reached login handler %d times", *calls)
			}
			for i := 0; i < loginBurst; i++ {
				w := authLoginResponse(e, loginReq{appID: "react", token: "react-proxy"})
				if w.Code != http.StatusOK {
					t.Fatalf("valid request %d: got %d, want 200", i, w.Code)
				}
			}
			if w := authLoginResponse(e, loginReq{appID: "react", token: "react-proxy"}); w.Code != http.StatusTooManyRequests {
				t.Fatalf("valid requests over burst: got %d, want 429", w.Code)
			}
			if w := authLoginResponse(e, loginReq{appID: "react", token: token}); w.Code != http.StatusForbidden {
				t.Fatalf("mismatch after burst: got %d, want 403", w.Code)
			}
		})
	}
}

func TestLoginPreservesTrustedClientBuckets(t *testing.T) {
	e, _ := newLoginRoutesEcho()
	q := loginReq{appID: "react", token: "react-proxy", clientIP: "203.0.113.1"}
	for i := 0; i < loginBurst; i++ {
		if w := authLoginResponse(e, q); w.Code != http.StatusOK {
			t.Fatalf("valid request %d: got %d, want 200", i, w.Code)
		}
	}
	if w := authLoginResponse(e, q); w.Code != http.StatusTooManyRequests {
		t.Fatalf("client over burst: got %d, want 429", w.Code)
	}
	q.clientIP = "203.0.113.2"
	if w := authLoginResponse(e, q); w.Code != http.StatusOK {
		t.Fatalf("other client: got %d, want 200", w.Code)
	}
}

func TestLoginPreservesUnconfiguredAppBucket(t *testing.T) {
	e, calls := newLoginRoutesEcho()
	for i := 0; i < loginBurst; i++ {
		q := loginReq{appID: "legacy", clientIP: "203.0.113.1"}
		if i%2 == 0 {
			q.token = "arbitrary"
			q.clientIP = "203.0.113.2"
		}
		if w := authLoginResponse(e, q); w.Code != http.StatusOK {
			t.Fatalf("legacy request %d: got %d, want 200", i, w.Code)
		}
	}
	if w := authLoginResponse(e, loginReq{appID: "legacy", token: "other", clientIP: "203.0.113.3"}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("legacy shared bucket over burst: got %d, want 429", w.Code)
	}
	if *calls != loginBurst {
		t.Fatalf("login handler calls: got %d, want %d", *calls, loginBurst)
	}
}

func TestLoginProxyTokenGuardKeepsOtherRoutesAndUnknownApps(t *testing.T) {
	e, _ := newLoginRoutesEcho()
	for _, id := range []string{"", "unknown"} {
		if w := authLoginResponse(e, loginReq{appID: id}); w.Code != http.StatusBadRequest {
			t.Fatalf("app %q: got %d, want 400", id, w.Code)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
	r.Header.Set(appIDHeader, "react")
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("callback without proxy token: got %d, want 200", w.Code)
	}
}
