package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/voice0726/auth-gateway/internal/config"
	"go.uber.org/zap"
)

func TestLogoutOriginGuardAndMethod(t *testing.T) {
	cfg := config.Config{FrontendOrigin: "http://localhost:5173"}
	e := echo.New()
	mutations := 0
	e.POST("/auth/logout", func(c echo.Context) error { mutations++; return c.NoContent(http.StatusNoContent) }, logoutOrigin(cfg))
	for _, tc := range []struct {
		name, method, origin      string
		wantStatus, wantMutations int
	}{
		{"missing origin", http.MethodPost, "", http.StatusForbidden, 0},
		{"different origin", http.MethodPost, "https://evil.example", http.StatusForbidden, 0},
		{"null origin", http.MethodPost, "null", http.StatusForbidden, 0},
		{"get has no state change", http.MethodGet, "http://localhost:5173", http.StatusMethodNotAllowed, 0},
		{"allowed origin", http.MethodPost, "http://localhost:5173", http.StatusNoContent, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/auth/logout", nil)
			if tc.origin != "" {
				req.Header.Set(echo.HeaderOrigin, tc.origin)
			}
			res := httptest.NewRecorder()
			e.ServeHTTP(res, req)
			if res.Code != tc.wantStatus || mutations != tc.wantMutations {
				t.Fatalf("status=%d mutations=%d, want status=%d mutations=%d", res.Code, mutations, tc.wantStatus, tc.wantMutations)
			}
		})
	}
}

func TestCORSPreflightAllowsApplicationHeader(t *testing.T) {
	cfg := config.Config{CORSAllowOrigins: []string{"http://react.localtest.me:5174"}}
	e := NewEcho(cfg, zap.NewNop())
	req := httptest.NewRequest(http.MethodOptions, "/auth/me", nil)
	req.Header.Set(echo.HeaderOrigin, "http://react.localtest.me:5174")
	req.Header.Set(echo.HeaderAccessControlRequestMethod, http.MethodGet)
	req.Header.Set(echo.HeaderAccessControlRequestHeaders, appIDHeader)
	res := httptest.NewRecorder()
	e.ServeHTTP(res, req)
	if res.Code != http.StatusNoContent || !strings.Contains(strings.ToLower(res.Header().Get(echo.HeaderAccessControlAllowHeaders)), "x-app-id") {
		t.Fatalf("preflight status=%d allow-headers=%q", res.Code, res.Header().Get(echo.HeaderAccessControlAllowHeaders))
	}
}
