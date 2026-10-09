package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/voice0726/auth-gateway/internal/config"
	"go.uber.org/zap"
)

func TestHealthz(t *testing.T) {
	e := NewEcho(config.Config{}, zap.NewNop())
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	res := httptest.NewRecorder()

	e.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusOK)
	}
	if res.Body.Len() != 0 {
		t.Errorf("body = %q, want empty", res.Body.String())
	}
}
