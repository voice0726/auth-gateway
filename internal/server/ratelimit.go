package server

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/time/rate"
)

const (
	loginRatePerSecond = rate.Limit(0.2)
	loginBurst         = 10
	loginLimiterTTL    = 5 * time.Minute
)

// loginRateLimit は、未認証で login_states を作る /auth/login の頻度を IP 単位で制限する。
// カウンタはインスタンスごとのメモリ上にあり、複数インスタンス間では共有しない。
func loginRateLimit() echo.MiddlewareFunc {
	return middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Store: middleware.NewRateLimiterMemoryStoreWithConfig(middleware.RateLimiterMemoryStoreConfig{
			Rate:      loginRatePerSecond,
			Burst:     loginBurst,
			ExpiresIn: loginLimiterTTL,
		}),
		IdentifierExtractor: func(c echo.Context) (string, error) { return clientIP(c.Request()), nil },
		DenyHandler: func(c echo.Context, _ string, _ error) error {
			return echo.NewHTTPError(http.StatusTooManyRequests, "too many requests")
		},
	})
}

// clientIP は、Cloud Run が X-Forwarded-For の末尾に追記する接続元 IP を返す。
// 先頭側の値はクライアントが偽装できるため使わない。
func clientIP(r *http.Request) string {
	if xff := r.Header.Get(echo.HeaderXForwardedFor); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
