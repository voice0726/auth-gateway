package server

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/time/rate"
)

const (
	loginRatePerSecond = rate.Limit(2)
	loginBurst         = 60
	loginLimiterTTL    = 5 * time.Minute
	unknownAppBucket   = "-"
)

// loginRateLimit は、未認証で login_states を作る /auth/login の頻度をアプリ単位で制限する。
// gateway はアプリのリバースプロキシ経由でしか呼ばれず、接続元 IP は全利用者で同じになる。
// そのため IP ではなく X-App-Id をキーにし、登録済みのアプリ ID だけを別バケットにする。
// 未登録の値を別バケットにすると、値を変えるだけでバケットとメモリを増やせてしまう。
// カウンタはインスタンスごとのメモリ上にあり、複数インスタンス間では共有しない。
func loginRateLimit(appIDs []string) echo.MiddlewareFunc {
	known := make(map[string]struct{}, len(appIDs))
	for _, id := range appIDs {
		known[id] = struct{}{}
	}
	return middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Store: middleware.NewRateLimiterMemoryStoreWithConfig(middleware.RateLimiterMemoryStoreConfig{
			Rate:      loginRatePerSecond,
			Burst:     loginBurst,
			ExpiresIn: loginLimiterTTL,
		}),
		IdentifierExtractor: func(c echo.Context) (string, error) {
			id := c.Request().Header.Get(appIDHeader)
			if _, ok := known[id]; !ok {
				return unknownAppBucket, nil
			}
			return id, nil
		},
		DenyHandler: func(c echo.Context, _ string, _ error) error {
			return echo.NewHTTPError(http.StatusTooManyRequests, "too many requests")
		},
	})
}
