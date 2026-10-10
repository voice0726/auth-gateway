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
	loginRatePerSecond = rate.Limit(2)
	loginBurst         = 60
	loginLimiterTTL    = 5 * time.Minute
	unknownAppBucket   = "-"

	// clientIPHeader は、アプリのリバースプロキシが利用者の接続元 IP を渡すヘッダ。
	// X-Internal-Token でアプリが特定できたときだけ信用する。
	clientIPHeader = "X-Client-Ip"
)

// loginRateLimit は、未認証で login_states を作る /auth/login の頻度を制限する。
//
// gateway はアプリのリバースプロキシ経由で呼ばれるため、接続元 IP は全利用者で同じになる。
// そのため既定のキーは X-App-Id とし、アプリ全体で 1 つのバケットを共有する。
// 登録外の値を別バケットにすると、値を変えるだけでバケットとメモリを増やせてしまう。
//
// プロキシが X-Internal-Token と X-Client-Ip を付けたときは、アプリ内で IP ごとに数える。
// トークンが一致しない X-Client-Ip は偽装できるため使わない。
//
// カウンタはインスタンスごとのメモリ上にあり、複数インスタンス間では共有しない。
func loginRateLimit(apps []appRoutes) echo.MiddlewareFunc {
	return middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Store: middleware.NewRateLimiterMemoryStoreWithConfig(middleware.RateLimiterMemoryStoreConfig{
			Rate:      loginRatePerSecond,
			Burst:     loginBurst,
			ExpiresIn: loginLimiterTTL,
		}),
		IdentifierExtractor: func(c echo.Context) (string, error) {
			return loginLimitKey(apps, c.Request()), nil
		},
		DenyHandler: func(c echo.Context, _ string, _ error) error {
			return echo.NewHTTPError(http.StatusTooManyRequests, "too many requests")
		},
	})
}

func loginLimitKey(apps []appRoutes, r *http.Request) string {
	appID := r.Header.Get(appIDHeader)
	known := false
	for _, app := range apps {
		if app.id == appID {
			known = true
			break
		}
	}
	if !known {
		return unknownAppBucket
	}
	trusted, ok := appByInternalToken(apps, r.Header.Get("X-Internal-Token"))
	if !ok || trusted.id != appID {
		return appID
	}
	ip := net.ParseIP(strings.TrimSpace(r.Header.Get(clientIPHeader)))
	if ip == nil {
		return appID
	}
	return appID + "|" + ip.String()
}
