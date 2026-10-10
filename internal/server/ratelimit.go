package server

import (
	"crypto/sha256"
	"crypto/subtle"
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
	// proxyTokenHeader の値がそのアプリの proxy_token と一致したときだけ信用する。
	clientIPHeader   = "X-Client-Ip"
	proxyTokenHeader = "X-Proxy-Token"
)

// proxyTokenMatches は、appID のアプリに proxy_token が設定されていて、token が一致するかを返す。
// 長さの違いが比較時間に出ないよう、固定長のダイジェストで比較する。
func proxyTokenMatches(apps []appRoutes, appID, token string) bool {
	got := sha256.Sum256([]byte(token))
	matched := 0
	for _, app := range apps {
		if app.id != appID || app.proxyToken == "" {
			continue
		}
		want := sha256.Sum256([]byte(app.proxyToken))
		matched |= subtle.ConstantTimeCompare(got[:], want[:])
	}
	return matched == 1
}

// loginRateLimit は、未認証で login_states を作る /auth/login の頻度を制限する。
//
// gateway はアプリのリバースプロキシ経由で呼ばれるため、接続元 IP は全利用者で同じになる。
// そのため既定のキーは X-App-Id とし、アプリ全体で 1 つのバケットを共有する。
// 登録外の値を別バケットにすると、値を変えるだけでバケットとメモリを増やせてしまう。
//
// プロキシが X-Proxy-Token（アプリの proxy_token）と X-Client-Ip を付けたときは、アプリ内で IP ごとに数える。
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
	if !proxyTokenMatches(apps, appID, r.Header.Get(proxyTokenHeader)) {
		return appID
	}
	ip := net.ParseIP(strings.TrimSpace(r.Header.Get(clientIPHeader)))
	if ip == nil {
		return appID
	}
	return appID + "|" + ip.String()
}
