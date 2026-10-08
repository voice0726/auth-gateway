package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/redis/go-redis/v9"
	"github.com/voice0726/auth-gateway/internal/infra/db"
	appRedis "github.com/voice0726/auth-gateway/internal/infra/redis"
	"github.com/voice0726/auth-gateway/internal/infra/zitadel"
	"github.com/voice0726/auth-gateway/internal/service"
	"gorm.io/gorm"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/voice0726/auth-gateway/internal/config"
	authhandler "github.com/voice0726/auth-gateway/internal/handler/auth"
)

func NewEcho(cfg config.Config, logger *zap.Logger) *echo.Echo {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.Use(middleware.Recover())
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogMethod:   true,
		LogURIPath:  true,
		LogStatus:   true,
		LogLatency:  true,
		LogRemoteIP: true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			logger.Info("request",
				zap.String("method", v.Method),
				zap.String("path", v.URIPath),
				zap.Int("status", v.Status),
				zap.Duration("latency", v.Latency),
				zap.String("remote", v.RemoteIP),
			)
			return nil
		},
	}))
	if len(cfg.CORSAllowOrigins) > 0 {
		e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
			AllowOrigins:     cfg.CORSAllowOrigins,
			AllowMethods:     []string{http.MethodGet, http.MethodPost, http.MethodOptions},
			AllowHeaders:     []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization},
			AllowCredentials: true,
		}))
	}
	return e
}

func RegisterRoutes(e *echo.Echo, cfg config.Config, database *gorm.DB, cache *redis.Client, logger *zap.Logger) error {
	apps := make([]appRoutes, 0, len(cfg.Applications))
	for _, app := range cfg.Applications {
		appCfg := cfg.ForApplication(app)
		idp, err := zitadel.NewClient(appCfg)
		if err != nil {
			return fmt.Errorf("application %s: initialize identity provider: %w", app.ID, err)
		}
		sessions := db.NewSessionRepository(database, app.ID)
		states := appRedis.NewStateStoreWithConfig(cache, appCfg)
		authService := service.NewAuthService(appCfg, idp, sessions, states, logger)
		handler, err := authhandler.NewHandler(appCfg, authService, logger)
		if err != nil {
			return err
		}
		apps = append(apps, newAppRoutes(appCfg, handler))
	}
	registerRoutes(e, apps)
	return nil
}

// appIDHeader は、リバースプロキシが固定値で付けるアプリ識別ヘッダ。認証情報ではない。
const appIDHeader = "X-App-Id"

// appRoutes は、1アプリ分のハンドラ。Origin検証など設定依存のガードは構築時に組み込む。
type appRoutes struct {
	id, internalToken string
	login, callback   echo.HandlerFunc
	logout, me        echo.HandlerFunc
	internalSession   echo.HandlerFunc
}

func newAppRoutes(cfg config.Config, handler *authhandler.Handler) appRoutes {
	return appRoutes{
		id:              cfg.AppID,
		internalToken:   cfg.InternalToken,
		login:           handler.Login,
		callback:        handler.Callback,
		logout:          logoutOrigin(cfg)(handler.Logout),
		me:              sessionOrigin(cfg)(handler.Me),
		internalSession: handler.InternalSession,
	}
}

// registerRoutes は、アプリを共通パスに登録する。
// /auth/* は X-App-Id、/internal/session は X-Internal-Token でアプリを特定する。
func registerRoutes(e *echo.Echo, apps []appRoutes) {
	byID := make(map[string]appRoutes, len(apps))
	for _, app := range apps {
		byID[app.id] = app
	}
	byHeader := func(pick func(appRoutes) echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			app, ok := byID[c.Request().Header.Get(appIDHeader)]
			if !ok {
				return echo.NewHTTPError(http.StatusBadRequest, "unknown application")
			}
			return pick(app)(c)
		}
	}
	auth := e.Group("/auth", noStore)
	auth.GET("/login", byHeader(func(a appRoutes) echo.HandlerFunc { return a.login }))
	auth.GET("/callback", byHeader(func(a appRoutes) echo.HandlerFunc { return a.callback }))
	auth.POST("/logout", byHeader(func(a appRoutes) echo.HandlerFunc { return a.logout }))
	auth.GET("/me", byHeader(func(a appRoutes) echo.HandlerFunc { return a.me }))
	internal := e.Group("/internal", noStore)
	internal.GET("/session", func(c echo.Context) error {
		app, ok := appByInternalToken(apps, c.Request().Header.Get("X-Internal-Token"))
		if !ok {
			return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
		}
		return app.internalSession(c)
	})
}

func noStore(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Set(echo.HeaderCacheControl, "no-store")
		return next(c)
	}
}

func sessionOrigin(cfg config.Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			origin := c.Request().Header.Get(echo.HeaderOrigin)
			if origin != "" && origin != cfg.FrontendOrigin {
				return echo.NewHTTPError(http.StatusForbidden, "origin forbidden")
			}
			return next(c)
		}
	}
}

func logoutOrigin(cfg config.Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if c.Request().Header.Get(echo.HeaderOrigin) != cfg.FrontendOrigin {
				return echo.NewHTTPError(http.StatusForbidden, "origin forbidden")
			}
			return next(c)
		}
	}
}

func Run(lc fx.Lifecycle, cfg config.Config, e *echo.Echo, logger *zap.Logger) {
	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			go func() {
				if err := e.Start(cfg.ServerAddr); err != nil && !errors.Is(err, http.ErrServerClosed) {
					logger.Error("server stopped", zap.Error(err))
				}
			}()
			logger.Info("server started", zap.String("addr", cfg.ServerAddr))
			return nil
		},
		OnStop: func(ctx context.Context) error {
			logger.Info("server shutting down")
			return e.Shutdown(ctx)
		},
	})
}
