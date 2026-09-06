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
		registerApplicationRoutes(e, appCfg, handler)
	}
	return nil
}

func registerApplicationRoutes(e *echo.Echo, cfg config.Config, handler *authhandler.Handler) {
	group := e.Group("/auth/" + cfg.AppID)
	group.GET("/login", handler.Login)
	group.GET("/callback", handler.Callback)
	group.POST("/logout", handler.Logout, logoutOrigin(cfg))
	group.GET("/me", handler.Me, sessionOrigin(cfg))
	e.GET("/internal/"+cfg.AppID+"/session", handler.InternalSession, internalAuth(cfg))
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
