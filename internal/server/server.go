package server

import (
	"context"
	"errors"
	"net/http"

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

func RegisterRoutes(e *echo.Echo, cfg config.Config, authHandler *authhandler.Handler) {
	e.GET("/auth/login", authHandler.Login)
	e.GET("/auth/callback", authHandler.Callback)
	e.POST("/auth/logout", authHandler.Logout, logoutOrigin(cfg))
	e.GET("/auth/me", authHandler.Me)

	internal := e.Group("/internal", internalAuth(cfg))
	internal.GET("/session", authHandler.InternalSession)
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
