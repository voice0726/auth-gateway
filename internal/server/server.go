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
	e.Use(requestLogger(logger))
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
	e.POST("/auth/logout", authHandler.Logout)
	e.GET("/auth/me", authHandler.Me)

	internal := e.Group("/internal", internalAuth(cfg))
	internal.GET("/session", authHandler.InternalSession)
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
