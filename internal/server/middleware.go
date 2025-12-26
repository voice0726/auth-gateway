package server

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"

	"github.com/voice0726/auth-gateway/internal/config"
)

func requestLogger(logger *zap.Logger) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()
			err := next(c)
			stop := time.Now()
			request := c.Request()
			response := c.Response()
			logger.Info("request",
				zap.String("method", request.Method),
				zap.String("path", request.URL.Path),
				zap.Int("status", response.Status),
				zap.Duration("latency", stop.Sub(start)),
				zap.String("remote", c.RealIP()),
			)
			return err
		}
	}
}

func internalAuth(cfg config.Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			token := c.Request().Header.Get("X-Internal-Token")
			if token == "" || token != cfg.InternalToken {
				return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
			}
			return next(c)
		}
	}
}
