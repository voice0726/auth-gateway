package server

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/voice0726/auth-gateway/internal/config"
)

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
