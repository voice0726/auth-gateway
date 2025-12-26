package main

import (
	"go.uber.org/fx"

	"github.com/voice0726/auth-gateway/internal/config"
	authhandler "github.com/voice0726/auth-gateway/internal/handler/auth"
	"github.com/voice0726/auth-gateway/internal/infra/db"
	appRedis "github.com/voice0726/auth-gateway/internal/infra/redis"
	"github.com/voice0726/auth-gateway/internal/infra/zitadel"
	"github.com/voice0726/auth-gateway/internal/logger"
	"github.com/voice0726/auth-gateway/internal/server"
	"github.com/voice0726/auth-gateway/internal/service"
)

func main() {
	fx.New(
		fx.Provide(
			config.Load,
			logger.New,
			db.NewConn,
			appRedis.NewClient,
			fx.Annotate(zitadel.NewClient, fx.As(new(service.IdentityProvider))),
			fx.Annotate(db.NewSessionRepository, fx.As(new(service.SessionService))),
			fx.Annotate(appRedis.NewStateStoreWithConfig, fx.As(new(service.LoginStateService))),
			service.NewAuthService,
			authhandler.NewHandler,
			server.NewEcho,
		),
		fx.Invoke(
			server.RegisterRoutes,
			server.Run,
		),
	).Run()
}
