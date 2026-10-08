package main

import (
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
	"go.uber.org/zap"

	"github.com/voice0726/auth-gateway/internal/config"
	"github.com/voice0726/auth-gateway/internal/infra/db"
	"github.com/voice0726/auth-gateway/internal/logger"
	"github.com/voice0726/auth-gateway/internal/server"
)

func main() {
	fx.New(
		fx.Provide(
			config.Load,
			logger.New,
			db.NewConn,
			server.NewEcho,
		),
		fx.WithLogger(func(log *zap.Logger) fxevent.Logger {
			return &fxevent.ZapLogger{Logger: log}
		}),
		fx.Invoke(
			server.RegisterRoutes,
			server.Run,
		),
	).Run()
}
