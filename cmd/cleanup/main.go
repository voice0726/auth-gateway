package main

import (
	"time"

	"go.uber.org/zap"

	"github.com/voice0726/auth-gateway/internal/config"
	"github.com/voice0726/auth-gateway/internal/infra/db"
	"github.com/voice0726/auth-gateway/internal/logger"
)

// 期限切れのセッションとログイン state を削除する。定期実行(日次)を想定する。
func main() {
	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}
	log, err := logger.New(cfg)
	if err != nil {
		panic(err)
	}
	gormDB, err := db.NewConn(cfg, log)
	if err != nil {
		log.Fatal("db init failed", zap.Error(err))
	}
	sessions, states, err := db.PurgeExpired(gormDB, time.Now())
	if err != nil {
		log.Fatal("cleanup failed", zap.Error(err))
	}
	log.Info("cleanup completed", zap.Int64("sessions", sessions), zap.Int64("login_states", states))
}
