package main

import (
	"go.uber.org/zap"

	"github.com/voice0726/auth-gateway/internal/config"
	"github.com/voice0726/auth-gateway/internal/infra/db"
	"github.com/voice0726/auth-gateway/internal/logger"
	"github.com/voice0726/auth-gateway/internal/model"
)

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
	if err := gormDB.AutoMigrate(&model.Session{}); err != nil {
		log.Fatal("migration failed", zap.Error(err))
	}
}
