package db

import (
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
	"moul.io/zapgorm2"

	"github.com/voice0726/auth-gateway/internal/config"
)

func NewConn(cfg config.Config, log *zap.Logger) (*gorm.DB, error) {
	dsn := dsn(cfg, cfg.DBName)
	gormLogger := zapgorm2.New(log)
	// セッションのSQLにはトークンが含まれるため、SQL本文をログに出さない。
	gormLogger.LogLevel = gormlogger.Silent
	gormLogger.SlowThreshold = 200 * time.Millisecond
	gormLogger.IgnoreRecordNotFoundError = true
	gormDB, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: gormLogger,
	})
	if err != nil {
		return nil, err
	}
	return gormDB, nil
}

func dsn(cfg config.Config, dbName string) string {
	return fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%d sslmode=%s TimeZone=%s",
		cfg.DBHost,
		cfg.DBUser,
		cfg.DBPassword,
		dbName,
		cfg.DBPort,
		cfg.DBSSLMode,
		cfg.DBTimeZone,
	)
}
