package logger

import (
	"strings"

	prettyconsole "github.com/thessem/zap-prettyconsole"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/voice0726/auth-gateway/internal/config"
)

func New(cfg config.Config) (*zap.Logger, error) {
	level := zapcore.InfoLevel
	if err := level.UnmarshalText([]byte(strings.ToLower(cfg.LogLevel))); err != nil {
		level = zapcore.InfoLevel
	}

	var log *zap.Logger
	var err error

	switch strings.ToLower(cfg.LogFormat) {
	case "json":
		zcfg := zap.NewProductionConfig()
		zcfg.Level = zap.NewAtomicLevelAt(level)
		log, err = zcfg.Build()
	default:
		log = prettyconsole.NewLogger(level)
	}
	if err != nil {
		return nil, err
	}

	zap.ReplaceGlobals(log)
	return log, nil
}
