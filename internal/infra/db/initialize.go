package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/voice0726/auth-gateway/internal/config"
)

// EnsureDatabase は初期化コマンド専用。通常のサーバー起動はDBを作成しない。
func EnsureDatabase(ctx context.Context, cfg config.Config) error {
	conn, err := pgx.Connect(ctx, dsn(cfg, "postgres"))
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	var exists bool
	if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)", cfg.DBName).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{cfg.DBName}.Sanitize()); err != nil {
		return fmt.Errorf("create database: %w", err)
	}
	return nil
}
