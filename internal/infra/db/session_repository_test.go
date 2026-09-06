package db

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/voice0726/auth-gateway/internal/config"
	"github.com/voice0726/auth-gateway/internal/model"
	"go.uber.org/zap"
)

func TestDatabaseInitializationAndApplicationIsolation(t *testing.T) {
	portText := os.Getenv("GATEWAY_TEST_DB_PORT")
	if portText == "" {
		t.Skip("GATEWAY_TEST_DB_PORT requires a disposable PostgreSQL instance")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{DBHost: "127.0.0.1", DBPort: port, DBUser: "postgres", DBPassword: "test-only", DBName: "session_test_" + strings.ReplaceAll(uuid.NewString(), "-", ""), DBSSLMode: "disable", DBTimeZone: "UTC"}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for range 2 {
		if err := EnsureDatabase(ctx, cfg); err != nil {
			t.Fatal(err)
		}
	}
	database, err := NewConn(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := database.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	// 旧テーブルからの移行で、所属不明のセッションを別アプリへ割り当てない。
	if err := database.Exec("CREATE TABLE sessions (id varchar(64) PRIMARY KEY)").Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Exec("INSERT INTO sessions (id) VALUES ('legacy-session')").Error; err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := database.AutoMigrate(&model.Session{}); err != nil {
			t.Fatal(err)
		}
	}
	a, b := NewSessionRepository(database, "react"), NewSessionRepository(database, "tanstack")
	for _, repo := range []*SessionRepository{a, b} {
		if _, err := repo.Get("legacy-session"); !errors.Is(err, model.ErrSessionNotFound) {
			t.Fatalf("legacy session accepted: %v", err)
		}
	}
	for _, tc := range []struct {
		repo *SessionRepository
		id   string
	}{{a, "a-session"}, {b, "b-session"}} {
		sess := model.Session{ID: tc.id, UserID: "same-user", ExpiresAt: time.Now().Add(time.Hour)}
		if err := sess.SetRoles([]string{}); err != nil {
			t.Fatal(err)
		}
		if err := sess.SetClaims(map[string]any{}); err != nil {
			t.Fatal(err)
		}
		if err := tc.repo.Create(sess); err != nil {
			t.Fatal(err)
		}
		if _, err := tc.repo.Get(tc.id); err != nil {
			t.Fatal(err)
		}
	}
	duplicate := model.Session{ID: "a-session", UserID: "attacker"}
	if err := duplicate.SetRoles([]string{}); err != nil {
		t.Fatal(err)
	}
	if err := duplicate.SetClaims(map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if err := b.Create(duplicate); err == nil {
		t.Fatal("duplicate ID overwrote another application's session")
	}
	if _, err := b.Get("a-session"); !errors.Is(err, model.ErrSessionNotFound) {
		t.Fatalf("foreign session accepted: %v", err)
	}
	if err := b.Delete("a-session"); err != nil {
		t.Fatal(err)
	}
	if v, err := a.Get("a-session"); err != nil || v.UserID != "same-user" {
		t.Fatalf("foreign deletion or overwrite affected original session: %v", err)
	}
	if err := a.Delete("a-session"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Get("a-session"); !errors.Is(err, model.ErrSessionNotFound) {
		t.Fatalf("deleted session accepted: %v", err)
	}
	if _, err := b.Get("b-session"); err != nil {
		t.Fatalf("other application lost its session: %v", err)
	}
	var count int64
	if err := database.Model(&model.Session{}).Where("id = ?", "legacy-session").Count(&count).Error; err != nil || count != 1 {
		t.Fatal("legacy data must remain untouched")
	}
}
