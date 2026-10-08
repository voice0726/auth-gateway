package db

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/voice0726/auth-gateway/internal/config"
	"github.com/voice0726/auth-gateway/internal/model"
	"github.com/voice0726/auth-gateway/internal/service"
	"go.uber.org/zap"
)

func TestLoginStateConsumeIsAtomicAndIsolatedByApplication(t *testing.T) {
	portText := os.Getenv("GATEWAY_TEST_DB_PORT")
	if portText == "" {
		t.Skip("GATEWAY_TEST_DB_PORT requires a disposable PostgreSQL instance")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{DBHost: "127.0.0.1", DBPort: port, DBUser: "postgres", DBPassword: "test-only", DBName: "state_test_" + strings.ReplaceAll(uuid.NewString(), "-", ""), DBSSLMode: "disable", DBTimeZone: "UTC"}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := EnsureDatabase(ctx, cfg); err != nil {
		t.Fatal(err)
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
	for range 2 {
		if err := database.AutoMigrate(&model.LoginState{}); err != nil {
			t.Fatal(err)
		}
	}
	a, b := NewLoginStateRepository(database, "react"), NewLoginStateRepository(database, "tanstack")
	const state = "same-state"
	future := time.Now().Add(time.Minute)

	if err := a.Set(state, "/react", future); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Consume(state); !errors.Is(err, service.ErrStateNotFound) {
		t.Fatalf("foreign login state accepted: %v", err)
	}
	if err := b.Set(state, "/tanstack", future); err != nil {
		t.Fatalf("same state under another application: %v", err)
	}
	if err := a.Set(state, "/dup", future); err == nil {
		t.Fatal("duplicate state overwrote an existing row")
	}
	if got, err := a.Consume(state); err != nil || got != "/react" {
		t.Fatalf("consume: %q %v", got, err)
	}
	if _, err := a.Consume(state); !errors.Is(err, service.ErrStateNotFound) {
		t.Fatalf("state consumed twice: %v", err)
	}
	if got, err := b.Consume(state); err != nil || got != "/tanstack" {
		t.Fatalf("other application's state changed: %q %v", got, err)
	}

	if err := a.Set("expired", "/x", time.Now().Add(-time.Second)); !errors.Is(err, service.ErrStateExpired) {
		t.Fatalf("expired Set: %v", err)
	}
	if err := a.Set("short", "/x", time.Now().Add(50*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := a.Consume("short"); !errors.Is(err, service.ErrStateExpired) {
		t.Fatalf("expired state accepted: %v", err)
	}
	if _, err := a.Consume("short"); !errors.Is(err, service.ErrStateNotFound) {
		t.Fatalf("expired state must be removed: %v", err)
	}

	if err := a.Set("race", "/race", future); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var successes atomic.Int32
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := a.Consume("race"); err == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("concurrent consume succeeded %d times, want 1", successes.Load())
	}
}

func TestPurgeExpiredRemovesOnlyExpiredRows(t *testing.T) {
	portText := os.Getenv("GATEWAY_TEST_DB_PORT")
	if portText == "" {
		t.Skip("GATEWAY_TEST_DB_PORT requires a disposable PostgreSQL instance")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{DBHost: "127.0.0.1", DBPort: port, DBUser: "postgres", DBPassword: "test-only", DBName: "purge_test_" + strings.ReplaceAll(uuid.NewString(), "-", ""), DBSSLMode: "disable", DBTimeZone: "UTC"}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := EnsureDatabase(ctx, cfg); err != nil {
		t.Fatal(err)
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
	if err := database.AutoMigrate(&model.Session{}, &model.LoginState{}); err != nil {
		t.Fatal(err)
	}
	// DB の精度(マイクロ秒)に合わせ、期限ちょうどの行を境界として使う。
	now := time.Now().Truncate(time.Microsecond)
	for _, s := range []model.LoginState{
		{AppID: "react", State: "old", ExpiresAt: now.Add(-time.Hour)},
		{AppID: "tanstack", State: "old", ExpiresAt: now.Add(-time.Minute)},
		{AppID: "react", State: "live", ExpiresAt: now.Add(time.Hour)},
		{AppID: "tanstack", State: "live", ExpiresAt: now.Add(time.Hour)},
		{AppID: "react", State: "exactly-now", ExpiresAt: now},
	} {
		if err := database.Create(&s).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []model.Session{
		{AppID: "react", ID: "old", ExpiresAt: now.Add(-time.Hour)},
		{AppID: "react", ID: "live", ExpiresAt: now.Add(time.Hour)},
		{AppID: "tanstack", ID: "tanstack-live", ExpiresAt: now.Add(time.Hour)},
		{AppID: "react", ID: "exactly-now", ExpiresAt: now},
		{AppID: "react", ID: "no-expiry"},
	} {
		if err := s.SetRoles([]string{}); err != nil {
			t.Fatal(err)
		}
		if err := s.SetClaims(map[string]any{}); err != nil {
			t.Fatal(err)
		}
		if err := database.Create(&s).Error; err != nil {
			t.Fatal(err)
		}
	}
	// 期限切れ state の Consume と削除が競合しても、拒否のどちらかになる。
	var wg sync.WaitGroup
	consumeErr := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := NewLoginStateRepository(database, "react").Consume("old")
		consumeErr <- err
	}()
	sessions, states, err := PurgeExpired(database, now)
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if err := <-consumeErr; !errors.Is(err, service.ErrStateExpired) && !errors.Is(err, service.ErrStateNotFound) {
		t.Fatalf("racing consume of expired state: %v", err)
	}
	// Consume が先に "old"(react) を消した場合、purge の件数は 1 少ない。
	if sessions != 1 || (states != 2 && states != 1) {
		t.Fatalf("purged sessions=%d states=%d", sessions, states)
	}
	var ids []string
	database.Model(&model.Session{}).Order("id").Pluck("id", &ids)
	if strings.Join(ids, ",") != "exactly-now,live,no-expiry,tanstack-live" {
		t.Fatalf("sessions left: %v", ids)
	}
	var left []string
	database.Model(&model.LoginState{}).Order("app_id, state").Pluck("app_id || ':' || state", &left)
	if strings.Join(left, ",") != "react:exactly-now,react:live,tanstack:live" {
		t.Fatalf("login states left: %v", left)
	}
}
