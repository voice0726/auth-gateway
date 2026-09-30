package redis

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/voice0726/auth-gateway/internal/service"
)

func TestLoginStateIsIsolatedByApplication(t *testing.T) {
	port := os.Getenv("GATEWAY_TEST_REDIS_PORT")
	if port == "" {
		t.Skip("GATEWAY_TEST_REDIS_PORT requires a disposable Redis instance")
	}
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:" + port})
	defer client.Close()
	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Fatal(err)
	}
	prefix := "test:" + uuid.NewString()
	a, b := NewStateStore(client, prefix+":react"), NewStateStore(client, prefix+":tanstack")
	const state = "same-state"
	if err := a.Set(state, "/react", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Get(state); !errors.Is(err, service.ErrStateNotFound) {
		t.Fatalf("foreign login state accepted: %v", err)
	}
	if err := b.Set(state, "/tanstack", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := a.Delete(state); err != nil {
		t.Fatal(err)
	}
	if got, err := b.Get(state); err != nil || got != "/tanstack" {
		t.Fatalf("other application's state changed: %q %v", got, err)
	}
	if err := b.Delete(state); err != nil {
		t.Fatal(err)
	}
}
