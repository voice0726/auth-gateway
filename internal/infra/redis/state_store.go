package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/voice0726/auth-gateway/internal/config"
	"github.com/voice0726/auth-gateway/internal/service"
)

type StateStoreRedis struct {
	client *redis.Client
	prefix string
}

func NewStateStore(client *redis.Client, prefix string) *StateStoreRedis {
	return &StateStoreRedis{client: client, prefix: prefix}
}

func NewStateStoreWithConfig(client *redis.Client, cfg config.Config) service.LoginStateService {
	return NewStateStore(client, cfg.RedisPrefix)
}

func (s *StateStoreRedis) Set(state string, redirectURI string, expiresAt time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return service.ErrStateExpired
	}

	return s.client.Set(ctx, s.key(state), redirectURI, ttl).Err()
}

func (s *StateStoreRedis) Get(state string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	value, err := s.client.Get(ctx, s.key(state)).Result()
	if err == redis.Nil {
		return "", service.ErrStateNotFound
	}
	if err != nil {
		return "", err
	}
	return value, nil
}

func (s *StateStoreRedis) Delete(state string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return s.client.Del(ctx, s.key(state)).Err()
}

func (s *StateStoreRedis) key(state string) string {
	return fmt.Sprintf("%s:state:%s", s.prefix, state)
}
