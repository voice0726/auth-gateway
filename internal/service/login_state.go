package service

import (
	"errors"
	"time"
)

var ErrStateNotFound = errors.New("stateSrv not found")
var ErrStateExpired = errors.New("stateSrv expired")

type LoginStateService interface {
	Set(state string, redirectURI string, expiresAt time.Time) error
	// Consume は state の戻り先を返し、同時に削除する。
	Consume(state string) (string, error)
}
