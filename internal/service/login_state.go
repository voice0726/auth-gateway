package service

import (
	"errors"
	"time"
)

var ErrStateNotFound = errors.New("stateSrv not found")
var ErrStateExpired = errors.New("stateSrv expired")

type LoginStateService interface {
	Set(state string, redirectURI string, expiresAt time.Time) error
	Get(state string) (string, error)
	Delete(state string) error
}
