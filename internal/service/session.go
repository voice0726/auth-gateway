package service

import "github.com/voice0726/auth-gateway/internal/model"

type SessionService interface {
	Create(session model.Session) error
	Get(id string) (model.Session, error)
	Delete(id string) error
}
