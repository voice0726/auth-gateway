package db

import (
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/voice0726/auth-gateway/internal/model"
)

type SessionRepository struct {
	db *gorm.DB
}

func NewSessionRepository(db *gorm.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

func (s *SessionRepository) Create(sess model.Session) error {
	return s.db.Save(&sess).Error
}

func (s *SessionRepository) Get(id string) (model.Session, error) {
	var record model.Session
	if err := s.db.First(&record, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return model.Session{}, model.ErrSessionNotFound
		}
		return model.Session{}, err
	}
	if !record.ExpiresAt.IsZero() && time.Now().After(record.ExpiresAt) {
		return model.Session{}, model.ErrSessionExpired
	}
	return record, nil
}

func (s *SessionRepository) Delete(id string) error {
	return s.db.Delete(&model.Session{}, "id = ?", id).Error
}
