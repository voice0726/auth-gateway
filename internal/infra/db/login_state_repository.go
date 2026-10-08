package db

import (
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/voice0726/auth-gateway/internal/model"
	"github.com/voice0726/auth-gateway/internal/service"
)

type LoginStateRepository struct {
	db    *gorm.DB
	appID string
}

func NewLoginStateRepository(db *gorm.DB, appID string) *LoginStateRepository {
	return &LoginStateRepository{db: db, appID: appID}
}

func (r *LoginStateRepository) Set(state, redirect string, expiresAt time.Time) error {
	if time.Until(expiresAt) <= 0 {
		return service.ErrStateExpired
	}
	return r.db.Create(&model.LoginState{AppID: r.appID, State: state, Redirect: redirect, ExpiresAt: expiresAt}).Error
}

// Consume は state を削除しながら取得する。同じ state は一度しか成功しない。
// 期限切れの行も削除する。
func (r *LoginStateRepository) Consume(state string) (string, error) {
	var rows []model.LoginState
	err := r.db.Clauses(clause.Returning{}).
		Where("app_id = ? AND state = ?", r.appID, state).
		Delete(&rows).Error
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", service.ErrStateNotFound
	}
	if time.Now().After(rows[0].ExpiresAt) {
		return "", service.ErrStateExpired
	}
	return rows[0].Redirect, nil
}
