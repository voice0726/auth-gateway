package db

import (
	"time"

	"gorm.io/gorm"

	"github.com/voice0726/auth-gateway/internal/model"
)

// PurgeExpired は、全アプリの期限切れセッションとログイン state を削除する。
// 期限なし(ExpiresAt がゼロ値)のセッションは、Get が期限切れと扱わないため残す。
func PurgeExpired(database *gorm.DB, now time.Time) (sessions, states int64, err error) {
	res := database.Where("expires_at < ? AND expires_at <> ?", now, time.Time{}).Delete(&model.Session{})
	if res.Error != nil {
		return 0, 0, res.Error
	}
	sessions = res.RowsAffected
	res = database.Where("expires_at < ?", now).Delete(&model.LoginState{})
	return sessions, res.RowsAffected, res.Error
}
