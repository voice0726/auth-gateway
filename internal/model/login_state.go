package model

import "time"

// LoginState は、ログイン開始から callback までの一時データ。
type LoginState struct {
	AppID     string    `gorm:"primaryKey;size:64"`
	State     string    `gorm:"primaryKey;size:255"`
	Redirect  string    `gorm:"type:text"`
	ExpiresAt time.Time `gorm:"index"`
}
