package model

import (
	"errors"
	"time"

	"github.com/jackc/pgtype"
)

var ErrSessionNotFound = errors.New("session not found")
var ErrSessionExpired = errors.New("session expired")

type Session struct {
	ID           string       `gorm:"primaryKey;size:64"`
	UserID       string       `gorm:"size:255"`
	Email        string       `gorm:"size:255"`
	Name         string       `gorm:"size:255"`
	Roles        pgtype.JSONB `gorm:"type:jsonb"`
	AccessToken  string       `gorm:"type:text"`
	RefreshToken string       `gorm:"type:text"`
	IDToken      string       `gorm:"type:text"`
	ExpiresAt    time.Time    `gorm:"index"`
	Claims       pgtype.JSONB `gorm:"type:jsonb"`
	CreatedAt    time.Time    `gorm:"autoCreateTime"`
	UpdatedAt    time.Time    `gorm:"autoUpdateTime"`
}

func (s *Session) SetRoles(roles []string) error {
	return s.Roles.Set(roles)
}

func (s *Session) RolesSlice() []string {
	var roles []string
	_ = s.Roles.AssignTo(&roles)
	return roles
}

func (s *Session) SetClaims(claims map[string]any) error {
	return s.Claims.Set(claims)
}

func (s *Session) ClaimsMap() map[string]any {
	var claims map[string]any
	_ = s.Claims.AssignTo(&claims)
	if claims == nil {
		return map[string]any{}
	}
	return claims
}
