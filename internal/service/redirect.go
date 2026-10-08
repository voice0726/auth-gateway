package service

import "github.com/voice0726/auth-gateway/internal/config"

const LoginRedirectFallback = config.DefaultLoginRedirect
const LogoutRedirectFallback = "/login"

func SafeRedirect(value, fallback string) string {
	if value == "" || value == "/" || !config.IsSafeRelativePath(value) {
		return fallback
	}
	return value
}
