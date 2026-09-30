package service

import (
	"net/url"
	"strings"
	"unicode/utf8"
)

const LoginRedirectFallback = "/dashboard"
const LogoutRedirectFallback = "/login"

func SafeRedirect(value, fallback string) string {
	if value == "" || value == "/" || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.Contains(value, "\\") || hasControl(value) {
		return fallback
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return fallback
	}
	return value
}

func hasControl(value string) bool {
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		if r == utf8.RuneError && size == 1 || r < 0x20 || r == 0x7f {
			return true
		}
		value = value[size:]
	}
	return false
}
