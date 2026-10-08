package config

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

type Application struct {
	ID            string `yaml:"id"`
	Origin        string `yaml:"origin"`
	ClientID      string `yaml:"client_id"`
	SessionSecret string `yaml:"session_secret"`
	InternalToken string `yaml:"internal_token"`
	// DefaultRedirect はログイン後の戻り先が未指定または不正なときの遷移先。省略時は DefaultLoginRedirect。
	DefaultRedirect string `yaml:"default_redirect"`
}

const DefaultLoginRedirect = "/dashboard"

// ForApplication は共有の接続設定に、固定されたアプリ設定を重ねる。
func (c Config) ForApplication(app Application) Config {
	c.AppID = app.ID
	c.Applications = nil
	c.FrontendOrigin = app.Origin
	c.ZitadelClientID = app.ClientID
	c.ZitadelRedirectURI = app.Origin + "/auth/callback"
	c.SessionSecret = app.SessionSecret
	c.InternalToken = app.InternalToken
	c.DefaultRedirect = app.DefaultRedirect
	if c.DefaultRedirect == "" {
		c.DefaultRedirect = DefaultLoginRedirect
	}
	c.CookieName = "session_" + app.ID
	c.CookieDomain = ""
	c.RedisPrefix += ":" + app.ID
	return c
}

func validateApplications(cfg Config) error {
	if len(cfg.Applications) == 0 {
		return fmt.Errorf("applications is required; single-app configuration must be migrated")
	}
	ids, origins, tokens, secrets, clients := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, app := range cfg.Applications {
		if !regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`).MatchString(app.ID) || ids[app.ID] {
			return fmt.Errorf("application id must be unique and use lowercase letters, digits or hyphens")
		}
		u, err := url.Parse(app.Origin)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || origins[strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))] {
			return fmt.Errorf("application %s: origin must use a unique hostname and http(s), without a path", app.ID)
		}
		if clients[app.ClientID] {
			return fmt.Errorf("application %s: client_id must be unique", app.ID)
		}
		if tokens[app.InternalToken] || secrets[app.SessionSecret] {
			return fmt.Errorf("application %s: internal_token and session_secret must each be unique", app.ID)
		}
		if app.DefaultRedirect != "" && !IsSafeRelativePath(app.DefaultRedirect) {
			return fmt.Errorf("application %s: default_redirect must be a same-origin relative path", app.ID)
		}
		if err := validate(cfg.ForApplication(app)); err != nil {
			return fmt.Errorf("application %s: %w", app.ID, err)
		}
		clients[app.ClientID] = true
		ids[app.ID], origins[strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))], tokens[app.InternalToken], secrets[app.SessionSecret] = true, true, true, true
	}
	return nil
}

// IsSafeRelativePath は、同一オリジンの絶対パス("/" 始まり)かを判定する。
// 外部URL・"//host"・バックスラッシュ・制御文字は false。
func IsSafeRelativePath(value string) bool {
	if !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.Contains(value, "\\") || hasControl(value) {
		return false
	}
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "" && u.Host == "" && u.User == nil && u.Opaque == ""
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
