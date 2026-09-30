package config

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

type Application struct {
	ID            string `yaml:"id"`
	Origin        string `yaml:"origin"`
	ClientID      string `yaml:"client_id"`
	SessionSecret string `yaml:"session_secret"`
	InternalToken string `yaml:"internal_token"`
}

// ForApplication は共有の接続設定に、固定されたアプリ設定を重ねる。
func (c Config) ForApplication(app Application) Config {
	c.AppID = app.ID
	c.Applications = nil
	c.FrontendOrigin = app.Origin
	c.ZitadelClientID = app.ClientID
	c.ZitadelRedirectURI = app.Origin + "/auth/callback"
	c.SessionSecret = app.SessionSecret
	c.InternalToken = app.InternalToken
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
		if err := validate(cfg.ForApplication(app)); err != nil {
			return fmt.Errorf("application %s: %w", app.ID, err)
		}
		clients[app.ClientID] = true
		ids[app.ID], origins[strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))], tokens[app.InternalToken], secrets[app.SessionSecret] = true, true, true, true
	}
	return nil
}
