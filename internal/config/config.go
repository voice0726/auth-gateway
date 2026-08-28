package config

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Env        string
	ServerAddr string
	AppHost    string

	DBHost     string
	DBPort     int
	DBUser     string
	DBPassword string
	DBName     string
	DBSSLMode  string
	DBTimeZone string

	ZitadelIssuer       string
	ZitadelClientID     string
	ZitadelClientSecret string
	ZitadelRedirectURI  string
	ZitadelScopes       []string
	ZitadelPort         int
	ZitadelInsecure     bool

	SessionSecret string
	SessionTTL    time.Duration
	StateTTL      time.Duration

	FrontendPostLogoutURL string
	FrontendOrigin        string

	CookieName     string
	CookieSecure   bool
	CookieDomain   string
	CookieSameSite http.SameSite

	LogLevel  string
	LogFormat string

	InternalToken string

	CORSAllowOrigins []string

	RedisAddr     string
	RedisPassword string
	RedisDB       int
	RedisPrefix   string
}

type rawConfig struct {
	Env        string `yaml:"env"`
	ServerAddr string `yaml:"server_addr"`

	DBHost     string `yaml:"db_host"`
	DBPort     int    `yaml:"db_port"`
	DBUser     string `yaml:"db_user"`
	DBPassword string `yaml:"db_password"`
	DBName     string `yaml:"db_name"`
	DBSSLMode  string `yaml:"db_sslmode"`
	DBTimeZone string `yaml:"db_timezone"`

	ZitadelIssuer       string   `yaml:"zitadel_issuer"`
	ZitadelClientID     string   `yaml:"zitadel_client_id"`
	ZitadelClientSecret string   `yaml:"zitadel_client_secret"`
	ZitadelRedirectURI  string   `yaml:"zitadel_redirect_uri"`
	ZitadelScopes       []string `yaml:"zitadel_scopes"`
	ZitadelPort         int      `yaml:"zitadel_port"`
	ZitadelInsecure     bool     `yaml:"zitadel_insecure"`

	SessionSecret string        `yaml:"session_secret"`
	SessionTTL    time.Duration `yaml:"session_ttl"`
	StateTTL      time.Duration `yaml:"state_ttl"`

	FrontendPostLogoutURL string `yaml:"frontend_post_logout_url"`
	FrontendOrigin        string `yaml:"frontend_origin"`
	AppHost               string `yaml:"app_host"`

	CookieName     string `yaml:"cookie_name"`
	CookieSecure   bool   `yaml:"cookie_secure"`
	CookieDomain   string `yaml:"cookie_domain"`
	CookieSameSite string `yaml:"cookie_same_site"`

	LogLevel  string `yaml:"log_level"`
	LogFormat string `yaml:"log_format"`

	InternalToken string `yaml:"internal_token"`

	CORSAllowOrigins []string `yaml:"cors_allow_origins"`

	RedisAddr     string `yaml:"redis_addr"`
	RedisPassword string `yaml:"redis_password"`
	RedisDB       int    `yaml:"redis_db"`
	RedisPrefix   string `yaml:"redis_prefix"`
}

func Load() (Config, error) {
	path := os.Getenv("CONFIG_PATH")
	if path == "" {
		path = "config/dev.yaml"
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	var raw rawConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return Config{}, err
	}

	cfg := Config{
		Env:                   raw.Env,
		ServerAddr:            raw.ServerAddr,
		DBHost:                raw.DBHost,
		DBPort:                raw.DBPort,
		DBUser:                raw.DBUser,
		DBPassword:            raw.DBPassword,
		DBName:                raw.DBName,
		DBSSLMode:             raw.DBSSLMode,
		DBTimeZone:            raw.DBTimeZone,
		ZitadelIssuer:         raw.ZitadelIssuer,
		ZitadelClientID:       raw.ZitadelClientID,
		ZitadelClientSecret:   raw.ZitadelClientSecret,
		ZitadelRedirectURI:    raw.ZitadelRedirectURI,
		ZitadelScopes:         normalizeScopes(raw.ZitadelScopes),
		ZitadelPort:           raw.ZitadelPort,
		ZitadelInsecure:       raw.ZitadelInsecure,
		SessionSecret:         raw.SessionSecret,
		SessionTTL:            raw.SessionTTL,
		StateTTL:              raw.StateTTL,
		FrontendPostLogoutURL: raw.FrontendPostLogoutURL,
		FrontendOrigin:        raw.FrontendOrigin,
		AppHost:               raw.AppHost,
		CookieName:            raw.CookieName,
		CookieSecure:          raw.CookieSecure,
		CookieDomain:          raw.CookieDomain,
		CookieSameSite:        parseSameSite(raw.CookieSameSite),
		LogLevel:              raw.LogLevel,
		LogFormat:             raw.LogFormat,
		InternalToken:         raw.InternalToken,
		CORSAllowOrigins:      raw.CORSAllowOrigins,
		RedisAddr:             raw.RedisAddr,
		RedisPassword:         raw.RedisPassword,
		RedisDB:               raw.RedisDB,
		RedisPrefix:           raw.RedisPrefix,
	}

	if cfg.ZitadelPort == 0 {
		if cfg.ZitadelInsecure {
			cfg.ZitadelPort = 80
		} else {
			cfg.ZitadelPort = 443
		}
	}

	if err := validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func normalizeScopes(scopes []string) []string {
	if len(scopes) == 0 {
		return []string{"openid", "profile", "email"}
	}
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		result = append(result, scope)
	}
	if len(result) == 0 {
		return []string{"openid", "profile", "email"}
	}
	return result
}

func validate(cfg Config) error {
	missing := make([]string, 0, 5)
	if cfg.ZitadelIssuer == "" {
		missing = append(missing, "zitadel_issuer")
	}
	if cfg.ZitadelClientID == "" {
		missing = append(missing, "zitadel_client_id")
	}
	if cfg.ZitadelRedirectURI == "" {
		missing = append(missing, "zitadel_redirect_uri")
	}
	if cfg.SessionSecret == "" {
		missing = append(missing, "session_secret")
	}
	if cfg.FrontendPostLogoutURL == "" {
		missing = append(missing, "frontend_post_logout_url")
	}
	if cfg.FrontendOrigin == "" {
		return errors.New("frontend_origin is required")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required config fields: %s", strings.Join(missing, ", "))
	}
	if len(cfg.SessionSecret) != 16 && len(cfg.SessionSecret) != 24 && len(cfg.SessionSecret) != 32 {
		return errors.New("session_secret must be 16, 24, or 32 bytes for AES")
	}
	if cfg.ServerAddr == "" {
		return errors.New("server_addr is required")
	}
	if cfg.DBHost == "" {
		return errors.New("db_host is required")
	}
	if cfg.DBPort == 0 {
		return errors.New("db_port is required")
	}
	if cfg.DBUser == "" {
		return errors.New("db_user is required")
	}
	if cfg.DBPassword == "" {
		return errors.New("db_password is required")
	}
	if cfg.DBName == "" {
		return errors.New("db_name is required")
	}
	if cfg.DBSSLMode == "" {
		return errors.New("db_sslmode is required")
	}
	if cfg.DBTimeZone == "" {
		return errors.New("db_timezone is required")
	}
	if cfg.CookieName == "" {
		return errors.New("cookie_name is required")
	}
	if cfg.LogLevel == "" {
		return errors.New("log_level is required")
	}
	if cfg.LogFormat == "" {
		return errors.New("log_format is required")
	}
	if cfg.InternalToken == "" {
		return errors.New("internal_token is required")
	}
	if cfg.RedisAddr == "" {
		return errors.New("redis_addr is required")
	}
	if cfg.RedisPrefix == "" {
		return errors.New("redis_prefix is required")
	}
	if cfg.SessionTTL == 0 {
		return errors.New("session_ttl is required")
	}
	if cfg.StateTTL == 0 {
		return errors.New("state_ttl is required")
	}
	return nil
}

func parseSameSite(value string) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}
