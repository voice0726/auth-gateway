package config

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	AppID        string
	Applications []Application
	Env          string
	ServerAddr   string

	DBHost     string
	DBPort     int
	DBUser     string
	DBPassword string
	DBName     string
	DBSSLMode  string
	DBTimeZone string

	ZitadelIssuer      string
	ZitadelClientID    string
	ZitadelRedirectURI string
	ZitadelScopes      []string
	ZitadelPort        int
	ZitadelInsecure    bool

	SessionSecret string
	SessionTTL    time.Duration
	StateTTL      time.Duration

	FrontendOrigin  string
	DefaultRedirect string

	CookieName     string
	CookieSecure   bool
	CookieDomain   string
	CookieSameSite http.SameSite

	LogLevel  string
	LogFormat string

	InternalToken string
	ProxyToken    string

	CORSAllowOrigins []string
}

type rawConfig struct {
	Applications []Application `yaml:"applications"`
	Env          string        `yaml:"env"`
	ServerAddr   string        `yaml:"server_addr"`

	DBHost     string `yaml:"db_host"`
	DBPort     int    `yaml:"db_port"`
	DBUser     string `yaml:"db_user"`
	DBPassword string `yaml:"db_password"`
	DBName     string `yaml:"db_name"`
	DBSSLMode  string `yaml:"db_sslmode"`
	DBTimeZone string `yaml:"db_timezone"`

	ZitadelIssuer   string   `yaml:"zitadel_issuer"`
	ZitadelScopes   []string `yaml:"zitadel_scopes"`
	ZitadelPort     int      `yaml:"zitadel_port"`
	ZitadelInsecure bool     `yaml:"zitadel_insecure"`

	SessionTTL time.Duration `yaml:"session_ttl"`
	StateTTL   time.Duration `yaml:"state_ttl"`

	CookieSecure   bool   `yaml:"cookie_secure"`
	CookieSameSite string `yaml:"cookie_same_site"`

	LogLevel  string `yaml:"log_level"`
	LogFormat string `yaml:"log_format"`

	CORSAllowOrigins []string `yaml:"cors_allow_origins"`
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
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&raw); err != nil {
		return Config{}, err
	}

	cfg := Config{
		Applications:     raw.Applications,
		Env:              raw.Env,
		ServerAddr:       raw.ServerAddr,
		DBHost:           raw.DBHost,
		DBPort:           raw.DBPort,
		DBUser:           raw.DBUser,
		DBPassword:       raw.DBPassword,
		DBName:           raw.DBName,
		DBSSLMode:        raw.DBSSLMode,
		DBTimeZone:       raw.DBTimeZone,
		ZitadelIssuer:    raw.ZitadelIssuer,
		ZitadelScopes:    normalizeScopes(raw.ZitadelScopes),
		ZitadelPort:      raw.ZitadelPort,
		ZitadelInsecure:  raw.ZitadelInsecure,
		SessionTTL:       raw.SessionTTL,
		StateTTL:         raw.StateTTL,
		CookieSecure:     raw.CookieSecure,
		CookieSameSite:   parseSameSite(raw.CookieSameSite),
		LogLevel:         raw.LogLevel,
		LogFormat:        raw.LogFormat,
		CORSAllowOrigins: raw.CORSAllowOrigins,
	}

	if cfg.ZitadelPort == 0 {
		if cfg.ZitadelInsecure {
			cfg.ZitadelPort = 80
		} else {
			cfg.ZitadelPort = 443
		}
	}
	if port := os.Getenv("PORT"); port != "" {
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return Config{}, errors.New("PORT must be a valid TCP port")
		}
		cfg.ServerAddr = net.JoinHostPort("", strconv.Itoa(portNumber))
	}

	if err := validateApplications(cfg); err != nil {
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
