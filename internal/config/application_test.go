package config

import (
	"strings"
	"testing"
)

func TestApplicationConfigurationIsolation(t *testing.T) {
	t.Setenv("CONFIG_PATH", "../../config/dev.yaml")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	first := cfg.Applications[0]
	second := Application{ID: "tanstack", Origin: "http://tanstack.localtest.me:3000", ClientID: "second-client", SessionSecret: "abcdef0123456789abcdef0123456789", InternalToken: "second-token"}
	cfg.Applications = append(cfg.Applications, second)
	if err := validateApplications(cfg); err != nil {
		t.Fatal(err)
	}
	a, b := cfg.ForApplication(first), cfg.ForApplication(second)
	if a.CookieName == b.CookieName || a.RedisPrefix == b.RedisPrefix || a.CookieDomain != "" || b.CookieDomain != "" {
		t.Fatal("cookie and state namespaces must be isolated")
	}
	if b.ZitadelRedirectURI != second.Origin+"/auth/callback" {
		t.Fatal("callback must belong to the application origin")
	}
	for _, tc := range []struct {
		name   string
		change func(*Application)
	}{
		{"duplicate app", func(v *Application) { v.ID = first.ID }},
		{"route traversal", func(v *Application) { v.ID = "../react" }},
		{"same host on another port", func(v *Application) { v.Origin = "http://react.localtest.me:3000" }},
		{"origin path", func(v *Application) { v.Origin = "http://tanstack.localtest.me/app" }},
		{"shared backend token", func(v *Application) { v.InternalToken = first.InternalToken }},
		{"shared cookie key", func(v *Application) { v.SessionSecret = first.SessionSecret }},
		{"shared client", func(v *Application) { v.ClientID = first.ClientID }},
		{"empty client", func(v *Application) { v.ClientID = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := second
			tc.change(&v)
			cfg.Applications[1] = v
			err := validateApplications(cfg)
			if err == nil {
				t.Fatal("invalid application accepted")
			}
			if strings.Contains(err.Error(), first.SessionSecret) || strings.Contains(err.Error(), first.InternalToken) {
				t.Fatal("validation leaked secret")
			}
		})
	}
	cfg.Applications = nil
	if err := validateApplications(cfg); err == nil {
		t.Fatal("missing applications must fail closed")
	}
}
