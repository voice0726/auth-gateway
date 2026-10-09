package config

import "testing"

func TestLoadPortOverride(t *testing.T) {
	t.Setenv("CONFIG_PATH", "../../config/dev.yaml")

	for _, tc := range []struct {
		name           string
		port           string
		wantServerAddr string
		wantError      bool
	}{
		{name: "empty keeps configured address", port: "", wantServerAddr: ":8800"},
		{name: "valid port overrides configured address", port: "18123", wantServerAddr: ":18123"},
		{name: "maximum port is valid", port: "65535", wantServerAddr: ":65535"},
		{name: "malformed port", port: "not-a-port", wantError: true},
		{name: "zero port", port: "0", wantError: true},
		{name: "negative port", port: "-1", wantError: true},
		{name: "port above maximum", port: "65536", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PORT", tc.port)

			cfg, err := Load()
			if tc.wantError {
				if err == nil {
					t.Fatal("Load() error = nil, want invalid PORT error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg.ServerAddr != tc.wantServerAddr {
				t.Errorf("ServerAddr = %q, want %q", cfg.ServerAddr, tc.wantServerAddr)
			}
		})
	}
}
