package service

import "testing"

func TestSafeRedirect(t *testing.T) {
	for _, tc := range []struct{ name, input, want string }{
		{"dashboard", "/dashboard", "/dashboard"},
		{"query", "/customers/123?tab=active", "/customers/123?tab=active"},
		{"external", "https://evil.example", "/dashboard"},
		{"protocol relative", "//evil.example", "/dashboard"},
		{"root", "/", "/dashboard"},
		{"backslash", `/\\evil.example`, "/dashboard"},
		{"control", "/dashboard\n", "/dashboard"},
		{"empty", "", "/login"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := SafeRedirect(tc.input, map[bool]string{true: "/login", false: "/dashboard"}[tc.want == "/login"]); got != tc.want {
				t.Fatalf("SafeRedirect(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
