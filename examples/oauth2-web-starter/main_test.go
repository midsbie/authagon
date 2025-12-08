package main

import "testing"

func TestSanitizeRedirectURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		out  string
	}{
		{name: "empty", in: "", out: "/"},
		{name: "root", in: "/", out: "/"},
		{name: "path", in: "/dashboard", out: "/dashboard"},
		{name: "path with query", in: "/dashboard?tab=1", out: "/dashboard?tab=1"},
		{name: "absolute url", in: "http://evil.example/", out: "/"},
		{name: "https absolute url", in: "https://evil.example/path", out: "/"},
		{name: "protocol relative", in: "//evil.example/path", out: "/"},
		{name: "relative without leading slash", in: "dashboard", out: "/"},
		{name: "javascript url", in: "javascript:alert(1)", out: "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeRedirectURL(tt.in); got != tt.out {
				t.Fatalf("sanitizeRedirectURL(%q) = %q, want %q", tt.in, got, tt.out)
			}
		})
	}
}
