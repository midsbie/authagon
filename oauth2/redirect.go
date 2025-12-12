package oauth2

import (
	"net/url"
	"strings"
)

// RedirectValidator normalizes and validates a post-login redirect URL.
// Implementations should return a safe, normalized value (for example
// falling back to "/" on invalid or external URLs).
type RedirectValidator func(raw string) string

// SanitizeRedirectURL validates and normalizes a post-login redirect URL.
//
// It only allows same-site, relative paths (e.g. "/", "/dashboard",
// or "/dashboard?tab=1"). Any invalid, absolute, or otherwise unsafe
// value results in a fallback of "/".
func SanitizeRedirectURL(raw string) string {
	if raw == "" {
		return "/"
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "/"
	}

	// Reject absolute or protocol-relative URLs.
	if u.Scheme != "" || u.Host != "" {
		return "/"
	}

	// Only allow paths that start with "/".
	if u.Path == "" || !strings.HasPrefix(u.Path, "/") {
		return "/"
	}

	// Rebuild path + query (ignore fragment).
	res := u.Path
	if u.RawQuery != "" {
		res += "?" + u.RawQuery
	}

	return res
}
