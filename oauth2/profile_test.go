package oauth2

import "testing"

func TestProfileMapString(t *testing.T) {
	t.Parallel()

	pm := ProfileMap{
		"str":  "value",
		"int":  42,
		"nil":  nil,
		"bool": true,
	}

	if got := pm.String("str"); got != "value" {
		t.Fatalf("String(\"str\") = %q, want %q", got, "value")
	}
	if got := pm.String("int"); got != "42" {
		t.Fatalf("String(\"int\") = %q, want %q", got, "42")
	}
	if got := pm.String("bool"); got != "true" {
		t.Fatalf("String(\"bool\") = %q, want %q", got, "true")
	}
	if got := pm.String("nil"); got != "" {
		t.Fatalf("String(\"nil\") = %q, want empty", got)
	}
	if got := pm.String("missing"); got != "" {
		t.Fatalf("String(\"missing\") = %q, want empty", got)
	}
}

func TestProfileMapBool(t *testing.T) {
	t.Parallel()

	pm := ProfileMap{
		"boolTrue":   true,
		"boolFalse":  false,
		"strTrue":    "true",
		"strFalse":   "false",
		"strInvalid": "not-a-bool",
		"nil":        nil,
	}

	tests := []struct {
		key  string
		want bool
	}{
		{"boolTrue", true},
		{"boolFalse", false},
		{"strTrue", true},
		{"strFalse", false},
		{"strInvalid", false},
		{"nil", false},
		{"missing", false},
	}

	for _, tt := range tests {
		if got := pm.Bool(tt.key); got != tt.want {
			t.Fatalf("Bool(%q) = %v, want %v", tt.key, got, tt.want)
		}
	}
}

func TestProfileAttributesHelpers(t *testing.T) {
	t.Parallel()

	var p Profile

	p.SetBoolAttr("admin", true)
	p.SetStringAttr("role", "user")

	if got := p.GetBoolAttr("admin"); got != true {
		t.Fatalf("GetBoolAttr(\"admin\") = %v, want true", got)
	}
	if got := p.GetStringAttr("role"); got != "user" {
		t.Fatalf("GetStringAttr(\"role\") = %q, want %q", got, "user")
	}

	// Missing keys should return zero values.
	if got := p.GetBoolAttr("missingBool"); got != false {
		t.Fatalf("GetBoolAttr(\"missingBool\") = %v, want false", got)
	}
	if got := p.GetStringAttr("missingString"); got != "" {
		t.Fatalf("GetStringAttr(\"missingString\") = %q, want empty", got)
	}

	if p.Attributes == nil {
		t.Fatal("Attributes should not be nil after setting attributes")
	}
}
