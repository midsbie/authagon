package oauth2

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestHashID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "simple string",
			input:    "hello",
			expected: "2cf24dba4f21d4288094e9b259d9c18cb7e7c9a745b3b39e8b8b2f6a3b6ad2a9",
		},
		{
			name:     "string with spaces",
			input:    "hello world",
			expected: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
		},
		{
			name:     "string with special characters",
			input:    "user@example.com",
			expected: "973dfe463ec85785f5f95af5ba3906eedb2d931c24e69824a89ea65dba4e813b",
		},
		{
			name:     "long string",
			input:    "this is a very long string that should still be hashed correctly without any issues",
			expected: "8d1a8b94e2b1e5a8e6f9c1a0b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Calculate expected hash manually for verification
			h := sha256.New()
			h.Write([]byte(tt.input))
			expectedHash := hex.EncodeToString(h.Sum(nil))

			got, err := HashID(tt.input)
			if err != nil {
				t.Fatalf("HashID() error = %v, want nil", err)
			}

			if got != expectedHash {
				t.Errorf("HashID() = %q, want %q", got, expectedHash)
			}

			// Verify hash properties
			if len(got) != 64 {
				t.Errorf("HashID() length = %d, want 64", len(got))
			}

			// Verify it's valid hex
			if _, err := hex.DecodeString(got); err != nil {
				t.Errorf("HashID() result is not valid hex: %v", err)
			}
		})
	}
}

func TestHashID_Consistency(t *testing.T) {
	t.Parallel()

	input := "test-consistency"

	hash1, err1 := HashID(input)
	if err1 != nil {
		t.Fatalf("HashID() first call error = %v", err1)
	}

	hash2, err2 := HashID(input)
	if err2 != nil {
		t.Fatalf("HashID() second call error = %v", err2)
	}

	if hash1 != hash2 {
		t.Errorf("HashID() inconsistent results: %q != %q", hash1, hash2)
	}
}

func TestHashID_DifferentInputsDifferentHashes(t *testing.T) {
	t.Parallel()

	inputs := []string{"input1", "input2", "input3", "input1 ", " input1", "INPUT1"}
	hashes := make(map[string]string)

	for _, input := range inputs {
		hash, err := HashID(input)
		if err != nil {
			t.Fatalf("HashID(%q) error = %v", input, err)
		}

		if existing, exists := hashes[hash]; exists {
			t.Errorf("HashID() collision: %q and %q both produce hash %q", input, existing, hash)
		}
		hashes[hash] = input
	}
}

func TestRandomToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		length int
	}{
		{
			name:   "small token",
			length: 8,
		},
		{
			name:   "medium token",
			length: 16,
		},
		{
			name:   "large token",
			length: 32,
		},
		{
			name:   "very large token",
			length: 64,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := RandomToken(tt.length)
			if err != nil {
				t.Fatalf("RandomToken() error = %v, want nil", err)
			}

			// Hex encoding doubles the length
			expectedLen := tt.length * 2
			if len(token) != expectedLen {
				t.Errorf("RandomToken() length = %d, want %d", len(token), expectedLen)
			}

			// Verify it's valid hex
			if _, err := hex.DecodeString(token); err != nil {
				t.Errorf("RandomToken() result is not valid hex: %v", err)
			}

			// Verify it only contains hex characters
			for _, r := range token {
				if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
					t.Errorf("RandomToken() contains non-hex character: %c", r)
					break
				}
			}
		})
	}
}

func TestRandomToken_Uniqueness(t *testing.T) {
	t.Parallel()

	const tokenLen = 16
	const numTokens = 100
	tokens := make(map[string]bool)

	for i := 0; i < numTokens; i++ {
		token, err := RandomToken(tokenLen)
		if err != nil {
			t.Fatalf("RandomToken() error = %v", err)
		}

		if tokens[token] {
			t.Errorf("RandomToken() generated duplicate token: %q", token)
		}
		tokens[token] = true
	}

	if len(tokens) != numTokens {
		t.Errorf("Generated %d unique tokens, want %d", len(tokens), numTokens)
	}
}

func TestRandomToken_InvalidLength(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		length int
	}{
		{
			name:   "zero length",
			length: 0,
		},
		{
			name:   "negative length",
			length: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := RandomToken(tt.length)
			if err == nil {
				t.Fatalf("RandomToken(%d) error = nil, want error", tt.length)
			}
			if token != "" {
				t.Errorf("RandomToken(%d) token = %q, want empty string", tt.length, token)
			}
		})
	}
}

func TestRandomToken_Distribution(t *testing.T) {
	t.Parallel()

	const tokenLen = 8
	const numTokens = 50
	charCounts := make(map[rune]int)

	for i := 0; i < numTokens; i++ {
		token, err := RandomToken(tokenLen)
		if err != nil {
			t.Fatalf("RandomToken() error = %v", err)
		}

		for _, char := range token {
			charCounts[char]++
		}
	}

	// Verify we have a reasonable distribution of hex characters
	if len(charCounts) < 8 {
		t.Errorf("RandomToken() generated tokens with poor character distribution: only %d unique characters", len(charCounts))
	}

	// Verify all characters are valid hex
	validHexChars := "0123456789abcdef"
	for char := range charCounts {
		if !strings.ContainsRune(validHexChars, char) {
			t.Errorf("RandomToken() generated invalid hex character: %c", char)
		}
	}
}
