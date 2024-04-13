package oauth2

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

// HashID computes the hash of the given string value using the SHA256 algorithm.
//
// This function hashes the id input string using the SHA256 hashing function and returns a
// hexadecimal string representation of the computed hash. If the hash computation encounters an
// error, HashID returns an empty string and the error.
func HashID(id string) (string, error) {
	h := sha256.New()
	if _, err := io.WriteString(h, id); err != nil {
		return "", fmt.Errorf("failed to hash value: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func RandomToken(len int) (string, error) {
	b := make([]byte, len)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}
