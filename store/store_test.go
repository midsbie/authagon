package store

import (
	"testing"
)

func TestNewSessionResult(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		created bool
	}{
		{
			name:    "session created",
			created: true,
		},
		{
			name:    "session not created",
			created: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := NewSessionResult(tt.created)
			if sr == nil {
				t.Fatal("NewSessionResult() returned nil")
			}
			if sr.SessionCreated() != tt.created {
				t.Errorf("SessionCreated() = %v, want %v", sr.SessionCreated(), tt.created)
			}
		})
	}
}

func TestSessionResult_SessionCreated(t *testing.T) {
	t.Parallel()

	sr := &sessionResult{created: true}
	if !sr.SessionCreated() {
		t.Errorf("SessionCreated() = false, want true")
	}

	sr = &sessionResult{created: false}
	if sr.SessionCreated() {
		t.Errorf("SessionCreated() = true, want false")
	}
}