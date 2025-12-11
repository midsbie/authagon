package store

import (
	"context"
	"sync"
	"time"
)

var _ SessionStorer[any] = (*MemoryStore[any])(nil)

// MemoryStore is a generic, concurrency-safe in-memory implementation of SessionStorer[T]. It
// stores session values in a map keyed by session ID and enforces TTL-based expiration on Get. It
// is suitable for development and small-scale deployments where persistence across process restarts
// is not required.
type MemoryStore[T any] struct {
	mu       sync.RWMutex
	sessions map[string]sessionEntry[T]
}

type sessionEntry[T any] struct {
	value     T
	expiresAt time.Time
}

// NewMemoryStore creates a new MemoryStore[T] ready for use.
func NewMemoryStore[T any]() *MemoryStore[T] {
	return &MemoryStore[T]{
		sessions: make(map[string]sessionEntry[T]),
	}
}

// Set stores value under the given session ID with the provided TTL. Any existing entry for sid is
// overwritten.
func (s *MemoryStore[T]) Set(ctx context.Context, sid string, value T,
	duration time.Duration) error {
	s.mu.Lock()
	s.sessions[sid] = sessionEntry[T]{
		value:     value,
		expiresAt: time.Now().Add(duration),
	}
	s.mu.Unlock()
	return nil
}

// Get returns the value stored for sid. If the entry is missing or has expired it returns the zero
// value of T and ErrNotFound.
func (s *MemoryStore[T]) Get(ctx context.Context, sid string) (T, error) {
	var zero T

	s.mu.RLock()
	entry, ok := s.sessions[sid]
	s.mu.RUnlock()
	if !ok {
		return zero, ErrNotFound
	}

	// If the session has expired, delete it and treat as not found.
	if time.Now().After(entry.expiresAt) {
		s.mu.Lock()
		delete(s.sessions, sid)
		s.mu.Unlock()
		return zero, ErrNotFound
	}

	return entry.value, nil
}

// Del removes the entry for sid, if present.
func (s *MemoryStore[T]) Del(ctx context.Context, sid string) error {
	s.mu.Lock()
	delete(s.sessions, sid)
	s.mu.Unlock()
	return nil
}
