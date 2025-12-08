package store

import (
	"context"
	"sync"
	"time"
)

var _ SessionStorer[any] = (*MemoryStore[any])(nil)

type MemoryStore[T any] struct {
	mu       sync.RWMutex
	sessions map[string]sessionEntry[T]
}

type sessionEntry[T any] struct {
	value     T
	expiresAt time.Time
}

func NewMemoryStore[T any]() *MemoryStore[T] {
	return &MemoryStore[T]{
		sessions: make(map[string]sessionEntry[T]),
	}
}

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

func (s *MemoryStore[T]) Del(ctx context.Context, sid string) error {
	s.mu.Lock()
	delete(s.sessions, sid)
	s.mu.Unlock()
	return nil
}
