package store

import (
	"context"
	"sync"
	"time"
)

var _ SessionStorer = (*MemoryStore)(nil)

type MemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]sessionEntry
}

type sessionEntry struct {
	value     any
	expiresAt time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sessions: make(map[string]sessionEntry),
	}
}

func (s *MemoryStore) Set(ctx context.Context, sid string, value any,
	duration time.Duration) (SessionResultReporter, error) {
	s.mu.RLock()
	_, exists := s.sessions[sid]
	s.mu.RUnlock()

	s.mu.Lock()
	s.sessions[sid] = sessionEntry{
		value:     value,
		expiresAt: time.Now().Add(duration),
	}
	s.mu.Unlock()
	return NewSessionResult(!exists), nil
}

func (s *MemoryStore) Get(ctx context.Context, sid string) (any, bool, error) {
	s.mu.RLock()
	entry, ok := s.sessions[sid]
	s.mu.RUnlock()
	if !ok {
		return nil, false, nil
	}

	// If the session has expired, delete it and treat as not found.
	if time.Now().After(entry.expiresAt) {
		s.mu.Lock()
		delete(s.sessions, sid)
		s.mu.Unlock()
		return nil, false, nil
	}

	return entry.value, true, nil
}

func (s *MemoryStore) Del(ctx context.Context, sid string) error {
	s.mu.Lock()
	delete(s.sessions, sid)
	s.mu.Unlock()
	return nil
}
