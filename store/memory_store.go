package store

import (
	"context"
	"fmt"
	"sync"
	"time"
)

var _ SessionStorer = (*MemoryStore)(nil)

type MemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]any
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sessions: make(map[string]any),
	}
}

func (s *MemoryStore) Set(ctx context.Context, sid string, value any,
	duration time.Duration) (SessionResultReporter, error) {
	s.mu.Lock()
	s.sessions[sid] = value
	s.mu.Unlock()
	return NewSessionResult(false), nil
}

func (s *MemoryStore) Get(ctx context.Context, sid string) (any, bool, error) {
	s.mu.RLock()
	v, ok := s.sessions[sid]
	s.mu.RUnlock()
	if ok {
		return v, true, nil
	}
	return nil, false, fmt.Errorf("session not found: %s", sid)
}

func (s *MemoryStore) Del(ctx context.Context, sid string) error {
	s.mu.Lock()
	delete(s.sessions, sid)
	s.mu.Unlock()
	return nil
}
