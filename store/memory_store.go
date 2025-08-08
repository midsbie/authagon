package store

import (
	"context"
	"fmt"
	"time"
)

var _ SessionStorer = (*MemoryStore)(nil)

type MemoryStore struct {
	sessions map[string]any
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sessions: map[string]any{}}
}

func (s *MemoryStore) Set(ctx context.Context, sid string, value any,
	duration time.Duration) (SessionResultReporter, error) {
	s.sessions[sid] = value
	return NewSessionResult(false), nil
}

func (s *MemoryStore) Get(ctx context.Context, sid string) (any, bool, error) {
	if a, ok := s.sessions[sid]; ok {
		return a, true, nil
	}

	return nil, false, fmt.Errorf("session not found: %s", sid)
}

func (s *MemoryStore) Del(ctx context.Context, sid string) error {
	delete(s.sessions, sid)
	return nil
}
