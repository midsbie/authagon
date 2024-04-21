package store

import (
	"context"
	"fmt"
	"time"
)

var _ SessionStorer = (*MemoryStore)(nil)

type MemoryStore struct {
	sessions map[string]interface{}
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sessions: map[string]interface{}{}}
}

func (s *MemoryStore) Set(ctx context.Context, sid string, value interface{},
	duration time.Duration) (SetSessionReporter, error) {
	s.sessions[sid] = value
	return NewSetSessionResponse(sid, SessionCreatedExistingAccount), nil
}

func (s *MemoryStore) Get(ctx context.Context, sid string) (interface{}, bool, error) {
	if a, ok := s.sessions[sid]; ok {
		return a, true, nil
	}

	return nil, false, fmt.Errorf("session not found: %s", sid)
}

func (s *MemoryStore) Del(ctx context.Context, sid string) error {
	delete(s.sessions, sid)
	return nil
}
