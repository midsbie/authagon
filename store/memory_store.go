package store

import (
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

func (s *MemoryStore) Set(sid string, value interface{}, duration time.Duration) error {
	s.sessions[sid] = value
	return nil
}

func (s *MemoryStore) Get(sid string) (interface{}, error) {
	if a, ok := s.sessions[sid]; ok {
		return a, nil
	}

	return nil, fmt.Errorf("session not found: %s", sid)
}

func (s *MemoryStore) Exists(sid string) (bool, error) {
	_, ok := s.sessions[sid]
	return ok, nil
}

func (s *MemoryStore) Del(sid string) error {
	delete(s.sessions, sid)
	return nil
}
