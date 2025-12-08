package store

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestMemoryStoreSetGet(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore[map[string]string]()
	ctx := context.Background()

	const sid = "abc123"
	val := map[string]string{"k": "v"}

	if err := s.Set(ctx, sid, val, time.Minute); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	got, err := s.Get(ctx, sid)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got["k"] != "v" {
		t.Fatalf("Get() value = %#v, want %v", got, val)
	}
}

func TestMemoryStoreExpiration(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore[string]()
	ctx := context.Background()

	const sid = "expires"
	if err := s.Set(ctx, sid, "value", 10*time.Millisecond); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Immediately available.
	if v, err := s.Get(ctx, sid); err != nil || v != "value" {
		t.Fatalf("Get() before expiry = (v=%v, err=%v), want value/nil", v, err)
	}

	// Wait for expiry.
	time.Sleep(20 * time.Millisecond)

	v, err := s.Get(ctx, sid)
	if err == nil {
		t.Fatalf("Get() after expiry error = nil, want ErrNotFound")
	}
	if v != "" {
		t.Fatalf("Get() after expiry value = %#v, want empty", v)
	}
}

func TestMemoryStoreGetNotFound(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore[int]()
	ctx := context.Background()

	got, err := s.Get(ctx, "does-not-exist")
	if err == nil {
		t.Fatalf("Get() error = nil, want ErrNotFound")
	}
	if got != 0 {
		t.Fatalf("Get() value = %#v, want zero", got)
	}
}

func TestMemoryStoreDel(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore[int]()
	ctx := context.Background()

	const sid = "to-delete"
	if err := s.Set(ctx, sid, 42, time.Minute); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	if err := s.Del(ctx, sid); err != nil {
		t.Fatalf("Del() error = %v", err)
	}

	_, err := s.Get(ctx, sid)
	if err == nil {
		t.Fatalf("Get() after Del() error = nil, want ErrNotFound")
	}

	// Deleting non-existent key should be a no-op.
	if err := s.Del(ctx, sid); err != nil {
		t.Fatalf("Del() non-existent error = %v, want nil", err)
	}
}

func TestMemoryStoreConcurrentAccess(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore[int]()
	ctx := context.Background()

	const writers = 50
	const readsPerWriter = 100

	var wg sync.WaitGroup
	wg.Add(writers)

	// Concurrent writers.
	for w := 0; w < writers; w++ {
		w := w
		go func() {
			defer wg.Done()
			sid := func(i int) string { return "sid-" + strconv.Itoa(w) + "-" + strconv.Itoa(i) }
			for i := 0; i < readsPerWriter; i++ {
				if err := s.Set(ctx, sid(i), i, time.Minute); err != nil {
					t.Errorf("Set() error (w=%d,i=%d): %v", w, i, err)
				}
			}
		}()
	}

	wg.Wait()

	// Concurrent readers.
	var rWg sync.WaitGroup
	rWg.Add(writers)
	for w := 0; w < writers; w++ {
		w := w
		go func() {
			defer rWg.Done()
			sid := func(i int) string { return "sid-" + strconv.Itoa(w) + "-" + strconv.Itoa(i) }
			for i := 0; i < readsPerWriter; i++ {
				v, err := s.Get(ctx, sid(i))
				if err != nil {
					t.Errorf("Get() missing value (w=%d,i=%d): err=%v", w, i, err)
					continue
				}
				if v != i {
					t.Errorf("Get() value mismatch (w=%d,i=%d): got=%v want=%v", w, i, v, i)
				}
			}
		}()
	}
	rWg.Wait()
}
