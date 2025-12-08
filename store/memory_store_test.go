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

	s := NewMemoryStore()
	ctx := context.Background()

	const sid = "abc123"
	val := map[string]string{"k": "v"}

	res, err := s.Set(ctx, sid, val, time.Minute)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if res == nil || !res.SessionCreated() {
		t.Fatalf("Set() SessionResultReporter unexpected: %#v, want SessionCreated()=true", res)
	}

	got, ok, err := s.Get(ctx, sid)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !ok {
		t.Fatalf("Get() ok = false, want true")
	}
	m, ok := got.(map[string]string)
	if !ok || m["k"] != "v" {
		t.Fatalf("Get() value = %#v, want %v", got, val)
	}
}

func TestMemoryStoreExpiration(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore()
	ctx := context.Background()

	const sid = "expires"
	if _, err := s.Set(ctx, sid, "value", 10*time.Millisecond); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Immediately available.
	if v, ok, err := s.Get(ctx, sid); err != nil || !ok || v.(string) != "value" {
		t.Fatalf("Get() before expiry = (v=%v, ok=%v, err=%v), want value/true/nil", v, ok, err)
	}

	// Wait for expiry.
	time.Sleep(20 * time.Millisecond)

	v, ok, err := s.Get(ctx, sid)
	if err != nil {
		t.Fatalf("Get() after expiry error = %v, want nil", err)
	}
	if ok {
		t.Fatalf("Get() after expiry ok = true, want false")
	}
	if v != nil {
		t.Fatalf("Get() after expiry value = %#v, want nil", v)
	}
}

func TestMemoryStoreGetNotFound(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore()
	ctx := context.Background()

	got, ok, err := s.Get(ctx, "does-not-exist")
	if err != nil {
		t.Fatalf("Get() error = %v, want nil", err)
	}
	if ok {
		t.Fatalf("Get() ok = true, want false")
	}
	if got != nil {
		t.Fatalf("Get() value = %#v, want nil", got)
	}
}

func TestMemoryStoreDel(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore()
	ctx := context.Background()

	const sid = "to-delete"
	if _, err := s.Set(ctx, sid, 42, time.Minute); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	if err := s.Del(ctx, sid); err != nil {
		t.Fatalf("Del() error = %v", err)
	}

	_, ok, err := s.Get(ctx, sid)
	if err != nil {
		t.Fatalf("Get() after Del() error = %v, want nil", err)
	}
	if ok {
		t.Fatalf("Get() after Del() ok = true, want false")
	}

	// Deleting non-existent key should be a no-op.
	if err := s.Del(ctx, sid); err != nil {
		t.Fatalf("Del() non-existent error = %v, want nil", err)
	}
}

func TestMemoryStoreConcurrentAccess(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore()
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
				if _, err := s.Set(ctx, sid(i), i, time.Minute); err != nil {
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
				v, ok, err := s.Get(ctx, sid(i))
				if err != nil || !ok {
					t.Errorf("Get() missing value (w=%d,i=%d): ok=%v err=%v", w, i, ok, err)
					continue
				}
				if vi, _ := v.(int); vi != i {
					t.Errorf("Get() value mismatch (w=%d,i=%d): got=%v want=%v", w, i, vi, i)
				}
			}
		}()
	}
	rWg.Wait()
}
