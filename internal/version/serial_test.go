package version

import (
	"errors"
	"testing"
)

func TestSerialStrictlyIncreasing(t *testing.T) {
	a := NewSerialAllocator(0)
	var prev uint32
	for i := 0; i < 5; i++ {
		got, err := a.Next()
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		if got <= prev {
			t.Fatalf("serial %d not strictly greater than %d", got, prev)
		}
		prev = got
	}
	if a.Last() != 5 {
		t.Errorf("Last = %d, want 5", a.Last())
	}
}

func TestSerialNeverReusesAfterRestore(t *testing.T) {
	a := NewSerialAllocator(0)
	s1, _ := a.Next() // 1
	s2, _ := a.Next() // 2
	if s1 != 1 || s2 != 2 {
		t.Fatalf("got %d,%d want 1,2", s1, s2)
	}
	// Simulate restart: restore from persisted state.
	b := NewSerialAllocator(0)
	if err := b.Restore(a.Last()); err != nil {
		t.Fatal(err)
	}
	s3, _ := b.Next() // 3 — must not reuse 1 or 2
	if s3 != 3 {
		t.Errorf("after restore next = %d, want 3", s3)
	}
	if s3 == s1 || s3 == s2 {
		t.Errorf("serial reused: %d", s3)
	}
}

func TestSerialExhaustion(t *testing.T) {
	a := NewSerialAllocator(MaxSerial - 1)
	got, err := a.Next()
	if err != nil || got != MaxSerial {
		t.Fatalf("Next at max-1 = %d, %v; want %d nil", got, err, MaxSerial)
	}
	_, err = a.Next()
	if !errors.Is(err, ErrSerialExhausted) {
		t.Fatalf("expected ErrSerialExhausted, got %v", err)
	}
	// Exhaustion is terminal: subsequent calls keep failing and state is
	// unchanged.
	if a.Last() != MaxSerial {
		t.Errorf("Last changed after exhaustion: %d", a.Last())
	}
	_, err = a.Peek()
	if !errors.Is(err, ErrSerialExhausted) {
		t.Fatalf("Peek after exhaustion: %v", err)
	}
}

func TestRestoreRejectsDecrease(t *testing.T) {
	a := NewSerialAllocator(10)
	if err := a.Restore(5); err == nil {
		t.Fatal("restore below current should fail")
	}
}

func TestAdvanceTo(t *testing.T) {
	a := NewSerialAllocator(3)
	if err := a.AdvanceTo(10); err != nil {
		t.Fatal(err)
	}
	if a.Last() != 10 {
		t.Errorf("Last = %d, want 10", a.Last())
	}
	next, _ := a.Next()
	if next != 11 {
		t.Errorf("next after advance = %d, want 11", next)
	}
	if err := a.AdvanceTo(5); err == nil {
		t.Fatal("advance below current should fail")
	}
}
