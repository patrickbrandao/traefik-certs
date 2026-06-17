package reconcile_test

import (
	"context"
	"testing"
	"time"

	"github.com/patrickbrandao/traefik-certs/internal/reconcile"
)

// ---------------------------------------------------------------------------
// SourceTable — concurrent safety (item 1.1)
// ---------------------------------------------------------------------------

func TestSourceTable_SetGet(t *testing.T) {
	st := reconcile.NewSourceTable()
	st.Set("example.com", "acme")
	if got := st.Get("example.com"); got != "acme" {
		t.Errorf("Get = %q, want %q", got, "acme")
	}
}

func TestSourceTable_GetMissing(t *testing.T) {
	st := reconcile.NewSourceTable()
	if got := st.Get("missing.example.com"); got != "" {
		t.Errorf("Get of missing key = %q, want empty string", got)
	}
}

func TestSourceTable_Overwrite(t *testing.T) {
	st := reconcile.NewSourceTable()
	st.Set("example.com", "acme")
	st.Set("example.com", "redis")
	if got := st.Get("example.com"); got != "redis" {
		t.Errorf("Get after overwrite = %q, want redis", got)
	}
}

func TestSourceTable_ConcurrentSetGet(t *testing.T) {
	st := reconcile.NewSourceTable()

	// Fire multiple goroutines doing concurrent reads and writes.
	// The race detector will flag any data race if the mutex is absent.
	const n = 50
	done := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		go func() {
			st.Set("example.com", "acme")
			_ = st.Get("example.com")
			done <- struct{}{}
		}()
	}
	for i := 0; i < n; i++ {
		<-done
	}
}

// ---------------------------------------------------------------------------
// WaitAndContinue — context cancellation (item 1.3)
// ---------------------------------------------------------------------------

func TestWaitAndContinue_ReturnsTrueAfterInterval(t *testing.T) {
	ctx := context.Background()
	start := time.Now()
	got := reconcile.WaitAndContinue(ctx, 10*time.Millisecond)
	elapsed := time.Since(start)

	if !got {
		t.Error("expected true when context is not cancelled")
	}
	if elapsed < 10*time.Millisecond {
		t.Errorf("returned too early: elapsed = %v", elapsed)
	}
}

func TestWaitAndContinue_ReturnsFalseOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	got := reconcile.WaitAndContinue(ctx, 10*time.Second)
	if got {
		t.Error("expected false when context is already cancelled")
	}
}

func TestWaitAndContinue_CancelDuringWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	got := reconcile.WaitAndContinue(ctx, 10*time.Second)
	elapsed := time.Since(start)

	if got {
		t.Error("expected false when context cancelled mid-wait")
	}
	// Should have returned well before the 10s interval.
	if elapsed > 2*time.Second {
		t.Errorf("waited too long after cancellation: elapsed = %v", elapsed)
	}
}
