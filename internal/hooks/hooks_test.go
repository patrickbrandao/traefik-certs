package hooks_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/patrickbrandao/traefik-certs/internal/certmodel"
	"github.com/patrickbrandao/traefik-certs/internal/config"
	"github.com/patrickbrandao/traefik-certs/internal/hooks"
)

// TestRunHook2_FanOutParallel verifica que múltiplas URLs recebem o POST em
// paralelo e que cada uma é contatada independentemente (SPEC §9.2).
func TestRunHook2_FanOutParallel(t *testing.T) {
	var gotA, gotB int32
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&gotA, 1)
		w.WriteHeader(http.StatusOK)
	}))
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&gotB, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer a.Close()
	defer b.Close()

	cfg := &config.Config{
		WebhookURLs:    []string{a.URL, b.URL},
		WebhookTimeout: 2 * time.Second,
		WebhookRetries: 0,
	}
	cj := &certmodel.CertJSON{FQDN: "example.com"}

	var wg sync.WaitGroup
	hooks.RunHook2(context.Background(), cfg, &wg, cj)
	wg.Wait()

	if atomic.LoadInt32(&gotA) != 1 {
		t.Errorf("URL A recebeu %d POSTs, want 1", gotA)
	}
	if atomic.LoadInt32(&gotB) != 1 {
		t.Errorf("URL B recebeu %d POSTs, want 1", gotB)
	}
}

// TestRunHook2_PartialFailure verifica que a falha de uma URL (após retries)
// não impede as demais de receberem o POST (SPEC §9.2, §13).
func TestRunHook2_PartialFailure(t *testing.T) {
	var okCount int32
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&okCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ok.Close()
	defer fail.Close()

	cfg := &config.Config{
		WebhookURLs:    []string{ok.URL, fail.URL},
		WebhookTimeout: 1 * time.Second,
		WebhookRetries: 1, // backoff pequeno: 1s entre tentativa 0 e 1
	}
	cj := &certmodel.CertJSON{FQDN: "example.com"}

	var wg sync.WaitGroup
	hooks.RunHook2(context.Background(), cfg, &wg, cj)
	wg.Wait()

	if atomic.LoadInt32(&okCount) != 1 {
		t.Errorf("URL OK recebeu %d POSTs, want 1 (falha da outra URL não deve afetá-la)", okCount)
	}
}

// TestRunHook2_EmptyListNoop verifica que lista vazia não dispara nada.
func TestRunHook2_EmptyListNoop(t *testing.T) {
	cfg := &config.Config{
		WebhookURLs:    nil,
		WebhookTimeout: 1 * time.Second,
		WebhookRetries: 0,
	}
	cj := &certmodel.CertJSON{FQDN: "example.com"}

	var wg sync.WaitGroup
	hooks.RunHook2(context.Background(), cfg, &wg, cj)
	wg.Wait() // não deve bloquear nem disparar goroutines
}
