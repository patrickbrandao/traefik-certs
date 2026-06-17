package certstore_test

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/patrickbrandao/traefik-certs/internal/certstore"
	"github.com/patrickbrandao/traefik-certs/internal/certmodel"
)

// ---------------------------------------------------------------------------
// WriteAtomic
// ---------------------------------------------------------------------------

func TestWriteAtomic_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	s := certstore.New(dir)

	if err := s.WriteAtomic(dir, "test.txt", []byte("hello"), 0644); err != nil {
		t.Fatalf("WriteAtomic error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "test.txt"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("content = %q, want %q", string(data), "hello")
	}
}

func TestWriteAtomic_CorrectPermissions(t *testing.T) {
	dir := t.TempDir()
	s := certstore.New(dir)

	if err := s.WriteAtomic(dir, "secret.pem", []byte("key"), 0600); err != nil {
		t.Fatalf("WriteAtomic error: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "secret.pem"))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("permissions = %04o, want 0600", perm)
	}
}

func TestWriteAtomic_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	s := certstore.New(dir)

	s.WriteAtomic(dir, "file.txt", []byte("first"), 0644)
	s.WriteAtomic(dir, "file.txt", []byte("second"), 0644)

	data, _ := os.ReadFile(filepath.Join(dir, "file.txt"))
	if string(data) != "second" {
		t.Errorf("expected overwrite, got %q", string(data))
	}
}

func TestWriteAtomic_MkdirAll(t *testing.T) {
	base := t.TempDir()
	subDir := filepath.Join(base, "a", "b", "c")
	s := certstore.New(base)

	if err := s.WriteAtomic(subDir, "file.txt", []byte("x"), 0644); err != nil {
		t.Fatalf("WriteAtomic with nested dirs: %v", err)
	}
	if _, err := os.Stat(filepath.Join(subDir, "file.txt")); err != nil {
		t.Fatalf("file not created: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Lock — per-FQDN serialisation
// ---------------------------------------------------------------------------

func TestLock_SerializesAccess(t *testing.T) {
	dir := t.TempDir()
	s := certstore.New(dir)

	const workers = 10
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		counter int
	)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock := s.Lock("example.com")
			defer unlock()

			mu.Lock()
			counter++
			mu.Unlock()
		}()
	}

	wg.Wait()
	if counter != workers {
		t.Errorf("counter = %d, want %d", counter, workers)
	}
}

func TestLock_IndependentFQDNs(t *testing.T) {
	dir := t.TempDir()
	s := certstore.New(dir)

	// Locking different FQDNs concurrently should not deadlock.
	done := make(chan struct{})
	go func() {
		unlock := s.Lock("a.example.com")
		defer unlock()
		done <- struct{}{}
	}()
	go func() {
		unlock := s.Lock("b.example.com")
		defer unlock()
		done <- struct{}{}
	}()

	<-done
	<-done
}

// ---------------------------------------------------------------------------
// WriteCertFiles / WriteCertFilesFlat — DRY delegation (item 3.5)
// ---------------------------------------------------------------------------

func minimalCertJSON() *certmodel.CertJSON {
	return &certmodel.CertJSON{
		FQDN:    "example.com",
		CertMD5: "abc123",
		PEM: certmodel.PEMBlock{
			Cert:      "CERT",
			Chain:     "CHAIN",
			Fullchain: "FULLCHAIN",
			Privkey:   "KEY",
		},
	}
}

func TestWriteCertFiles_CreatesAllFiles(t *testing.T) {
	dir := t.TempDir()
	s := certstore.New(dir)
	cj := minimalCertJSON()

	if err := s.WriteCertFiles("example.com", cj); err != nil {
		t.Fatalf("WriteCertFiles: %v", err)
	}

	fqdnDir := filepath.Join(dir, "example.com")
	for _, name := range []string{"fullchain.pem", "cert.pem", "chain.pem", "privkey.pem", "cert.md5", "cert.json"} {
		if _, err := os.Stat(filepath.Join(fqdnDir, name)); err != nil {
			t.Errorf("missing file %s: %v", name, err)
		}
	}
}

func TestWriteCertFilesFlat_CreatesAllFiles(t *testing.T) {
	dir := t.TempDir()
	s := certstore.New(dir)
	cj := minimalCertJSON()

	dest := filepath.Join(dir, "dest")
	if err := os.MkdirAll(dest, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if err := s.WriteCertFilesFlat(dest, cj); err != nil {
		t.Fatalf("WriteCertFilesFlat: %v", err)
	}

	for _, name := range []string{"fullchain.pem", "cert.pem", "chain.pem", "privkey.pem", "cert.md5", "cert.json"} {
		if _, err := os.Stat(filepath.Join(dest, name)); err != nil {
			t.Errorf("missing file %s: %v", name, err)
		}
	}
}

func TestWriteCertFiles_PrivkeyPermissions(t *testing.T) {
	dir := t.TempDir()
	s := certstore.New(dir)
	cj := minimalCertJSON()

	if err := s.WriteCertFiles("example.com", cj); err != nil {
		t.Fatalf("WriteCertFiles: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "example.com", "privkey.pem"))
	if err != nil {
		t.Fatalf("Stat privkey.pem: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("privkey.pem permissions = %04o, want 0600", perm)
	}
}
