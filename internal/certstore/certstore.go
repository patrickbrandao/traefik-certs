package certstore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/patrickbrandao/traefik-certs/internal/certmodel"
)

type Store struct {
	saveDir string
	locks   map[string]*sync.Mutex
	mu      sync.Mutex
}

func New(saveDir string) *Store {
	return &Store{
		saveDir: saveDir,
		locks:   make(map[string]*sync.Mutex),
	}
}

func (s *Store) Lock(fqdn string) func() {
	s.mu.Lock()
	lk, ok := s.locks[fqdn]
	if !ok {
		lk = &sync.Mutex{}
		s.locks[fqdn] = lk
	}
	s.mu.Unlock()
	lk.Lock()
	return lk.Unlock
}

func (s *Store) FQDNPath(fqdn string) string {
	return filepath.Join(s.saveDir, fqdn)
}

func (s *Store) Exists(fqdn string) bool {
	_, err := os.Stat(s.FQDNPath(fqdn))
	return err == nil
}

func (s *Store) ReadCertJSON(fqdn string) (*certmodel.CertJSON, error) {
	path := filepath.Join(s.FQDNPath(fqdn), "cert.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cj certmodel.CertJSON
	if err := json.Unmarshal(data, &cj); err != nil {
		return nil, fmt.Errorf("parse cert.json: %w", err)
	}
	return &cj, nil
}

func (s *Store) ScanFQDNs() ([]string, error) {
	entries, err := os.ReadDir(s.saveDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var fqdns []string
	for _, e := range entries {
		if e.IsDir() {
			fqdns = append(fqdns, e.Name())
		}
	}
	return fqdns, nil
}

func (s *Store) WriteAtomic(dir string, name string, data []byte, perm os.FileMode) error {
	dirPath := dir
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dirPath, err)
	}
	tmpFile, err := os.CreateTemp(dirPath, ".tmp-"+name+"-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write temp file: %w", err)
	}
	tmpFile.Close()
	if err := os.Chmod(tmpPath, perm); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("chmod temp file: %w", err)
	}
	finalPath := filepath.Join(dirPath, name)
	if err := os.Rename(tmpPath, finalPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}

// writeCertFilesToDir writes all certificate files into the specified directory.
// It is the shared implementation for WriteCertFiles and WriteCertFilesFlat.
func (s *Store) writeCertFilesToDir(dir string, cj *certmodel.CertJSON) error {
	if err := s.WriteAtomic(dir, "fullchain.pem", []byte(cj.PEM.Fullchain), 0644); err != nil {
		return err
	}
	if err := s.WriteAtomic(dir, "cert.pem", []byte(cj.PEM.Cert), 0644); err != nil {
		return err
	}
	if err := s.WriteAtomic(dir, "chain.pem", []byte(cj.PEM.Chain), 0644); err != nil {
		return err
	}
	if err := s.WriteAtomic(dir, "privkey.pem", []byte(cj.PEM.Privkey), 0600); err != nil {
		return err
	}
	if err := s.WriteAtomic(dir, "cert.md5", []byte(cj.CertMD5+"\n"), 0644); err != nil {
		return err
	}

	cjBytes, err := json.MarshalIndent(cj, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal cert.json: %w", err)
	}
	if err := s.WriteAtomic(dir, "cert.json", cjBytes, 0600); err != nil {
		return err
	}

	return nil
}

// WriteCertFiles writes all certificate files under saveDir/<fqdn>/.
func (s *Store) WriteCertFiles(fqdn string, cj *certmodel.CertJSON) error {
	return s.writeCertFilesToDir(s.FQDNPath(fqdn), cj)
}

// WriteCertFilesFlat writes all certificate files into an arbitrary flat directory.
func (s *Store) WriteCertFilesFlat(dir string, cj *certmodel.CertJSON) error {
	return s.writeCertFilesToDir(dir, cj)
}
