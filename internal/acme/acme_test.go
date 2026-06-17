package acme_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/patrickbrandao/traefik-certs/internal/acme"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// writeACMEFile writes the given JSON object to a temp file and returns its path.
func writeACMEFile(t *testing.T, content interface{}) string {
	t.Helper()
	data, err := json.Marshal(content)
	if err != nil {
		t.Fatalf("marshal acme.json content: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "acme.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write acme.json: %v", err)
	}
	return path
}

// b64 base64-encodes a string the same way Traefik writes acme.json.
func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// fakePEM returns a syntactically valid PEM block for testing (not a real cert).
// We use a minimal DER-like payload that passes base64 decoding.
var fakeCertPEM = "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2a\n-----END CERTIFICATE-----\n"
var fakeKeyPEM = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIPl7cBm9tT/WU0ZvL1G\n-----END EC PRIVATE KEY-----\n"

// ---------------------------------------------------------------------------
// ParseACME — basic cases
// ---------------------------------------------------------------------------

func TestParseACME_FileNotFound(t *testing.T) {
	_, err := acme.ParseACME("/nonexistent/acme.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestParseACME_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acme.json")
	os.WriteFile(path, []byte{}, 0600)

	_, err := acme.ParseACME(path)
	if err == nil {
		t.Error("expected error for empty acme.json")
	}
}

func TestParseACME_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acme.json")
	os.WriteFile(path, []byte("{not valid json"), 0600)

	_, err := acme.ParseACME(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseACME_MissingCertOrKey(t *testing.T) {
	// An entry with certificate but no key should be silently ignored (logged at debug).
	content := map[string]interface{}{
		"myresolver": map[string]interface{}{
			"Certificates": []interface{}{
				map[string]interface{}{
					"certificate": b64(fakeCertPEM),
					// "key" intentionally omitted
					"domain": map[string]interface{}{
						"main": "example.com",
					},
				},
			},
		},
	}
	path := writeACMEFile(t, content)
	entries, err := acme.ParseACME(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for missing key, got %d", len(entries))
	}
}

func TestParseACME_TraefikV2Style(t *testing.T) {
	content := map[string]interface{}{
		"myresolver": map[string]interface{}{
			"Certificates": []interface{}{
				map[string]interface{}{
					"certificate": b64(fakeCertPEM),
					"key":         b64(fakeKeyPEM),
					"domain": map[string]interface{}{
						"main": "example.com",
						"sans": []string{"www.example.com"},
					},
				},
			},
		},
	}
	path := writeACMEFile(t, content)
	entries, err := acme.ParseACME(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Expect one entry per unique FQDN: example.com and www.example.com
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

func TestParseACME_CaseInsensitiveKeys(t *testing.T) {
	// Traefik v3 may use lowercase "certificates"
	content := map[string]interface{}{
		"myresolver": map[string]interface{}{
			"certificates": []interface{}{
				map[string]interface{}{
					"Certificate": b64(fakeCertPEM),
					"Key":         b64(fakeKeyPEM),
					"domain": map[string]interface{}{
						"main": "ci.example.com",
					},
				},
			},
		},
	}
	path := writeACMEFile(t, content)
	entries, err := acme.ParseACME(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry (case-insensitive keys), got %d", len(entries))
	}
}

func TestParseACME_WildcardSanitized(t *testing.T) {
	content := map[string]interface{}{
		"myresolver": map[string]interface{}{
			"Certificates": []interface{}{
				map[string]interface{}{
					"certificate": b64(fakeCertPEM),
					"key":         b64(fakeKeyPEM),
					"domain": map[string]interface{}{
						"main": "*.example.com",
					},
				},
			},
		},
	}
	path := writeACMEFile(t, content)
	entries, err := acme.ParseACME(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	// FQDN should be sanitized (strip "*.")
	if entries[0].FQDN != "example.com" {
		t.Errorf("FQDN = %q, want %q", entries[0].FQDN, "example.com")
	}
}

func TestParseACME_MultipleResolvers(t *testing.T) {
	content := map[string]interface{}{
		"resolver1": map[string]interface{}{
			"Certificates": []interface{}{
				map[string]interface{}{
					"certificate": b64(fakeCertPEM),
					"key":         b64(fakeKeyPEM),
					"domain":      map[string]interface{}{"main": "a.example.com"},
				},
			},
		},
		"resolver2": map[string]interface{}{
			"Certificates": []interface{}{
				map[string]interface{}{
					"certificate": b64(fakeCertPEM),
					"key":         b64(fakeKeyPEM),
					"domain":      map[string]interface{}{"main": "b.example.com"},
				},
			},
		},
	}
	path := writeACMEFile(t, content)
	entries, err := acme.ParseACME(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries from 2 resolvers, got %d", len(entries))
	}
}

func TestParseACME_EmptyResolver(t *testing.T) {
	content := map[string]interface{}{
		"myresolver": map[string]interface{}{
			"Certificates": []interface{}{},
		},
	}
	path := writeACMEFile(t, content)
	entries, err := acme.ParseACME(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for empty resolver, got %d", len(entries))
	}
}
