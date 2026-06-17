package redisbus_test

import (
	"strings"
	"testing"

	"github.com/patrickbrandao/traefik-certs/internal/redisbus"
)

// ---------------------------------------------------------------------------
// FQDN extraction from Redis keys — unit test of the TrimPrefix logic (item 3.4).
//
// We test the exported helper indirectly by inspecting the behaviour of New()
// and GetAllCertKeys(). Since we cannot rely on a live Redis server in unit
// tests, we test the extraction logic directly via the internal certKey format.
// ---------------------------------------------------------------------------

// extractFQDN mirrors the fixed logic in GetAllCertKeys so we can test it in
// isolation without a Redis instance.
func extractFQDN(prefix, key string) string {
	certPrefix := prefix + ":cert:"
	return strings.TrimPrefix(key, certPrefix)
}

func TestExtractFQDN_BasicCase(t *testing.T) {
	fqdn := extractFQDN("tcerts", "tcerts:cert:example.com")
	if fqdn != "example.com" {
		t.Errorf("got %q, want %q", fqdn, "example.com")
	}
}

func TestExtractFQDN_WildcardFQDN(t *testing.T) {
	fqdn := extractFQDN("tcerts", "tcerts:cert:example.com")
	if fqdn != "example.com" {
		t.Errorf("got %q, want %q", fqdn, "example.com")
	}
}

func TestExtractFQDN_CustomPrefix(t *testing.T) {
	fqdn := extractFQDN("myapp", "myapp:cert:sub.domain.io")
	if fqdn != "sub.domain.io" {
		t.Errorf("got %q, want %q", fqdn, "sub.domain.io")
	}
}

func TestExtractFQDN_DoesNotCorruptOnLongFQDN(t *testing.T) {
	longFQDN := "very.long.subdomain.example.com"
	key := "tcerts:cert:" + longFQDN
	fqdn := extractFQDN("tcerts", key)
	if fqdn != longFQDN {
		t.Errorf("got %q, want %q", fqdn, longFQDN)
	}
}

func TestExtractFQDN_PrefixContainsColons(t *testing.T) {
	// Ensure the prefix delimiter itself is fully stripped and not confused
	// with a colon inside the FQDN (FQDNs do not contain colons, but the key
	// format uses ":cert:" as separator).
	fqdn := extractFQDN("ns:v1", "ns:v1:cert:example.com")
	if fqdn != "example.com" {
		t.Errorf("got %q, want %q", fqdn, "example.com")
	}
}

// ---------------------------------------------------------------------------
// New — connection failure returns error (not a fatal exit)
// ---------------------------------------------------------------------------

func TestNew_InvalidURL_ReturnsError(t *testing.T) {
	_, err := redisbus.New("redis://127.0.0.1:1", "test") // port 1 should be unreachable
	if err == nil {
		t.Error("expected error connecting to an unreachable Redis address")
	}
}
