package certmodel_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/patrickbrandao/traefik-certs/internal/certmodel"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// makeCert generates a self-signed leaf certificate with the given DNS SANs.
// Returns (fullchainPEM, privkeyPEM, notBefore, notAfter).
func makeCert(t *testing.T, dnsNames []string, notBefore, notAfter time.Time) (fullchain, privkey string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		DNSNames:     dnsNames,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	return certPEM, keyPEM
}

// ---------------------------------------------------------------------------
// DecomposePEM
// ---------------------------------------------------------------------------

func TestDecomposePEM_SingleCert(t *testing.T) {
	fullchain, _ := makeCert(t, []string{"example.com"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	certPEM, chainPEM, err := certmodel.DecomposePEM(fullchain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if certPEM == "" {
		t.Error("certPEM should not be empty")
	}
	if chainPEM != "" {
		t.Errorf("chainPEM should be empty for single-cert fullchain, got %q", chainPEM)
	}
}

func TestDecomposePEM_TwoCerts(t *testing.T) {
	leaf, _ := makeCert(t, []string{"example.com"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	intermediate, _ := makeCert(t, []string{"ca.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	fullchain := leaf + intermediate

	certPEM, chainPEM, err := certmodel.DecomposePEM(fullchain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if certPEM != leaf {
		t.Error("certPEM should equal the leaf cert")
	}
	if chainPEM != intermediate {
		t.Error("chainPEM should equal the intermediate cert")
	}
}

func TestDecomposePEM_Empty(t *testing.T) {
	_, _, err := certmodel.DecomposePEM("")
	if err == nil {
		t.Error("expected error for empty PEM")
	}
}

func TestDecomposePEM_NoCertBlock(t *testing.T) {
	_, _, err := certmodel.DecomposePEM("not a pem block")
	if err == nil {
		t.Error("expected error when no CERTIFICATE block found")
	}
}

// ---------------------------------------------------------------------------
// CoversWildcard
// ---------------------------------------------------------------------------

func TestCoversWildcard(t *testing.T) {
	cj := &certmodel.CertJSON{SANs: []string{"*.example.com"}}

	cases := []struct {
		fqdn string
		want bool
	}{
		{"foo.example.com", true},
		{"bar.example.com", true},
		{"example.com", false},                // apex not covered
		{"sub.foo.example.com", false},         // two levels deep
		{"foo.other.com", false},               // different domain
		{"*.example.com", false},               // wildcard itself
		{"foo.example.org", false},
	}

	for _, tc := range cases {
		got := cj.CoversWildcard(tc.fqdn)
		if got != tc.want {
			t.Errorf("CoversWildcard(%q) = %v, want %v", tc.fqdn, got, tc.want)
		}
	}
}

func TestCoversWildcard_NoWildcardSAN(t *testing.T) {
	cj := &certmodel.CertJSON{SANs: []string{"example.com", "www.example.com"}}
	if cj.CoversWildcard("foo.example.com") {
		t.Error("expected false when no wildcard SAN present")
	}
}

// ---------------------------------------------------------------------------
// IsValidNow (boundary conditions per SPEC §5)
// ---------------------------------------------------------------------------

func TestIsValidNow_CurrentlyValid(t *testing.T) {
	now := time.Now().UTC()
	cj := &certmodel.CertJSON{
		NotBeforeUnix: now.Add(-time.Hour).Unix(),
		NotAfterUnix:  now.Add(time.Hour).Unix(),
	}
	if !cj.IsValidNow() {
		t.Error("expected valid certificate to be valid now")
	}
}

func TestIsValidNow_ExactlyAtNotBefore(t *testing.T) {
	now := time.Now().UTC()
	cj := &certmodel.CertJSON{
		NotBeforeUnix: now.Unix(),
		NotAfterUnix:  now.Add(time.Hour).Unix(),
	}
	if !cj.IsValidNow() {
		t.Error("expected cert to be valid at exactly not_before (inclusive)")
	}
}

func TestIsValidNow_ExactlyAtNotAfter(t *testing.T) {
	now := time.Now().UTC()
	cj := &certmodel.CertJSON{
		NotBeforeUnix: now.Add(-time.Hour).Unix(),
		NotAfterUnix:  now.Unix(),
	}
	if !cj.IsValidNow() {
		t.Error("expected cert to be valid at exactly not_after (inclusive)")
	}
}

func TestIsValidNow_Expired(t *testing.T) {
	now := time.Now().UTC()
	cj := &certmodel.CertJSON{
		NotBeforeUnix: now.Add(-2 * time.Hour).Unix(),
		NotAfterUnix:  now.Add(-time.Hour).Unix(),
	}
	if cj.IsValidNow() {
		t.Error("expected expired certificate to be invalid")
	}
}

func TestIsValidNow_NotYetValid(t *testing.T) {
	now := time.Now().UTC()
	cj := &certmodel.CertJSON{
		NotBeforeUnix: now.Add(time.Hour).Unix(),
		NotAfterUnix:  now.Add(2 * time.Hour).Unix(),
	}
	if cj.IsValidNow() {
		t.Error("expected future certificate to be invalid now")
	}
}

// ---------------------------------------------------------------------------
// BuildCertJSON — SANs come from x509 (SPEC §5) and IsCurrentlyValid is inclusive
// ---------------------------------------------------------------------------

func TestBuildCertJSON_SANsFromX509(t *testing.T) {
	dnsNames := []string{"example.com", "www.example.com"}
	fullchain, privkey := makeCert(t, dnsNames, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	// Pass empty sans to prove the field is populated from the certificate, not the argument.
	cj, err := certmodel.BuildCertJSON("example.com", nil, fullchain, privkey, "acme", "test")
	if err != nil {
		t.Fatalf("BuildCertJSON error: %v", err)
	}
	if len(cj.SANs) != len(dnsNames) {
		t.Fatalf("expected %d SANs, got %d", len(dnsNames), len(cj.SANs))
	}
	for i, want := range dnsNames {
		if cj.SANs[i] != want {
			t.Errorf("SANs[%d] = %q, want %q", i, cj.SANs[i], want)
		}
	}
}

func TestBuildCertJSON_SANsFromX509IgnoresArgument(t *testing.T) {
	dnsNames := []string{"real.example.com"}
	fullchain, privkey := makeCert(t, dnsNames, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	// Pass different SANs in the argument — they must be ignored.
	cj, err := certmodel.BuildCertJSON("real.example.com", []string{"fake.example.com"}, fullchain, privkey, "acme", "test")
	if err != nil {
		t.Fatalf("BuildCertJSON error: %v", err)
	}
	if len(cj.SANs) != 1 || cj.SANs[0] != "real.example.com" {
		t.Errorf("expected SANs from x509, got %v", cj.SANs)
	}
}

func TestBuildCertJSON_IsCurrentlyValidInclusive(t *testing.T) {
	// Certificate whose NotBefore equals now — should be valid (inclusive).
	notBefore := time.Now().UTC().Truncate(time.Second)
	notAfter := notBefore.Add(time.Hour)
	fullchain, privkey := makeCert(t, []string{"example.com"}, notBefore, notAfter)

	cj, err := certmodel.BuildCertJSON("example.com", nil, fullchain, privkey, "acme", "test")
	if err != nil {
		t.Fatalf("BuildCertJSON error: %v", err)
	}
	if !cj.IsCurrentlyValid {
		t.Error("IsCurrentlyValid should be true when now == notBefore (inclusive per SPEC §5)")
	}
}
