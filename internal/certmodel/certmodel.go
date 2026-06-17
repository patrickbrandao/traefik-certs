package certmodel

import (
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

type CertJSON struct {
	FQDN              string   `json:"fqdn"`
	SANs              []string `json:"sans"`
	IsWildcard        bool     `json:"is_wildcard"`
	SubjectCN         string   `json:"subject_cn"`
	IssuerCN          string   `json:"issuer_cn"`
	IssuerOrg         string   `json:"issuer_org"`
	Serial            string   `json:"serial"`
	NotBefore         string   `json:"not_before"`
	NotBeforeUnix     int64    `json:"not_before_unix"`
	NotAfter          string   `json:"not_after"`
	NotAfterUnix      int64    `json:"not_after_unix"`
	SecondsToExpiry   int64    `json:"seconds_to_expiry"`
	IsCurrentlyValid  bool     `json:"is_currently_valid"`
	FingerprintSHA256 string   `json:"fingerprint_sha256"`
	CertMD5           string   `json:"cert_md5"`
	KeyAlgorithm      string   `json:"key_algorithm"`
	KeyBits           int      `json:"key_bits"`
	SignatureAlgo     string   `json:"signature_algorithm"`
	Source            string   `json:"source"`
	AcmeResolver      string   `json:"acme_resolver"`
	UpdatedAt         string   `json:"updated_at"`
	PEM               PEMBlock `json:"pem"`
	Hash              CertHash `json:"hash"`
}

type PEMBlock struct {
	Cert      string `json:"cert"`
	Chain     string `json:"chain"`
	Fullchain string `json:"fullchain"`
	Privkey   string `json:"privkey"`
}

type CertHash struct {
	Cert      string `json:"cert"`
	Chain     string `json:"chain"`
	Fullchain string `json:"fullchain"`
	Privkey   string `json:"privkey"`
}

func SanitizeFQDN(fqdn string) string {
	return strings.TrimPrefix(fqdn, "*.")
}

func IsWildcardSANs(sans []string) bool {
	for _, s := range sans {
		if strings.HasPrefix(s, "*.") {
			return true
		}
	}
	return false
}

func DecomposePEM(fullchainPEM string) (certPEM, chainPEM string, err error) {
	blocks := []string{}
	rest := []byte(fullchainPEM)
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			blocks = append(blocks, string(pem.EncodeToMemory(block)))
		}
		rest = remaining
		if len(rest) == 0 {
			break
		}
	}
	if len(blocks) == 0 {
		return "", "", fmt.Errorf("no CERTIFICATE blocks found in fullchain PEM")
	}
	certPEM = blocks[0]
	chainPEM = strings.Join(blocks[1:], "")
	return certPEM, chainPEM, nil
}

// BuildCertJSON constructs a CertJSON from PEM data.
// The sans parameter (from the ACME JSON) is used only to determine which FQDN
// directories to create; the SANs stored in CertJSON are always read
// authoritatively from the x509 certificate (SPEC §5).
func BuildCertJSON(fqdn string, sans []string, fullchainPEM, privkeyPEM, source, acmeResolver string) (*CertJSON, error) {
	certPEM, chainPEM, err := DecomposePEM(fullchainPEM)
	if err != nil {
		return nil, fmt.Errorf("decompose PEM: %w", err)
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse x509: %w", err)
	}

	now := time.Now().UTC()
	notBefore := cert.NotBefore.UTC()
	notAfter := cert.NotAfter.UTC()

	// SANs are always read from the x509 certificate (authoritative source per SPEC §5).
	// Fallback to Subject CN only when the certificate itself carries no DNSNames.
	leafSANs := cert.DNSNames
	if len(leafSANs) == 0 && cert.Subject.CommonName != "" {
		leafSANs = []string{cert.Subject.CommonName}
	}

	derHash := sha256.Sum256(cert.Raw)
	fingerprint := hex.EncodeToString(derHash[:])

	certMD5Sum := md5.Sum([]byte(certPEM))
	certMD5 := hex.EncodeToString(certMD5Sum[:])

	fullchainMD5 := md5.Sum([]byte(fullchainPEM))
	chainMD5 := md5.Sum([]byte(chainPEM))
	privkeyMD5 := md5.Sum([]byte(privkeyPEM))

	keyAlgo := ""
	keyBits := 0
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		keyAlgo = "RSA"
		keyBits = pub.N.BitLen()
	case *ecdsa.PublicKey:
		keyAlgo = "ECDSA"
		keyBits = pub.Curve.Params().BitSize
	default:
		keyAlgo = fmt.Sprintf("%T", cert.PublicKey)
	}

	issuerCN := cert.Issuer.CommonName
	if issuerCN == "" && len(cert.Issuer.Organization) > 0 {
		issuerCN = cert.Issuer.Organization[0]
	}
	issuerOrg := ""
	if len(cert.Issuer.Organization) > 0 {
		issuerOrg = cert.Issuer.Organization[0]
	}

	serial := fmt.Sprintf("%x", cert.SerialNumber)

	sigAlgo := cert.SignatureAlgorithm.String()

	isWildcard := IsWildcardSANs(leafSANs)

	// SPEC §5: not_before <= now <= not_after (both bounds inclusive).
	isValid := !now.Before(notBefore) && !now.After(notAfter)

	secondsToExpiry := int64(notAfter.Sub(now).Seconds())
	if secondsToExpiry < 0 {
		secondsToExpiry = 0
	}

	return &CertJSON{
		FQDN:              fqdn,
		SANs:              leafSANs,
		IsWildcard:        isWildcard,
		SubjectCN:         cert.Subject.CommonName,
		IssuerCN:          issuerCN,
		IssuerOrg:         issuerOrg,
		Serial:            serial,
		NotBefore:         notBefore.Format(time.RFC3339),
		NotBeforeUnix:     notBefore.Unix(),
		NotAfter:          notAfter.Format(time.RFC3339),
		NotAfterUnix:      notAfter.Unix(),
		SecondsToExpiry:   secondsToExpiry,
		IsCurrentlyValid:  isValid,
		FingerprintSHA256: fingerprint,
		CertMD5:           certMD5,
		KeyAlgorithm:      keyAlgo,
		KeyBits:           keyBits,
		SignatureAlgo:     sigAlgo,
		Source:            source,
		AcmeResolver:      acmeResolver,
		UpdatedAt:         now.Format(time.RFC3339),
		PEM: PEMBlock{
			Cert:      certPEM,
			Chain:     chainPEM,
			Fullchain: fullchainPEM,
			Privkey:   privkeyPEM,
		},
		Hash: CertHash{
			Cert:      certMD5,
			Chain:     hex.EncodeToString(chainMD5[:]),
			Fullchain: hex.EncodeToString(fullchainMD5[:]),
			Privkey:   hex.EncodeToString(privkeyMD5[:]),
		},
	}, nil
}

func (cj *CertJSON) MatchesExact(fqdn string) bool {
	for _, s := range cj.SANs {
		if s == fqdn {
			return true
		}
	}
	return false
}

func (cj *CertJSON) CoversWildcard(fqdn string) bool {
	for _, s := range cj.SANs {
		if strings.HasPrefix(s, "*.") {
			domain := s[2:]
			if !strings.HasPrefix(fqdn, "*.") && strings.HasSuffix(fqdn, "."+domain) {
				parts := strings.Split(fqdn, ".")
				wildParts := strings.Split(domain, ".")
				if len(parts) == len(wildParts)+1 {
					return true
				}
			}
		}
	}
	return false
}

// IsValidNow reports whether the certificate is currently valid per SPEC §5:
// not_before_unix <= now <= not_after_unix (both bounds inclusive).
func (cj *CertJSON) IsValidNow() bool {
	now := time.Now().UTC()
	nb := cj.NotBeforeUnix
	na := cj.NotAfterUnix
	nowUnix := now.Unix()
	return nowUnix >= nb && nowUnix <= na
}
