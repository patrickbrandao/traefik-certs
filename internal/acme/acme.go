package acme

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/patrickbrandao/traefik-certs/internal/certmodel"
)

type AcmeEntry struct {
	FQDN         string
	SANs         []string
	FullchainPEM string
	PrivkeyPEM   string
	Resolver     string
}

func ParseACME(path string) ([]AcmeEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read acme.json: %w", err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("acme.json is empty")
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse acme.json: %w", err)
	}

	var entries []AcmeEntry
	for resolverName, resolverData := range raw {
		certsData := extractCerts(resolverData)
		for _, certData := range certsData {
			entry := parseCertEntry(certData, resolverName)
			if entry != nil {
				for fqdn := range uniqueFQDNs(entry) {
					e := *entry
					e.FQDN = fqdn
					entries = append(entries, e)
				}
			}
		}
	}

	return entries, nil
}

func extractCerts(resolverData json.RawMessage) []map[string]interface{} {
	var obj map[string]interface{}
	if err := json.Unmarshal(resolverData, &obj); err != nil {
		return nil
	}
	for key, val := range obj {
		if strings.EqualFold(key, "certificates") {
			if arr, ok := val.([]interface{}); ok {
				var result []map[string]interface{}
				for _, item := range arr {
					if m, ok := item.(map[string]interface{}); ok {
						result = append(result, m)
					}
				}
				return result
			}
		}
	}
	return nil
}

func getString(obj map[string]interface{}, key string) string {
	for k, v := range obj {
		if strings.EqualFold(k, key) {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

func getStringSlice(obj map[string]interface{}, key string) []string {
	for k, v := range obj {
		if strings.EqualFold(k, key) {
			if arr, ok := v.([]interface{}); ok {
				result := make([]string, 0, len(arr))
				for _, item := range arr {
					if s, ok := item.(string); ok {
						result = append(result, s)
					}
				}
				return result
			}
		}
	}
	return nil
}

func getObject(obj map[string]interface{}, key string) map[string]interface{} {
	for k, v := range obj {
		if strings.EqualFold(k, key) {
			if m, ok := v.(map[string]interface{}); ok {
				return m
			}
		}
	}
	return nil
}

func parseCertEntry(certData map[string]interface{}, resolverName string) *AcmeEntry {
	certB64 := getString(certData, "certificate")
	keyB64 := getString(certData, "key")
	if certB64 == "" || keyB64 == "" {
		// SPEC §6: entries without certificate or key are ignored (log at debug level).
		slog.Debug("acme entry ignored, missing cert or key",
			"component", "acme",
			"resolver", resolverName,
		)
		return nil
	}

	fullchainBytes, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return nil
	}
	keyBytes, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil
	}

	domainObj := getObject(certData, "domain")
	mainDomain := ""
	var sans []string
	if domainObj != nil {
		mainDomain = getString(domainObj, "main")
		sans = getStringSlice(domainObj, "sans")
	}
	if mainDomain == "" && len(sans) == 0 {
		return nil
	}

	allSANs := []string{}
	if mainDomain != "" {
		allSANs = append(allSANs, mainDomain)
	}
	allSANs = append(allSANs, sans...)

	var uniqueSANs []string
	seen := map[string]bool{}
	for _, s := range allSANs {
		if !seen[s] {
			seen[s] = true
			uniqueSANs = append(uniqueSANs, s)
		}
	}

	return &AcmeEntry{
		FQDN:         "",
		SANs:         uniqueSANs,
		FullchainPEM: strings.TrimSpace(string(fullchainBytes)),
		PrivkeyPEM:   strings.TrimSpace(string(keyBytes)),
		Resolver:     resolverName,
	}
}

func uniqueFQDNs(entry *AcmeEntry) map[string]bool {
	fqdns := make(map[string]bool)
	for _, s := range entry.SANs {
		fqdns[certmodel.SanitizeFQDN(s)] = true
	}
	return fqdns
}
