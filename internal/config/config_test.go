package config_test

import (
	"os"
	"testing"

	"github.com/patrickbrandao/traefik-certs/internal/config"
)

// setEnv temporarily sets environment variables for the duration of a test.
func setEnv(t *testing.T, pairs ...string) {
	t.Helper()
	if len(pairs)%2 != 0 {
		t.Fatal("setEnv requires an even number of arguments")
	}
	for i := 0; i < len(pairs); i += 2 {
		key, val := pairs[i], pairs[i+1]
		old, had := os.LookupEnv(key)
		if val == "" {
			os.Unsetenv(key)
		} else {
			os.Setenv(key, val)
		}
		t.Cleanup(func() {
			if had {
				os.Setenv(key, old)
			} else {
				os.Unsetenv(key)
			}
		})
	}
}

func TestLoad_Defaults(t *testing.T) {
	// Clear variables that might be set in CI
	setEnv(t,
		"TCERTS_REDIS_URL", "",
		"TCERTS_LOG_LEVEL", "",
		"TCERTS_ACME_INTERVAL", "",
	)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.SaveDir != "/certs" {
		t.Errorf("SaveDir = %q, want /certs", cfg.SaveDir)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want info", cfg.LogLevel)
	}
}

func TestLoad_InvalidAcmeInterval(t *testing.T) {
	setEnv(t, "TCERTS_ACME_INTERVAL", "notanumber")
	_, err := config.Load()
	if err == nil {
		t.Error("expected error for invalid TCERTS_ACME_INTERVAL")
	}
}

func TestLoad_ZeroAcmeInterval(t *testing.T) {
	setEnv(t, "TCERTS_ACME_INTERVAL", "0")
	_, err := config.Load()
	if err == nil {
		t.Error("expected error for zero TCERTS_ACME_INTERVAL")
	}
}

func TestLoad_InvalidLogLevel(t *testing.T) {
	setEnv(t, "TCERTS_LOG_LEVEL", "verbose")
	_, err := config.Load()
	if err == nil {
		t.Error("expected error for invalid TCERTS_LOG_LEVEL")
	}
}

func TestLoad_ValidLogLevels(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		setEnv(t, "TCERTS_LOG_LEVEL", level)
		cfg, err := config.Load()
		if err != nil {
			t.Errorf("LogLevel %q: unexpected error: %v", level, err)
			continue
		}
		if cfg.LogLevel != level {
			t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, level)
		}
	}
}

// ---------------------------------------------------------------------------
// TCERTS_REDIS_URL validation (item 3.1)
// ---------------------------------------------------------------------------

func TestLoad_RedisURL_Valid(t *testing.T) {
	cases := []string{
		"redis://localhost:6379",
		"redis://user:pass@redis.example.com:6379/0",
		"rediss://redis.example.com:6380",
	}
	for _, u := range cases {
		setEnv(t, "TCERTS_REDIS_URL", u)
		_, err := config.Load()
		if err != nil {
			t.Errorf("RedisURL %q: unexpected error: %v", u, err)
		}
	}
}

func TestLoad_RedisURL_Invalid(t *testing.T) {
	cases := []string{
		"not-a-url",
		"http://example.com",
		"redis://",       // missing host
		"ftp://host:123",
	}
	for _, u := range cases {
		setEnv(t, "TCERTS_REDIS_URL", u)
		_, err := config.Load()
		if err == nil {
			t.Errorf("RedisURL %q: expected error but got none", u)
		}
	}
}

func TestLoad_InvalidHookTimeout(t *testing.T) {
	setEnv(t, "TCERTS_HOOK_TIMEOUT", "notaduration")
	_, err := config.Load()
	if err == nil {
		t.Error("expected error for invalid TCERTS_HOOK_TIMEOUT")
	}
}

func TestLoad_InvalidWebhookRetries(t *testing.T) {
	setEnv(t, "TCERTS_WEBHOOK_RETRIES", "-1")
	_, err := config.Load()
	if err == nil {
		t.Error("expected error for negative TCERTS_WEBHOOK_RETRIES")
	}
}

// ---------------------------------------------------------------------------
// TCERTS_WEBHOOK_URL — lista separada por vírgula (Task 002)
// ---------------------------------------------------------------------------

func TestLoad_WebhookURL_MultipleValid(t *testing.T) {
	setEnv(t, "TCERTS_WEBHOOK_URL", "https://a.example/hook, https://b.example/hook")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"https://a.example/hook", "https://b.example/hook"}
	if len(cfg.WebhookURLs) != len(want) {
		t.Fatalf("WebhookURLs len = %d, want %d", len(cfg.WebhookURLs), len(want))
	}
	for i := range want {
		if cfg.WebhookURLs[i] != want[i] {
			t.Errorf("WebhookURLs[%d] = %q, want %q", i, cfg.WebhookURLs[i], want[i])
		}
	}
}

func TestLoad_WebhookURL_EmptyEntriesDiscarded(t *testing.T) {
	cases := []string{
		"https://a.example/hook,, ,https://b.example/hook",
		"https://a.example/hook,",
		",https://a.example/hook",
	}
	for _, raw := range cases {
		setEnv(t, "TCERTS_WEBHOOK_URL", raw)
		cfg, err := config.Load()
		if err != nil {
			t.Errorf("raw %q: unexpected error: %v", raw, err)
			continue
		}
		// Cada caso contém exatamente 1 ou 2 URLs válidas; nenhuma entrada vazia deve sobreviver.
		for _, u := range cfg.WebhookURLs {
			if u == "" {
				t.Errorf("raw %q: encontrou entrada vazia após parse", raw)
			}
		}
	}
}

func TestLoad_WebhookURL_InvalidScheme(t *testing.T) {
	setEnv(t, "TCERTS_WEBHOOK_URL", "ftp://example.com/hook")
	_, err := config.Load()
	if err == nil {
		t.Error("expected error for invalid scheme in TCERTS_WEBHOOK_URL")
	}
}

func TestLoad_WebhookURL_EmptyHost(t *testing.T) {
	setEnv(t, "TCERTS_WEBHOOK_URL", "https:///hook")
	_, err := config.Load()
	if err == nil {
		t.Error("expected error for empty host in TCERTS_WEBHOOK_URL")
	}
}

func TestLoad_WebhookURL_HttpAccepted(t *testing.T) {
	setEnv(t, "TCERTS_WEBHOOK_URL", "http://localhost:8080/hook")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.WebhookURLs) != 1 || cfg.WebhookURLs[0] != "http://localhost:8080/hook" {
		t.Errorf("WebhookURLs = %v, want [http://localhost:8080/hook]", cfg.WebhookURLs)
	}
}

func TestLoad_WebhookURL_EmptyMeansIgnored(t *testing.T) {
	setEnv(t, "TCERTS_WEBHOOK_URL", "")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.WebhookURLs) != 0 {
		t.Errorf("WebhookURLs = %v, want empty slice", cfg.WebhookURLs)
	}
}

func TestLoad_AcmeJSONPath_Direct(t *testing.T) {
	setEnv(t,
		"TCERTS_ACME_JSON", "/etc/letsencrypt/acme.json",
	)
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "/etc/letsencrypt/acme.json"
	if cfg.AcmeJSONPath != want {
		t.Errorf("AcmeJSONPath = %q, want %q", cfg.AcmeJSONPath, want)
	}
}

func TestLoad_AcmeJSONPath_Default(t *testing.T) {
	setEnv(t, "TCERTS_ACME_JSON", "")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "/etc/letsencrypt/acme.json"
	if cfg.AcmeJSONPath != want {
		t.Errorf("AcmeJSONPath = %q, want %q", cfg.AcmeJSONPath, want)
	}
}
