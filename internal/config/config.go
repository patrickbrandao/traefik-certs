package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	SaveDir          string
	AcmeInterval     time.Duration
	AcmeJSONPath     string
	RedisURL         string
	RedisPrefix      string
	HookDir          string
	HookTimeout      time.Duration
	WebhookURLs      []string
	WebhookBearer    string
	WebhookTimeout   time.Duration
	WebhookRetries   int
	WebhookRedactKey bool
	LogLevel         string
	NodeID           string
}

func Load() (*Config, error) {
	c := &Config{}

	c.SaveDir = envOrDefault("TCERTS_SAVEDIR", "/certs")

	intervalMsStr := envOrDefault("TCERTS_ACME_INTERVAL", "3000")
	intervalMs, err := strconv.Atoi(intervalMsStr)
	if err != nil || intervalMs < 1 {
		return nil, fmt.Errorf("TCERTS_ACME_INTERVAL must be a positive integer, got %q", intervalMsStr)
	}
	c.AcmeInterval = time.Duration(intervalMs) * time.Millisecond

	c.AcmeJSONPath = envOrDefault("TCERTS_ACME_JSON", "/etc/letsencrypt/acme.json")

	c.RedisURL = os.Getenv("TCERTS_REDIS_URL")
	if c.RedisURL != "" {
		u, err := url.Parse(c.RedisURL)
		if err != nil || (u.Scheme != "redis" && u.Scheme != "rediss") || u.Host == "" {
			return nil, fmt.Errorf("TCERTS_REDIS_URL inválida: %q", c.RedisURL)
		}
	}

	c.RedisPrefix = envOrDefault("TCERTS_REDIS_PREFIX", "tcerts")

	c.HookDir = os.Getenv("TCERTS_HOOK_DIR")

	hookTimeoutStr := envOrDefault("TCERTS_HOOK_TIMEOUT", "30s")
	hookTimeout, err := time.ParseDuration(hookTimeoutStr)
	if err != nil {
		return nil, fmt.Errorf("TCERTS_HOOK_TIMEOUT is not valid: %q: %w", hookTimeoutStr, err)
	}
	c.HookTimeout = hookTimeout

	webhookURLs, err := parseWebhookURLs(os.Getenv("TCERTS_WEBHOOK_URL"))
	if err != nil {
		return nil, err
	}
	c.WebhookURLs = webhookURLs
	c.WebhookBearer = os.Getenv("TCERTS_WEBHOOK_BEARER")

	webhookTimeoutStr := envOrDefault("TCERTS_WEBHOOK_TIMEOUT", "10s")
	webhookTimeout, err := time.ParseDuration(webhookTimeoutStr)
	if err != nil {
		return nil, fmt.Errorf("TCERTS_WEBHOOK_TIMEOUT is not valid: %q: %w", webhookTimeoutStr, err)
	}
	c.WebhookTimeout = webhookTimeout

	retriesStr := envOrDefault("TCERTS_WEBHOOK_RETRIES", "3")
	retries, err := strconv.Atoi(retriesStr)
	if err != nil || retries < 0 {
		return nil, fmt.Errorf("TCERTS_WEBHOOK_RETRIES must be a non-negative integer, got %q", retriesStr)
	}
	c.WebhookRetries = retries

	c.WebhookRedactKey = os.Getenv("TCERTS_WEBHOOK_REDACT_KEY") == "true"

	c.LogLevel = envOrDefault("TCERTS_LOG_LEVEL", "info")
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return nil, fmt.Errorf("TCERTS_LOG_LEVEL must be one of debug, info, warn, error, got %q", c.LogLevel)
	}

	nodeID := os.Getenv("TCERTS_NODE_ID")
	if nodeID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			nodeID = "unknown"
		} else {
			nodeID = hostname
		}
	}
	c.NodeID = nodeID

	return c, nil
}

func envOrDefault(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

// parseWebhookURLs converte o valor bruto de TCERTS_WEBHOOK_URL em uma lista
// de URLs válidas. Entradas vazias (vírgula sobrando, espaços, trailing comma)
// são descartadas silenciosamente. Cada URL deve ter scheme http ou https e
// host não-vazio; caso contrário retorna erro fatal claro no boot (SPEC §3.1).
func parseWebhookURLs(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	var urls []string
	for _, p := range parts {
		u := strings.TrimSpace(p)
		if u == "" {
			continue
		}
		parsed, err := url.Parse(u)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return nil, fmt.Errorf("TCERTS_WEBHOOK_URL entrada inválida: %q (scheme deve ser http/https e host não-vazio)", u)
		}
		urls = append(urls, u)
	}
	return urls, nil
}
