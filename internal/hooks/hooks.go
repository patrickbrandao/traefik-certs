package hooks

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/patrickbrandao/traefik-certs/internal/certmodel"
	"github.com/patrickbrandao/traefik-certs/internal/config"
)

// RunHook1 executes every executable script in cfg.HookDir, passing dir and fqdn as
// positional arguments. The provided ctx is the process context; each script also
// gets its own per-script timeout derived from it so that both individual timeouts
// and graceful shutdown cancellation are honoured (item 1.6).
func RunHook1(ctx context.Context, cfg *config.Config, fqdn, dir string) {
	if cfg.HookDir == "" {
		return
	}

	entries, err := os.ReadDir(cfg.HookDir)
	if err != nil {
		slog.Error("hook1 read dir",
			"component", "hook",
			"fqdn", fqdn,
			"dir", cfg.HookDir,
			"error", err.Error(),
		)
		return
	}

	var scripts []string
	for _, e := range entries {
		if e.Type()&os.ModeSymlink != 0 {
			// For symlinks, resolve the target and check ITS exec bit (item 3.6).
			info, err := os.Stat(filepath.Join(cfg.HookDir, e.Name()))
			if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
				continue
			}
			scripts = append(scripts, e.Name())
			continue
		}
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.Mode()&0111 != 0 {
			scripts = append(scripts, e.Name())
		}
	}
	sort.Strings(scripts)

	for _, script := range scripts {
		func() {
			// Derive per-script timeout from the process context so that shutdown
			// cancellation propagates (item 1.6).
			sctx, cancel := context.WithTimeout(ctx, cfg.HookTimeout)
			defer cancel()

			cmd := exec.CommandContext(sctx, filepath.Join(cfg.HookDir, script), dir, fqdn)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()
			if err != nil {
				slog.Error("hook1 script failed",
					"component", "hook",
					"fqdn", fqdn,
					"script", script,
					"stdout", stdout.String(),
					"stderr", stderr.String(),
					"error", err.Error(),
				)
			} else {
				slog.Info("hook1 script completed",
					"component", "hook",
					"fqdn", fqdn,
					"script", script,
					"stdout", stdout.String(),
				)
			}
		}()
	}
}

// RunHook2 faz POST do cert.json para cada URL da lista cfg.WebhookURLs, em
// paralelo (uma goroutine rastreada por URL). wg é o WaitGroup do Reconcile:
// cada URL faz wg.Add(1) individualmente, garantindo que o shutdown aguarde
// todas as URLs em andamento (SPEC §11.5). Bearer, timeout, retries e redação
// são aplicados de forma idêntica a todas as URLs. ctx é o contexto do
// processo; tanto o timeout por request quanto o backoff entre tentativas
// respeitam ctx.Done() para não atrasar o shutdown (SPEC §9.2).
func RunHook2(ctx context.Context, cfg *config.Config, wg *sync.WaitGroup, cj *certmodel.CertJSON) {
	if len(cfg.WebhookURLs) == 0 {
		return
	}

	payload := cj
	if cfg.WebhookRedactKey {
		clone := *cj
		clone.PEM.Privkey = ""
		payload = &clone
	}

	body, err := json.Marshal(payload)
	if err != nil {
		slog.Error("hook2 marshal",
			"component", "webhook",
			"fqdn", cj.FQDN,
			"error", err.Error(),
		)
		return
	}

	for _, target := range cfg.WebhookURLs {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			postWebhook(ctx, cfg, cj.FQDN, target, body)
		}(target)
	}
}

// postWebhook executa o POST para uma única URL com retries e backoff
// exponencial. Falha após todas as tentativas é logada em error com
// webhook_url e não afeta as demais URLs (SPEC §9.2, §13).
func postWebhook(ctx context.Context, cfg *config.Config, fqdn, target string, body []byte) {
	for attempt := 0; attempt <= cfg.WebhookRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			// Respect context cancellation during backoff sleep (SPEC §9.2).
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
		}

		reqCtx, cancel := context.WithTimeout(ctx, cfg.WebhookTimeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, target, bytes.NewReader(body))
		if err != nil {
			cancel()
			slog.Error("hook2 create request",
				"component", "webhook",
				"fqdn", fqdn,
				"webhook_url", target,
				"attempt", attempt,
				"error", err.Error(),
			)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		if cfg.WebhookBearer != "" {
			req.Header.Set("Authorization", "Bearer "+cfg.WebhookBearer)
		}

		resp, err := http.DefaultClient.Do(req)
		cancel()
		if err != nil {
			slog.Error("hook2 request",
				"component", "webhook",
				"fqdn", fqdn,
				"webhook_url", target,
				"attempt", attempt,
				"error", err.Error(),
			)
			continue
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			slog.Info("hook2 success",
				"component", "webhook",
				"fqdn", fqdn,
				"webhook_url", target,
				"status", resp.StatusCode,
				"attempt", attempt,
			)
			return
		}

		slog.Error("hook2 response",
			"component", "webhook",
			"fqdn", fqdn,
			"webhook_url", target,
			"status", resp.StatusCode,
			"body", string(respBody),
			"attempt", attempt,
		)
	}

	slog.Error("hook2 exhausted retries",
		"component", "webhook",
		"fqdn", fqdn,
		"webhook_url", target,
		"retries", cfg.WebhookRetries,
	)
}
