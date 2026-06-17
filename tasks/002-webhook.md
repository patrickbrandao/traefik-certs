# Task 002 — `TCERTS_WEBHOOK_URL` com suporte a múltiplas URLs (vírgula)

**Data:** 2026-06-17
**Objetivo:** Permitir que `TCERTS_WEBHOOK_URL` receba uma lista de URLs separadas por vírgula, disparando um POST para cada URL em goroutine própria rastreada pelo `hookWg`, com bearer único compartilhado, entradas vazias descartadas silenciosamente e schemes `http`/`https` aceitos.

**Spec de referência (já atualizada):** `docs/03-variaveis-de-ambiente.md`, `docs/09-hooks.md` §9.2, `docs/11-seguranca-concorrencia.md` §11.5, `docs/12-logging.md` §12.2, `docs/13-casos-de-borda.md`, `docs/15-premissas-seguranca.md`, `docs/16-testes.md`, `docs/17-criterios-aceitacao.md`.

---

## Resumo

| Arquivo | Tipo de alteração |
|---|---|
| `internal/config/config.go` | Trocar campo `WebhookURL string` por `WebhookURLs []string`; adicionar parsing/validação no boot (split por `,`, trim, descartar vazias, validar scheme `http`/`https` + host). |
| `internal/config/config_test.go` | Novos testes: lista múltipla válida, entradas vazias descartadas, scheme inválido, host vazio. |
| `internal/hooks/hooks.go` | `RunHook2` iterar sobre `cfg.WebhookURLs`, cada URL em goroutine própria rastreada por `*sync.WaitGroup` injetado; adicionar campo `webhook_url` em todos os logs; falha por URL não afeta demais. |
| `internal/reconcile/reconcile.go` | Passar `&r.hookWg` para `RunHook2` (cada URL faz `wg.Add(1)`). |
| `internal/reconcile/reconcile_test.go` | Novos testes de fan-out paralelo (2+ URLs recebem POST; 1 URL falha sem abortar as demais; logs contêm `webhook_url`). |
| `run.sh` | Apenas exemplo documentado — sem mudança obrigatória (a variável continua com valor único válido; o novo parsing aceita lista opcionalmente). |

---

## Decisões de design (confirmadas com o operador)

1. **Modo de entrega:** paralelo — **1 goroutine por URL**, rastreada pelo `hookWg` existente.
2. **Bearer:** único e compartilhado — `TCERTS_WEBHOOK_BEARER` aplicado a todas as URLs.
3. **Entradas vazias (vírgula sobrando, trailing comma, espaços):** descartadas silenciosamente após `trim`.
4. **Schemes aceitos:** `http` e `https` (http é útil para testes locais/loopback; spec §15 adverte sobre risco de vazar chave privada em claro).

---

## Detalhamento por arquivo

### 1. `internal/config/config.go`

#### 1.1 Struct `Config` (linha 19)

**Antes:**
```go
WebhookURL       string
```

**Depois:**
```go
WebhookURLs      []string
```

> Racional: a lista é parseada e validada uma única vez no boot. O resto do código consome um slice já limpo, sem repetir a lógica de split.

#### 1.2 Função `Load()` — bloco do webhook (linhas 61–62)

**Antes:**
```go
c.WebhookURL = os.Getenv("TCERTS_WEBHOOK_URL")
c.WebhookBearer = os.Getenv("TCERTS_WEBHOOK_BEARER")
```

**Depois:**
```go
c.WebhookURLs = parseWebhookURLs(os.Getenv("TCERTS_WEBHOOK_URL"))
c.WebhookBearer = os.Getenv("TCERTS_WEBHOOK_BEARER")
```

#### 1.3 Nova função auxiliar `parseWebhookURLs` (adicionar ao final do arquivo)

```go
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
```

> Nota: a validação segue o mesmo padrão já usado para `TCERTS_REDIS_URL` (linhas 42–48): não confiar apenas na ausência de erro de `url.Parse`, validar explicitamente scheme e host.

#### 1.4 Ajuste do chamador (item 1.2)

Como `parseWebhookURLs` retorna `error`, o bloco de chamada deve propagar:

```go
urls, err := parseWebhookURLs(os.Getenv("TCERTS_WEBHOOK_URL"))
if err != nil {
    return nil, err
}
c.WebhookURLs = urls
c.WebhookBearer = os.Getenv("TCERTS_WEBHOOK_BEARER")
```

#### 1.5 Novo import

Adicionar `"strings"` aos imports do pacote (`net/url` e `fmt` já estão presentes).

---

### 2. `internal/config/config_test.go`

Adicionar os seguintes testes (após `TestLoad_InvalidWebhookRetries`, linha ~141):

```go
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
```

> Atenção: o `TestLoad_Defaults` (linha 34) não precisa mudar, pois `TCERTS_WEBHOOK_URL` não é setado ali — `WebhookURLs` será `nil`, o que é equivalente a "hook 2 ignorado".

---

### 3. `internal/hooks/hooks.go`

#### 3.1 Assinatura de `RunHook2` (linha 102)

**Antes:**
```go
func RunHook2(ctx context.Context, cfg *config.Config, cj *certmodel.CertJSON) {
```

**Depois:**
```go
func RunHook2(ctx context.Context, cfg *config.Config, wg *sync.WaitGroup, cj *certmodel.CertJSON) {
```

> Racional: como `RunHook2` é chamado dentro de uma goroutine já rastreada (em `reconcile.SyncCerts`), e cada URL precisa de sua própria entrada no `WaitGroup`, o `wg` deve ser repassado. Importante: `RunHook2` **não** faz `wg.Add(1)` para si próprio (isso já acontece no caller); ela faz `wg.Add(1)` **por URL** antes de disparar cada goroutine interna.

#### 3.2 Corpo de `RunHook2` (linhas 102–184) — reescrita completa

```go
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
```

#### 3.3 Novo import

Adicionar `"sync"` aos imports do pacote `hooks`.

#### 3.4 Pontos de atenção

- **Não usar `go func() { ... todas URLs ... }()` sem rastreamento individual** — cada URL chama `wg.Add(1)` antes de `go`. Caso contrário, o shutdown não aguardaria todas as URLs (SPEC §11.5).
- **Clone do `target` no closure:** usar `target` como parâmetro da goroutine (não capturar a variável de loop diretamente). No Go 1.23+ o loop var é escopada por iteração, mas passar como parâmetro é mais defensivo e explícito.
- **Backoff com `select`+`ctx.Done()`:** mantido exatamente como antes — nunca `time.Sleep`, para não atrasar o shutdown (SPEC §9.2).
- **Falha por URL é independente:** `postWebhook` retorna silenciosamente após esgotar retries (log em `error`); não há canal de erro compartilhado entre URLs.

---

### 4. `internal/reconcile/reconcile.go`

#### 4.1 Chamada de `RunHook2` em `SyncCerts` (linhas 227–235)

**Antes:**
```go
for fqdn, cj := range updates {
    r.hookWg.Add(1)
    go func(f string, c *certmodel.CertJSON) {
        defer r.hookWg.Done()
        dir := r.store.FQDNPath(f)
        hooks.RunHook1(ctx, r.cfg, f, dir)
        hooks.RunHook2(ctx, r.cfg, c)
    }(fqdn, cj)
}
```

**Depois:**
```go
for fqdn, cj := range updates {
    r.hookWg.Add(1)
    go func(f string, c *certmodel.CertJSON) {
        defer r.hookWg.Done()
        dir := r.store.FQDNPath(f)
        hooks.RunHook1(ctx, r.cfg, f, dir)
        hooks.RunHook2(ctx, r.cfg, &r.hookWg, c)
    }(fqdn, cj)
}
```

> Mudança mínima: apenas o novo argumento `&r.hookWg` foi adicionado. O `Add(1)`/`Done()` da goroutine externa (uma por FQDN) continua existindo; `RunHook2` fará `Add(1)` adicional por URL internamente. O `Done()` da goroutine externa dispara quando `RunHook1` e `RunHook2` retornam — e `RunHook2` só retorna após despachar todas as goroutines internas (cada uma com seu próprio `Done`). Logo, o shutdown aguarda todas as URLs.

#### 4.2 Verificação de consistência

- O `r.hookWg.Wait()` em `Reconcile.Wait()` (linha 124) **não precisa mudar** — ele aguarda todas as entradas do WaitGroup, incluindo as adicionadas por `RunHook2`.
- Não há outras chamadas a `RunHook2` no código (confirmado via busca).

---

### 5. `internal/reconcile/reconcile_test.go`

Adicionar testes de fan-out paralelo. Como `RunHook2` depende de `config.Config` e `certmodel.CertJSON`, e os testes do pacote `reconcile_test` são black-box (import externo), os testes de fan-out podem ser colocados aqui usando um servidor HTTP de teste:

```go
package reconcile_test

import (
    "context"
    "net/http"
    "net/http/httptest"
    "sync"
    "sync/atomic"
    "testing"
    "time"

    "github.com/patrickbrandao/traefik-certs/internal/certmodel"
    "github.com/patrickbrandao/traefik-certs/internal/config"
    "github.com/patrickbrandao/traefik-certs/internal/hooks"
)

// TestRunHook2_FanOutParallel verifica que múltiplas URLs recebem o POST em
// paralelo e que cada uma é contatada independentemente (SPEC §9.2).
func TestRunHook2_FanOutParallel(t *testing.T) {
    var gotA, gotB int32
    a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        atomic.AddInt32(&gotA, 1)
        w.WriteHeader(http.StatusOK)
    }))
    b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        atomic.AddInt32(&gotB, 1)
        w.WriteHeader(http.StatusOK)
    }))
    defer a.Close()
    defer b.Close()

    cfg := &config.Config{
        WebhookURLs:    []string{a.URL, b.URL},
        WebhookTimeout: 2 * time.Second,
        WebhookRetries: 0,
    }
    cj := &certmodel.CertJSON{FQDN: "example.com"}

    var wg sync.WaitGroup
    hooks.RunHook2(context.Background(), cfg, &wg, cj)
    wg.Wait()

    if atomic.LoadInt32(&gotA) != 1 {
        t.Errorf("URL A recebeu %d POSTs, want 1", gotA)
    }
    if atomic.LoadInt32(&gotB) != 1 {
        t.Errorf("URL B recebeu %d POSTs, want 1", gotB)
    }
}

// TestRunHook2_PartialFailure verifica que a falha de uma URL (após retries)
// não impede as demais de receberem o POST (SPEC §9.2, §13).
func TestRunHook2_PartialFailure(t *testing.T) {
    var okCount int32
    ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        atomic.AddInt32(&okCount, 1)
        w.WriteHeader(http.StatusOK)
    }))
    fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusInternalServerError)
    }))
    defer ok.Close()
    defer fail.Close()

    cfg := &config.Config{
        WebhookURLs:    []string{ok.URL, fail.URL},
        WebhookTimeout: 1 * time.Second,
        WebhookRetries: 1, // backoff pequeno: 1s entre tentativa 0 e 1
    }
    cj := &certmodel.CertJSON{FQDN: "example.com"}

    var wg sync.WaitGroup
    hooks.RunHook2(context.Background(), cfg, &wg, cj)
    wg.Wait()

    if atomic.LoadInt32(&okCount) != 1 {
        t.Errorf("URL OK recebeu %d POSTs, want 1 (falha da outra URL não deve afetá-la)", okCount)
    }
}

// TestRunHook2_EmptyListNoop verifica que lista vazia não dispara nada.
func TestRunHook2_EmptyListNoop(t *testing.T) {
    cfg := &config.Config{
        WebhookURLs:    nil,
        WebhookTimeout: 1 * time.Second,
        WebhookRetries: 0,
    }
    cj := &certmodel.CertJSON{FQDN: "example.com"}

    var wg sync.WaitGroup
    hooks.RunHook2(context.Background(), cfg, &wg, cj)
    wg.Wait() // não deve bloquear nem disparar goroutines
}
```

> Nota: estes testes precisam do import de `hooks` e `config` no pacote de teste `reconcile_test`. Se houver preferência por isolá-los em `internal/hooks/hooks_test.go` (pacote `hooks_test`), é igualmente aceitável — escolher conforme convenção do projeto. Recomenda-se `internal/hooks/hooks_test.go` para manter coesão com o componente testado.

---

### 6. `run.sh`

**Sem alteração obrigatória.** A linha 10 já usa um valor único:
```sh
WEBHOOK_URL="https://ws.$FQDN/webhook/cert-watcher";
```

Para documentar o novo recurso, pode-se adicionar exemplo comentado:
```sh
# Para múltiplos endpoints, separe por vírgula:
# WEBHOOK_URL="https://ws.$FQDN/webhook/cert-watcher,https://backup.$FQDN/webhook/cert-watcher";
```

Esta é uma melhoria opcional de documentação operacional, não um requisito de código.

---

## Verificação

Após aplicar todas as mudanças, executar:

```sh
go build ./cmd/cert-watcher
go build ./cmd/cert-get
go test ./...
go test -race ./...
```

**Critérios de aceitação:**
- `go build` dos dois binários sem erros.
- `go test ./...` passa (incluindo os novos testes em `config` e `hooks`/`reconcile`).
- `go test -race ./...` passa sem races detectados — em particular, o fan-out paralelo de `RunHook2` não deve disparar races no `hookWg`.
- Nenhum erro fatal no boot quando `TCERTS_WEBHOOK_URL` está vazio ou contém lista válida.
- Erro fatal claro no boot quando `TCERTS_WEBHOOK_URL` contém URL com scheme inválido ou host vazio.

---

## Checklist de aceitação (SPEC §17 — item Hook 2)

- [ ] `TCERTS_WEBHOOK_URL` aceita lista separada por vírgula.
- [ ] Entradas vazias (vírgula sobrando, trailing comma, espaços) descartadas silenciosamente.
- [ ] Scheme `http`/`https` + host não-vazio validados no boot; erro fatal claro caso contrário.
- [ ] POST do `cert.json` para cada URL em goroutine própria rastreada pelo `hookWg` (`wg.Add(1)` por URL).
- [ ] Bearer único compartilhado entre todas as URLs.
- [ ] retries/timeout/backoff com `select`+`ctx.Done()` aplicados a todas as URLs.
- [ ] Redação opcional da chave (`TCERTS_WEBHOOK_REDACT_KEY=true`) aplicada a todas as URLs.
- [ ] Falha por URL logada em `error` com campo `webhook_url`, sem afetar as demais.
- [ ] `RunHook2` recebe `ctx` do processo.
- [ ] Shutdown gracioso aguarda todas as goroutines (todas as URLs) via `hookWg.Wait()`.

---

## Notas de implementação

- **Compatibilidade retroativa:** um valor único (sem vírgula) continua funcionando — `strings.Split` com um único elemento retorna slice de tamanho 1.
- **Ordem de disparo:** como as URLs são despachadas em paralelo, a ordem de chegada não é garantida. Se no futuro houver requisito de ordem, trocar por disparo sequencial (decisão atual do operador: paralelo).
- **Logs:** todos os eventos do Hook 2 (success, request error, response error, exhausted retries) incluem `webhook_url`. O campo `attempt` continua presente para correlação com retries.
- **Sem mudança no schema `cert.json`:** o payload POSTado por URL é idêntico ao anterior; apenas o fan-out muda.
- **Sem mudança em `cert-get`:** o binário `cert-get` não toca em webhooks (confirmado via leitura de `cmd/cert-get/`).
