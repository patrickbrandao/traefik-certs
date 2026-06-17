# AGENTS.md / CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) and any other AI coding agent when working with code in this repository. `CLAUDE.md` is a symlink to `AGENTS.md` — they are one file, so every agent shares the same view.

## Project

`tcerts` syncs Let's Encrypt certificates that Traefik stores in `acme.json` across multiple nodes. It extracts each certificate to disk (one directory per FQDN) and distributes them between nodes over Redis. Go 1.23+, the only non-stdlib dependency is `github.com/redis/go-redis/v9`.

The authoritative spec lives in `docs/` (see the index below). Spec, code comments, and the `tasks/` change reports are written in **Portuguese**; keep new comments consistent with the surrounding file. When changing behavior, update both the relevant `docs/NN-*.md` section and the code — the docs are treated as the contract (`docs/17-criterios-aceitacao.md` is the acceptance checklist).

## Specification index (`docs/`)

| Capítulo | Arquivo |
|----------|---------|
| 1. Objetivo | [01-objetivo.md](docs/01-objetivo.md) |
| 2. Componentes / binários | [02-componentes-binarios.md](docs/02-componentes-binarios.md) |
| 3. Variáveis de ambiente | [03-variaveis-de-ambiente.md](docs/03-variaveis-de-ambiente.md) |
| 4. Contrato em disco | [04-contrato-em-disco.md](docs/04-contrato-em-disco.md) |
| 5. Schema do `cert.json` | [05-schema-cert-json.md](docs/05-schema-cert-json.md) |
| 6. Leitura e decomposição do `acme.json` | [06-leitura-acme-json.md](docs/06-leitura-acme-json.md) |
| 7. Tabela de origens | [07-tabela-origens.md](docs/07-tabela-origens.md) |
| 8. `cert-watcher` — fluxo de execução | [08-cert-watcher-fluxo.md](docs/08-cert-watcher-fluxo.md) |
| 9. Hooks (side effects) | [09-hooks.md](docs/09-hooks.md) |
| 10. `cert-get` — utilitário | [10-cert-get.md](docs/10-cert-get.md) |
| 11. Segurança de gravação e concorrência | [11-seguranca-concorrencia.md](docs/11-seguranca-concorrencia.md) |
| 12. Logging / observabilidade | [12-logging.md](docs/12-logging.md) |
| 13. Casos de borda e resiliência | [13-casos-de-borda.md](docs/13-casos-de-borda.md) |
| 14. Build e empacotamento | [14-build.md](docs/14-build.md) |
| 15. Premissas de segurança | [15-premissas-seguranca.md](docs/15-premissas-seguranca.md) |
| 16. Testes | [16-testes.md](docs/16-testes.md) |
| 17. Critérios de aceitação | [17-criterios-aceitacao.md](docs/17-criterios-aceitacao.md) |

## Commands

The Go toolchain may not be installed locally — builds run inside Docker. With Go 1.23+ available:

```sh
go build ./cmd/cert-watcher ./cmd/cert-get   # build both binaries
go test ./...                                 # run all tests
go test -race ./...                           # REQUIRED to pass — race detector is the arbiter for concurrency (docs/16)
go test ./internal/config/ -run TestLoad_WebhookURL_MultipleValid   # single test
```

Docker (the supported build path):

```sh
./build.sh     # builds traefik-certs:alpine, :latest, and :distroless from Dockerfile.alpine / Dockerfile.distroless
./run.sh       # example deploy of cert-watcher as a daemon (shows the full env-var set in context)
./hub.sh       # tag + push to Docker Hub (tmsoftbrasil/traefik-certs)
./clean.sh / ./destroy.sh   # remove containers/images
```

Both Dockerfiles build static binaries (`CGO_ENABLED=0 -ldflags="-s -w" -trimpath`). `CMD` is `cert-watcher`; override it to run `cert-get`.

## Two binaries

- **`cert-watcher`** (`cmd/cert-watcher`) — long-running daemon. Polls `acme.json`, writes certs to disk, and is the only writer to Redis.
- **`cert-get`** (`cmd/cert-get <FQDN> <DEST_DIR>`) — one-shot CLI embedded in consumer containers. Reads from local disk + Redis (read-only), picks the best matching cert, writes the PEM files flat into `DEST_DIR`.

Both load config the same way via `internal/config`.

## Architecture

Data flows in one direction at the source — `acme.json` → disk → Redis → other nodes' disks — but every write is gated by a **recency comparison**, never a blind overwrite. All packages are in `internal/`:

- **`config`** — loads/validates all `TCERTS_*` env vars at boot. Invalid values are **fatal** (clear error, no `os.Exit` deep in the stack — `Load()` returns an error). Validation does not trust `url.Parse` alone; scheme and host are checked explicitly (see `parseWebhookURLs` and the Redis URL check). Full env reference: `docs/03-variaveis-de-ambiente.md`.
- **`acme`** — parses `acme.json` resolver-agnostically. Reads keys case-insensitively (Traefik v2/v3 differ) and **fans out one `AcmeEntry` per sanitized FQDN** across `domain.main` + `domain.sans`. Entries missing cert/key are skipped silently (returns 0 entries, not an error).
- **`certmodel`** — the `CertJSON` struct (the on-disk + on-Redis representation) and PEM/x509 logic. **SANs are always read authoritatively from the x509 cert, never from the ACME JSON argument** (the `sans` arg only decides which directories to create). `DecomposePEM` splits a fullchain into leaf (`cert.pem`) + intermediates (`chain.pem`). Matching helpers: `MatchesExact`, `CoversWildcard`, `IsValidNow` (validity bounds are inclusive). `SanitizeFQDN` strips the `*.` wildcard prefix.
- **`certstore`** — atomic disk I/O under `$TCERTS_SAVEDIR/<sanitized-fqdn>/`. **All writes go through `WriteAtomic` (temp file + `chmod` + rename)**. Per-FQDN mutexes via `Lock(fqdn)` serialize concurrent writers. Each FQDN dir holds 6 files with specific perms (`privkey.pem`/`cert.json` are `0600`, rest `0644`) — see `docs/04-contrato-em-disco.md`.
- **`redisbus`** — wraps the Redis client. Keys are `<prefix>:cert:<fqdn>`, the pub/sub channel is `<prefix>:events`. The subscriber runs in a tracked goroutine that auto-reconnects; `Close()` cancels it via an internally-stored cancel func (independent of the caller's ctx) and waits.
- **`reconcile`** — the orchestrator. `SyncCerts` (ACME→disk→Redis) and `SyncRedis` (bidirectional disk↔Redis pull/push) plus `HandleRedisEvent` (subscriber callback). Holds the `SourceTable` and `hookWg`.
- **`hooks`** — `RunHook1` runs executable scripts in `TCERTS_HOOK_DIR` (`dir fqdn` args, sorted, per-script timeout); `RunHook2` POSTs `cert.json` to each URL in `TCERTS_WEBHOOK_URL` (comma-separated, one goroutine per URL).

### Recency comparison (the core invariant)

A cert is only written when it's strictly newer. The rule is consistent across `SyncCerts`, `SyncRedis`, and `HandleRedisEvent`: write if local is absent, OR `incoming.NotAfterUnix > local.NotAfterUnix`. `SyncCerts` adds a tiebreaker — equal `NotAfterUnix` but different `Hash.Cert` also writes. When touching any write path, preserve this comparison; a blind overwrite can propagate an older cert across the cluster.

### SourceTable

`reconcile.SourceTable` (a mutex-guarded `map[fqdn]source`, source ∈ `acme`/`redis`/`file`) records where each on-disk cert came from. Its purpose is loop prevention: in `SyncRedis`'s PUSH phase, certs whose source is `redis` are **not** pushed back to Redis. It's rebuilt from disk (`cert.json`'s `source` field) on startup.

### Redis is optional + resilient

Empty `TCERTS_REDIS_URL` ⇒ **local-only mode** (no error). If Redis is configured but unreachable at boot, the watcher starts anyway and `startRedisWatchdog` (in `cmd/cert-watcher/main.go`) retries with exponential backoff; on reconnect it registers the bus, starts the subscriber, and runs a full `SyncRedis` to catch up. The active bus is swapped behind `busMu` (`getBus`/`SetBus`).

### Concurrency & graceful shutdown

`-race` must stay clean (`docs/16`). Shared state is guarded: `SourceTable.mu`, `certstore`'s per-FQDN locks + `mu`, `Reconcile.busMu`. On SIGINT/SIGTERM, `main` cancels the root ctx then calls `rec.Wait()` (`hookWg.Wait()`) so in-flight hooks finish, then `CloseBus()`. **Hook goroutines must be tracked in `hookWg`** — `RunHook2` calls `wg.Add(1)` per URL itself, so the dispatch site passes `&r.hookWg`. Never `time.Sleep` for backoff/polling; use `select` on `ctx.Done()` + `time.After` (see `WaitAndContinue`, `postWebhook`, the watchdog) so shutdown is immediate.

### cert-get selection logic

`findBestCert` scans local disk then Redis, considering only currently-valid certs, and prefers: **exact SAN match over wildcard**, then **latest `NotAfterUnix`**. Directory names are not used for matching — only the `sans` in each `cert.json`.
