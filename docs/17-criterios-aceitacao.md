## 17. Critérios de aceitação (checklist)

- [ ] `cert-watcher` extrai cada certificado do `acme.json` para `$TCERTS_SAVEDIR/<fqdn>/` com os 6 arquivos
      corretos e `cert.json` no schema da §5.
- [ ] `fullchain.pem` = leaf+intermediários; `cert.pem` = leaf; `chain.pem` = intermediários; `cert.md5` = MD5 de `cert.pem`.
- [ ] `acme.json` é apenas lido, nunca escrito.
- [ ] Polling respeita `TCERTS_ACME_INTERVAL` (ms); caminho completo via `TCERTS_ACME_JSON`.
- [ ] Shutdown gracioso imediato: loop de polling usa `select`+`ctx.Done()`, não `time.Sleep`.
- [ ] Recência por `not_after`; desempate por `cert_md5`; só sobrescreve se mais novo (ou leaf diferente com mesmo `not_after`).
- [ ] Redis: chave `tcerts:cert:<fqdn>` + canal `tcerts:events`; payload = `cert.json`.
- [ ] FQDNs extraídos de chaves Redis por `strings.TrimPrefix`, não por offset numérico.
- [ ] Só publica certificados de origem ≠ `redis`; verifica `cert_md5` antes de publicar (sem reenvio duplicado).
- [ ] `redis → arquivo` nunca dispara hooks; `acme → arquivo` (novo/atualizado) sempre dispara.
- [ ] Hook 1: scripts executáveis sequenciais, args (`dir`, `fqdn`), timeout derivado do ctx do processo, falha não-fatal. Symlinks: exec bit verificado no alvo (`os.Stat`), não no symlink (`DirEntry.Info()`).
- [ ] Hook 2: `TCERTS_WEBHOOK_URL` aceita lista separada por vírgula (entradas vazias descartadas, scheme `http`/`https` + host não-vazio validados no boot); POST do `cert.json` para **cada URL em goroutine própria rastreada pelo `hookWg`** (`wg.Add(1)` por URL); Bearer único compartilhado; retries/timeout/backoff com `select`+`ctx.Done()` e redação opcional aplicados a todas; falha por URL logada em `error` com `webhook_url` sem afetar as demais; recebe `ctx` do processo.
- [ ] Goroutines de hook rastreadas por `sync.WaitGroup`; shutdown aguarda `hookWg.Wait()`.
- [ ] `sync_certs` (importa acme + dispara hooks de updates) chama `sync_redis` (pull sem hooks + push) ao final; ambos rodam no boot.
- [ ] Subscriber aprende em baixa latência (sem hooks). Subscriber com contexto interno desacoplável via `Close()`.
- [ ] Tabela de origens (`acme`/`file`/`redis`) montada do disco no boot, atualizada em runtime, protegida por `sync.RWMutex`.
- [ ] `cert-get <FQDN> <DIR>`: match exato → wildcard; mais recente válido (bounds inclusivos); grava achatado em `$2`; não cria diretórios; exit `1` + `stderr` em falha, resumo no `stdout` em sucesso.
- [ ] Modo local (sem `TCERTS_REDIS_URL`): só acme→disco, sem distribuição.
- [ ] Redis indisponível no boot: não fatal; modo local; goroutine watchdog com backoff exponencial e `select+ctx.Done()`; ao reconectar executa `sync_redis` completo.
- [ ] Escrita atômica, lock por FQDN, permissões corretas em todos os fluxos.
- [ ] `sans` em `CertJSON` lidos de `cert.DNSNames` (autoritativo); nunca de `domain.main`/`domain.sans` do JSON.
- [ ] `is_currently_valid` e `IsValidNow()`: ambos os extremos (`not_before`, `not_after`) inclusivos; implementados com `!now.Before(notBefore) && !now.After(notAfter)` (ou equivalente em Unix).
- [ ] `TCERTS_REDIS_URL`: validação explícita de scheme (`redis`/`rediss`) e host não-vazio; erro fatal claro.
- [ ] Logger JSON configurado antes de `config.Load()` em ambos os binários.
- [ ] Entradas do `acme.json` sem `certificate` ou `key`: ignoradas e logadas em `slog.Debug`.
- [ ] `go test ./...` passa. `go test -race ./...` passa sem races detectadas.
- [ ] Log estruturado JSON; shutdown gracioso; dois binários produzidos.
