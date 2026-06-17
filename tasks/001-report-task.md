# Report Task 001 — Remoção de `TCERTS_ACME_DIR` + `TCERTS_ACME_JSON` como caminho completo

**Data:** 2026-06-17
**Objetivo:** Remover `TCERTS_ACME_DIR`, consolidar em `TCERTS_ACME_JSON` como caminho completo do `acme.json` com default `/etc/letsencrypt/acme.json`.

---

## Resumo

| Arquivo | Linhas alteradas | Tipo de alteração |
|---|---|---|
| `internal/config/config.go` | 4 blocos | Remoção de `AcmeDir`/`AcmeJSON` do struct; `AcmeJSONPath` agora recebe diretamente o valor de `TCERTS_ACME_JSON`; removida função `findExistingDir()`; removido import `path/filepath`. |
| `internal/config/config_test.go` | 3 blocos | Removido `TCERTS_ACME_DIR` do `TestLoad_Defaults`; renomeado `TestLoad_AcmeJSONPath_UsesFilepathJoin` → `TestLoad_AcmeJSONPath_Direct`; adicionado `TestLoad_AcmeJSONPath_Default` para cobrir valor padrão. |
| `cmd/cert-watcher/main.go` | 1 bloco | Condição `cfg.AcmeDir == "" && cfg.AcmeJSONPath == ""` → apenas `cfg.AcmeJSONPath == ""`. |
| `docs/SPEC.md` | 6 blocos | Removida linha `TCERTS_ACME_DIR` da tabela de envs; atualizada descrição de `TCERTS_ACME_JSON`; ajustadas seções 3.2, 6, 13, 14 e checklist. |

---

## Detalhamento por arquivo

### 1. `internal/config/config.go`

**Struct `Config`:**
- Removidos campos `AcmeDir string` e `AcmeJSON string`.
- Mantido apenas `AcmeJSONPath string` como caminho completo.

**Função `Load()`:**
- Antes: lia `TCERTS_ACME_DIR` (com fallback `findExistingDir`) + `TCERTS_ACME_JSON` (default `acme.json`), compunha com `filepath.Join`.
- Depois: `c.AcmeJSONPath = envOrDefault("TCERTS_ACME_JSON", "/etc/letsencrypt/acme.json")`.

**Função removida:** `findExistingDir(paths ...string) string` (linhas 109-116).

**Import removido:** `"path/filepath"`.

### 2. `internal/config/config_test.go`

- `TestLoad_Defaults`: removida a linha `"TCERTS_ACME_DIR", "/nonexistent-dir-for-test"` do `setEnv`.
- `TestLoad_AcmeJSONPath_UsesFilepathJoin` renomeado para `TestLoad_AcmeJSONPath_Direct`: testa que `TCERTS_ACME_JSON` setado explicitamente é usado como caminho direto.
- Novo `TestLoad_AcmeJSONPath_Default`: testa que ao não setar a env, o valor padrão `/etc/letsencrypt/acme.json` é aplicado.

### 3. `cmd/cert-watcher/main.go`

- Linha 48: condição simplificada de `if cfg.AcmeDir == "" && cfg.AcmeJSONPath == "" {` para `if cfg.AcmeJSONPath == "" {`.

### 4. `docs/SPEC.md`

| Seção | Mudança |
|---|---|
| 3 (tabela de envs) | Removida linha `TCERTS_ACME_DIR`; `TCERTS_ACME_JSON` passa a ter default `/etc/letsencrypt/acme.json` e descrição "Caminho completo do arquivo acme.json". |
| 3.2 (construção de caminhos) | Adicionada nota de que `TCERTS_ACME_JSON` é exceção — já é o caminho completo. |
| 8.3 (`sync_certs`) | Pseudocódigo: `$TCERTS_ACME_DIR/$TCERTS_ACME_JSON` → `$TCERTS_ACME_JSON`. |
| 13 (casos de borda) | Removida linha sobre "nenhum dos diretórios padrão de `TCERTS_ACME_DIR` existe". |
| 14 (build) | `monta $TCERTS_ACME_DIR (RO)` → `monta $TCERTS_ACME_JSON (RO)`. |
| 17 (checklist) | Ajustado item de polling: `filepath.Join(TCERTS_ACME_DIR, TCERTS_ACME_JSON)` → `TCERTS_ACME_JSON`. |

---

## Verificação

```
go test ./...       → OK (todos os 6 pacotes com testes passam)
go test -race ./... → OK (sem race conditions detectadas)
go build ./cmd/cert-watcher → OK
go build ./cmd/cert-get     → OK
```

---

## Impacto no `run.sh`

O `run.sh` já utilizava `TCERTS_ACME_JSON=/etc/letsencrypt/acme.json` como caminho completo (linha 36). Nenhuma alteração necessária — compatível com a nova semântica desde o início.
