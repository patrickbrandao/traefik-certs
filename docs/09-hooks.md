## 9. Hooks (side effects)

Disparam **exclusivamente** quando há importação `acme.json → arquivo` (criação de novo diretório/arquivos
**ou** atualização de existentes via `sync_certs`). Importações `redis → arquivo` **nunca** disparam hooks.

Para cada FQDN atualizado por `sync_certs`, dispara-se em **goroutine rastreada** (ver §11 — não bloqueia o
loop, mas é aguardada no shutdown):

- **Hook 1** e **Hook 2** executam para cada FQDN atualizado.

### 9.1 Hook 1 — scripts em `TCERTS_HOOK_DIR`

- Se `TCERTS_HOOK_DIR` vazio → ignorar.
- Executar **todos os arquivos executáveis** do diretório, **sequencialmente em ordem lexical**.
- Argumentos de cada script: `$1` = caminho do diretório do FQDN (`$TCERTS_SAVEDIR/<fqdn>`), `$2` = FQDN.
- **Timeout por script:** usar `context.WithTimeout(ctx, cfg.HookTimeout)` onde `ctx` é o **contexto do
  processo** (não `context.Background()`). Isso garante que scripts em execução sejam cancelados tanto pelo
  timeout individual quanto pelo shutdown gracioso.
- `stdout`/`stderr` capturados e logados.
- Falha de um script: **logar e continuar** (não aborta os demais nem o processo).

#### Verificação do bit de execução em symlinks

Ao listar os scripts do diretório de hooks com `os.ReadDir`, entradas de tipo `os.ModeSymlink` devem ter
seu bit de execução verificado **no alvo do symlink**, não no próprio symlink:

```go
if e.Type()&os.ModeSymlink != 0 {
    info, err := os.Stat(filepath.Join(cfg.HookDir, e.Name()))  // segue o symlink
    if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
        continue
    }
    // executável
}
```

`DirEntry.Info()` retorna os metadados do symlink (que tem modo `lrwxrwxrwx = 0777`), não do alvo —
portanto não deve ser usado para verificar executabilidade de symlinks.

### 9.2 Hook 2 — webhook

- Parse de `TCERTS_WEBHOOK_URL` em lista (split por `,`, trim de cada entrada, descartar vazias). Se a lista
  resultante for vazia → ignorar.
- **Fan-out paralelo:** para cada URL válida, disparar **uma goroutine rastreada** (ver §11.5 — cada URL faz
  `hookWg.Add(1)` individualmente) que executa o POST independentemente. As goroutines compartilham o mesmo
  `ctx` do processo e o mesmo `hookWg` do `Reconcile`. **Bearer, timeout, retries e redação** são aplicados de
  forma idêntica a todas as URLs. Evitar `go func() { ...todas URLs... }()` sem rastreamento individual —
  hooks em andamento seriam abruptamente interrompidos em shutdown.
- `POST` do `cert.json` daquele FQDN. `Content-Type: application/json`.
- Se `TCERTS_WEBHOOK_BEARER` setado → header `Authorization: Bearer <valor>` (mesmo token para todas as URLs).
- Timeout `TCERTS_WEBHOOK_TIMEOUT`; `TCERTS_WEBHOOK_RETRIES` tentativas com backoff exponencial.
- **Backoff entre tentativas:** usar `select` com `ctx.Done()`, nunca `time.Sleep`:
  ```go
  select {
  case <-ctx.Done():
      return
  case <-time.After(backoff):
  }
  ```
  Usar `time.Sleep` bloqueia o shutdown pelo tempo de backoff (até `2^(retries-1)` segundos).
- A função recebe `ctx context.Context` como primeiro parâmetro para que o contexto do processo
  seja propagado corretamente.
- Se `TCERTS_WEBHOOK_REDACT_KEY=true`, remover `pem.privkey` do corpo (somente do POST, em todas as URLs).
- Falha após as tentativas em **uma URL**: logar em `error` com campo `webhook_url` e seguir. A falha de uma
  URL **não aborta nem afeta as demais** — cada goroutine é independente.
