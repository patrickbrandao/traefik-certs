## 14. Build e empacotamento

- `go build` gera dois binários estáticos (`CGO_ENABLED=0` recomendado) para Linux amd64/arm64.
- `cert-watcher` roda como daemon no container de sincronismo; monta `$TCERTS_ACME_JSON` (RO),
  `$TCERTS_SAVEDIR` (RW) e, se usado, `$TCERTS_HOOK_DIR`.
- `cert-get` é copiado para as imagens consumidoras; depende apenas de `$TCERTS_SAVEDIR` (e, opcionalmente,
  `$TCERTS_REDIS_URL`).
- **Shutdown gracioso:** tratar `SIGINT`/`SIGTERM`. Sequência obrigatória:
  1. Cancelar o contexto raiz.
  2. `hookWg.Wait()` — aguardar conclusão de todos os hooks em andamento.
  3. Fechar o bus Redis (`bus.Close()`).
  4. Encerrar o processo.
