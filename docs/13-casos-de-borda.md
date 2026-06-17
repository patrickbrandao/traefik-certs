## 13. Casos de borda e resiliência

- `acme.json` ausente no boot → não é fatal; logar e continuar tentando a cada tick.
- `acme.json` parcial/inválido em um ciclo → pular o ciclo.
- Entrada de certificado sem chave/cert → ignorar com `slog.Debug`.
- **Redis indisponível no boot:** não é fatal. Iniciar em modo local, iniciar goroutine de reconexão
  em background (ver abaixo).
- **Redis indisponível em runtime:** degradar para modo local, continuar `sync_certs`, goroutine de
  reconexão já em execução.
- **Goroutine de reconexão Redis:**
  - Tentativas com backoff exponencial (ex.: início em 5 s, máximo 60 s).
  - Respeitar `ctx.Done()` durante o backoff (usar `select`, nunca `time.Sleep`).
  - Ao reconectar com sucesso: chamar `rec.SetBus(bus)`, iniciar subscriber, executar `sync_redis()` completo.
  - A goroutine termina após conexão bem-sucedida.
- Wildcard + ápice no mesmo diretório → aceito (mesma bundle SAN).
- Concorrência de publicação entre nós com o mesmo cert novo → idempotente (mesmo `cert_md5`; last-write-wins).
- `TCERTS_WEBHOOK_URL` com lista de N URLs onde K falham após todas as retries: as N−K URLs bem-sucedidas
  **não são afetadas**; cada falha é logada independentemente em `error` com `webhook_url`. Nenhuma URL
  falha aborta o ciclo ou o processo.
- Nenhuma remoção de certificados expirados em nenhum fluxo (requisito explícito).
