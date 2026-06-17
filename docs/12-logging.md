## 12. Logging / observabilidade

### 12.1 Configuração do logger

O logger JSON **deve ser configurado antes de qualquer log**, incluindo antes de `config.Load()`. Seguir
dois passos:

1. **Pré-boot:** `slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))`.
2. **Pós-config:** reconfigurar com o nível lido de `TCERTS_LOG_LEVEL`.

Isso evita que a mensagem de erro de boot seja emitida em formato texto (quebrando pipelines JSON).

### 12.2 Campos e eventos

- Log estruturado em **JSON** via `log/slog`, nível por `TCERTS_LOG_LEVEL`.
- Campos recomendados por evento: `ts`, `level`, `msg`, `component` (`sync_certs`/`sync_redis`/`subscriber`/
  `hook`/`webhook`/`cert-get`), `fqdn`, `source`, `not_after`, `action` (`write`/`skip`/`publish`/`learn`),
  `node_id`, `webhook_url` (para eventos do Hook 2 — identifica qual URL da lista `TCERTS_WEBHOOK_URL`
  originou o evento).
- Eventos mínimos a logar: ciclo iniciado/concluído, certificado escrito (com motivo), publicação no Redis,
  aprendizado via Redis, disparo/resultado de hook e webhook (um evento por URL do Hook 2 — início, sucesso
  e erro — cada um com `webhook_url`), erros de parse/IO/Redis.
