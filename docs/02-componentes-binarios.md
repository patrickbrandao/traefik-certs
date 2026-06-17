## 2. Componentes / binários

O repositório produz **dois binários independentes**:

| Binário        | Caminho             | Destino                                                        |
|----------------|---------------------|---------------------------------------------------------------|
| `cert-watcher` | `cmd/cert-watcher`  | Container de sincronismo (roda como daemon).                  |
| `cert-get`     | `cmd/cert-get`      | Embarcado nos softwares/containers que consomem os certificados. |

Layout sugerido:

```
.
├── cmd/
│   ├── cert-watcher/main.go
│   └── cert-get/main.go
├── internal/
│   ├── acme/        # parsing do acme.json
│   ├── certstore/   # leitura/escrita do diretório de certificados (atômico, locks)
│   ├── certmodel/   # struct CertJSON, decomposição de PEM, parsing x509
│   ├── redisbus/    # chave + canal, publish/subscribe
│   ├── reconcile/   # sync_certs, sync_redis, comparação de recência, tabela de origens
│   ├── hooks/       # hook 1 (scripts) e hook 2 (webhook)
│   └── config/      # leitura das envs e defaults
├── go.mod
└── SPEC.md
```

Dependências: `github.com/redis/go-redis/v9`. Stdlib para x509/TLS/exec/HTTP. Log estruturado JSON
(`log/slog` da stdlib é suficiente).

**Module path:** definido pelo mantenedor (ex.: `github.com/<org>/tcerts`).
