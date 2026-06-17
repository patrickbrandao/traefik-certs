## 3. Variáveis de ambiente

| Variável                    | Default                                  | Aplica a            | Descrição |
|-----------------------------|------------------------------------------|---------------------|-----------|
| `TCERTS_SAVEDIR`            | `/certs`                                  | ambos               | Diretório raiz onde os certificados extraídos são gravados (um subdiretório por FQDN). |
| `TCERTS_ACME_INTERVAL`     | `3000`                                    | cert-watcher        | Intervalo de polling do `acme.json`, em **milissegundos**. Deve ser um inteiro positivo. |
| `TCERTS_ACME_JSON`         | `/etc/letsencrypt/acme.json`              | cert-watcher        | Caminho completo do arquivo `acme.json`. |
| `TCERTS_REDIS_URL`         | *(vazio)*                                 | ambos               | URL do Redis. Formatos aceitos: `redis://[:senha@]host:porta[/db]` e `rediss://…` (TLS). **Vazio → modo local** (sem distribuição). Valor não-vazio com scheme diferente de `redis` ou `rediss`, host ausente ou sintaxe inválida → **erro fatal claro no boot**. |
| `TCERTS_REDIS_PREFIX`      | `tcerts`                                  | ambos               | Prefixo das chaves (`<prefix>:cert:<fqdn>`) e do canal (`<prefix>:events`). |
| `TCERTS_HOOK_DIR`          | *(vazio)*                                 | cert-watcher        | Diretório com executáveis do hook 1. Vazio → hook 1 ignorado. |
| `TCERTS_HOOK_TIMEOUT`      | `30s`                                     | cert-watcher        | Timeout por script do hook 1 (formato `time.ParseDuration`). |
| `TCERTS_WEBHOOK_URL`       | *(vazio)*                                 | cert-watcher        | Lista de URLs do hook 2, **separadas por vírgula** (`,`). Espaços ao redor são trimmed. Entradas vazias (vírgula sobrando, trailing comma) são descartadas silenciosamente. Cada URL deve ter scheme `http` ou `https` e host não-vazio. Vazio ou nenhuma entrada válida → hook 2 ignorado. Ex.: `https://a.example/hook, https://b.example/hook`. |
| `TCERTS_WEBHOOK_BEARER`    | *(vazio)*                                 | cert-watcher        | Se setado, adiciona header `Authorization: Bearer <valor>` a **todas** as URLs da lista. Token único, compartilhado entre todos os endpoints. |
| `TCERTS_WEBHOOK_TIMEOUT`   | `10s`                                     | cert-watcher        | Timeout do POST (formato `time.ParseDuration`). |
| `TCERTS_WEBHOOK_RETRIES`   | `3`                                       | cert-watcher        | Tentativas do POST, com backoff exponencial. Deve ser inteiro ≥ 0. |
| `TCERTS_WEBHOOK_REDACT_KEY`| `false`                                   | cert-watcher        | Se `true`, remove `pem.privkey` **apenas do corpo do POST** (o arquivo em disco continua completo). |
| `TCERTS_LOG_LEVEL`         | `info`                                    | ambos               | `debug`, `info`, `warn`, `error`. Log estruturado em JSON. |
| `TCERTS_NODE_ID`           | hostname                                  | ambos               | Identificador do nó, apenas para logs. Não participa da lógica de dedup. |

### 3.1 Validação no boot

- `TCERTS_ACME_INTERVAL` não-numérico ou ≤ 0 → erro fatal.
- `TCERTS_REDIS_URL` não-vazio com scheme ≠ `redis`/`rediss`, host vazio ou URL sintaticamente inválida → erro fatal.
  Validar explicitamente o scheme e o host após `url.Parse`; **não confiar apenas na ausência de erro de `url.Parse`**, pois
  `url.Parse` em Go devolve `nil` para praticamente qualquer string.
- `TCERTS_HOOK_TIMEOUT`, `TCERTS_WEBHOOK_TIMEOUT` que não passem em `time.ParseDuration` → erro fatal.
- `TCERTS_WEBHOOK_RETRIES` negativo → erro fatal.
- `TCERTS_WEBHOOK_URL` não-vazio: fazer `strings.Split(",")`, trim de cada entrada, descartar vazias.
  Para cada URL remanescente, validar via `url.Parse` que `scheme ∈ {http, https}` e `host != ""` (mesma
  postura de validação explícita exigida para `TCERTS_REDIS_URL` acima — não confiar apenas na ausência de
  erro de `url.Parse`). Qualquer URL inválida → **erro fatal claro no boot**.
- `TCERTS_LOG_LEVEL` com valor desconhecido → erro fatal.

### 3.2 Construção de caminhos

Todo caminho de arquivo deve ser construído com `filepath.Join`, nunca com concatenação manual de strings
(`dir + "/" + file`). Isso garante portabilidade e elimina duplicatas de separador.
`TCERTS_ACME_JSON` é exceção: trata-se do caminho completo do arquivo, informado diretamente pela variável.
