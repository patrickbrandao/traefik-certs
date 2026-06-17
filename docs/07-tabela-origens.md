## 7. Tabela de origens

`cert-watcher` mantém em memória uma tabela `map[fqdn] -> source` (`acme` | `file` | `redis`):

- **Boot:** para cada diretório existente em `$TCERTS_SAVEDIR`, ler `cert.json` e usar seu campo `source`.
  Se `cert.json` ausente/ilegível mas houver PEMs, origem = `file`.
- **Runtime:** atualizada a cada gravação (escrita por `acme` → `acme`; por Redis → `redis`).

Uso: observabilidade e **guarda explícita** da regra "certificado aprendido via Redis nunca é reenviado ao
Redis". Como `source` é persistido no `cert.json` em disco, a classificação sobrevive a reinícios.

**Segurança de acesso concorrente:** esta tabela é acessada por múltiplas goroutines concorrentes
(`sync_certs`, `sync_redis`, o subscriber). Deve ser protegida por `sync.RWMutex` (ou equivalente):
leituras com RLock, escritas com Lock. Falhar nisto produz `concurrent map read and map write` detectado
pelo `-race` em produção.

> A dedup/identidade entre nós continua sendo `cert_md5` (MD5 do leaf), que é idêntico entre nós — o campo
> `source` diferir por nó não afeta a sincronização.
