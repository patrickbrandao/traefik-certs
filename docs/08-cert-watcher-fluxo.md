## 8. `cert-watcher` — fluxo de execução

### 8.0 Inicialização do logger

O logger JSON estruturado **deve ser configurado antes de qualquer chamada de log**, incluindo antes de
`config.Load()`. Usar um handler JSON com nível `info` como mínimo provisório; reconfigurar com o nível
correto após carregar `TCERTS_LOG_LEVEL`. Isso garante que erros de configuração no boot sejam emitidos
em JSON, não em texto plano.

```
boot:
  configurar logger JSON mínimo (nível info) — ANTES de config.Load()
  validar config (erros fatais com mensagem clara)
  reconfigurar logger com o nível de TCERTS_LOG_LEVEL
  configurar logger JSON mínimo (nível info) — ANTES de config.Load()
  carregar tabela de origens a partir do disco ($TCERTS_SAVEDIR/*/cert.json)
  tentar conectar ao Redis (ver §8.1)
  iniciar contexto raiz do processo (cancelado por SIGINT/SIGTERM)
  sync_certs()                        # primeira reconciliação
  se bus Redis disponível:
    iniciar subscriber do canal       # caminho de baixa latência redis → arquivos
  se Redis configurado mas unavailable no boot:
    iniciar goroutine watchdog de reconexão (ver §13)
  iniciar goroutine do loop de polling (ver §8.2)
  aguardar SIGINT ou SIGTERM
  cancelar contexto raiz
  aguardar goroutines de hook (via WaitGroup — ver §11)
  fechar bus Redis (se aberto)
```

### 8.1 Conexão Redis no boot

**Falha de conexão Redis no boot NÃO É fatal.** O processo deve:
1. Logar `warn` com o erro.
2. Continuar em **modo local** (somente `acme.json` → disco, sem distribuição).
3. Iniciar uma goroutine de reconexão em background (ver §13).

Só são fatais no boot: erros de configuração (§3.1) e erros de leitura de variáveis obrigatórias.

### 8.2 Loop de polling

O loop de polling deve usar `select` com `ctx.Done()` durante o intervalo de espera, de modo que o shutdown
seja **imediato** e nunca espere até `TCERTS_ACME_INTERVAL` ms para encerrar:

```go
// Implementação correta:
func WaitAndContinue(ctx context.Context, interval time.Duration) bool {
    select {
    case <-ctx.Done():
        return false
    case <-time.After(interval):
        return true
    }
}

// Loop:
for {
    if !WaitAndContinue(ctx, cfg.AcmeInterval) {
        return
    }
    rec.SyncCerts(ctx)
}
```

**Nunca** usar `time.Sleep(interval)` no loop de polling — impede shutdown gracioso.

### 8.3 `sync_certs()`

```
ler e parsear $TCERTS_ACME_JSON  (se ausente/parcial → pular ciclo)
para cada certificado do acme.json:
  decompor PEMs, parsear x509, montar CertJSON (source="acme")
  sans = cert.DNSNames  (fonte autoritativa — ver §5)
  para cada FQDN (sanitizado) do certificado:
    com lock(fqdn):
      local = ler estado em disco do fqdn (se houver)
      se (local ausente) OU (acme.not_after > local.not_after)
         OU (acme.not_after == local.not_after E acme.hash.cert != local.hash.cert):
        gravar_atomico(fqdn, CertJSON, source="acme")
        atualizar tabela de origens[fqdn]=acme
        registrar update do fqdn
disparar_side_effects(updates)      # hooks 1 e 2, em goroutine rastreada; ver §9 e §11
se Redis configurado:
  sync_redis()
```

### 8.4 `sync_redis()` (somente se `TCERTS_REDIS_URL` definido)

```
# PULL: aprender do Redis o que falta ou está mais novo (NUNCA dispara hooks)
para cada chave <prefix>:cert:<fqdn> no Redis:
  remote = CertJSON da chave
  com lock(fqdn):
    local = estado em disco do fqdn
    se (local ausente) OU (remote.not_after > local.not_after):
      gravar_atomico(fqdn, remote, source="redis")
      tabela de origens[fqdn]=redis

# PUSH: enviar updates locais e o que falta no Redis
para cada fqdn local cuja origem != "redis":
  remote = CertJSON da chave <prefix>:cert:<fqdn> (se existir)
  se (remote ausente) OU (local.not_after > remote.not_after):
    se (remote existe E remote.cert_md5 == local.cert_md5):  # dedup: idêntico, não reenviar
      continuar
    SET <prefix>:cert:<fqdn> = local.cert_json
    PUBLISH <prefix>:events  fqdn
```

> As chaves do Redis **não expiram** (não há remoção de certificados expirados — requisito).

#### Extração de FQDN das chaves Redis

Ao varrer as chaves `<prefix>:cert:*` do Redis e extrair o FQDN, usar **`strings.TrimPrefix(key, prefix+":cert:")`**.
Nunca usar offsets numéricos mágicos (`key[len(prefix)+6:]`) — frágeis a mudanças de prefixo e silenciosamente
incorretos quando o prefixo tem comprimento diferente do esperado.

### 8.5 Subscriber do canal

```
SUBSCRIBE <prefix>:events
ao receber <fqdn>:
  remote = CertJSON da chave <prefix>:cert:<fqdn>
  com lock(fqdn):
    local = estado em disco do fqdn
    se (local ausente) OU (remote.not_after > local.not_after):
      gravar_atomico(fqdn, remote, source="redis")   # SEM hooks
      tabela de origens[fqdn]=redis
```

### 8.6 Regras de recência e desempate (válidas em todo o sistema)

- Critério primário: **maior `not_after` vence**.
- `not_after` igual: manter o local (não reescrever) **salvo** se `cert_md5` (leaf) for diferente — nesse caso
  tratar como update.
- Identidade para dedup: `cert_md5`.
