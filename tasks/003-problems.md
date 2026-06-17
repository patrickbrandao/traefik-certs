# Report Task 003 — Revisão de bugs, falhas de execução e consumo de recursos

**Data:** 2026-06-17
**Escopo:** Revisão estática de todo o código (`cmd/`, `internal/`) procurando por: falhas que quebrem o
software em runtime, caminhos que levem a consumo excessivo de CPU/RAM, e comportamento inconsistente
entre os fluxos (`sync_certs`, `sync_redis`, subscriber, hooks, `cert-get`).

> Observação: o toolchain Go não está instalado neste ambiente (builds rodam em Docker, conforme
> `docs/14-build.md`), portanto a revisão é **estática**. Não foi possível rodar `go vet`/`go test -race`
> para confirmar empiricamente os itens de concorrência — recomenda-se executá-los ao validar os fixes.

---

## Resumo por severidade

| # | Severidade | Categoria | Local | Problema |
|---|-----------|-----------|-------|----------|
| 1 | **Alta** | RAM / Logs | `internal/hooks/hooks.go:73-93` | `stdout`/`stderr` de Hook 1 bufferizados **sem limite** e logados na íntegra. |
| 2 | **Alta** | RAM / Logs | `internal/hooks/hooks.go:182` | Corpo da resposta do webhook lido com `io.ReadAll` **sem limite**. |
| 3 | **Alta** | CPU / I/O | `internal/config/config.go:34-39` | `TCERTS_ACME_INTERVAL` aceita `1` (ms) → polling em loop quente. |
| 4 | **Média** | CPU / Rede | `internal/reconcile/reconcile.go:243-245`, `248-389` | `SyncRedis` completo (O(N) GETs + leituras de disco) a **cada tick**, mesmo sem mudanças. |
| 5 | **Média** | Inconsistência | `internal/reconcile/reconcile.go:347` | PUSH usa `<=` e descarta cert re-emitido com mesmo `NotAfter` — diverge do tiebreaker de `SyncCerts`. |
| 6 | **Média** | Shutdown / Consistência | `cmd/cert-watcher/main.go:100-119` | `SyncCerts` em voo não é aguardado no shutdown; pode `Add` no `hookWg` concorrente ao `Wait()` e gravar após o `CloseBus()`. |
| 7 | **Média** | Consistência | `internal/certstore/certstore.go:107-133` | Conjunto de 6 arquivos gravado de forma atômica **individual**, mas não como grupo; leitor externo pode ver `cert.pem`/`privkey.pem` descasados durante rotação. |
| 8 | **Baixa** | Robustez | `internal/redisbus/redisbus.go:122-127` | `Subscribe` sobrescreve `b.cancel` sem cancelar o anterior → vazamento de goroutine se chamado 2× no mesmo bus. |
| 9 | **Baixa** | Vazão de eventos | `internal/redisbus/redisbus.go:147-151` | Handler do subscriber roda **síncrono** no loop de pub/sub; handler lento provoca overflow/descarte do buffer do go-redis. |
| 10 | **Baixa** | Disco | `internal/certstore/certstore.go:82-101` | Arquivos `.tmp-*` ficam órfãos se o processo morre entre `CreateTemp` e `Rename`. |
| 11 | **Baixa** | Dados obsoletos | `internal/certmodel/certmodel.go:28-29,164-182` | `is_currently_valid` / `seconds_to_expiry` congelam no momento da gravação. |
| 12 | **Baixa** | Logs | `internal/reconcile/reconcile.go:142-150` | `acme.json` ausente/inválido loga em `Warn` a cada tick → poluição de log. |
| 13 | **Nit** | Código morto | `cmd/cert-get/main.go:148-150` | `bestSource` nunca é `""` quando `best != nil`; bloco inalcançável. |

---

## Detalhamento

### 1. [Alta] `stdout`/`stderr` de hooks bufferizados sem limite (RAM + logs)

`internal/hooks/hooks.go:73-93`

```go
var stdout, stderr bytes.Buffer
cmd.Stdout = &stdout
cmd.Stderr = &stderr
err := cmd.Run()
...
slog.Info("hook1 script completed", ..., "stdout", stdout.String())
```

Um script de hook que emite muita saída (acidental — ex.: `set -x`, loop de debug — ou malicioso)
enche `bytes.Buffer` na memória **sem teto**, limitado apenas por `HookTimeout` (default 30s) × taxa de
saída. Com um script que escreve alguns MB/s, isso são centenas de MB de RAM por execução. Pior: o
conteúdo é então logado **inteiro** via `slog`, multiplicando o uso de memória e gerando linhas de log
gigantescas (e potencialmente vazando dados sensíveis para o log).

**Correção sugerida:** envolver `cmd.Stdout`/`cmd.Stderr` com um writer limitado (cap ~64 KB), e/ou
truncar a string antes de logar. Ex.: `io.LimitReader` numa pipe, ou um `bytes.Buffer` com guarda de
tamanho.

---

### 2. [Alta] Resposta do webhook lida sem limite (RAM + logs)

`internal/hooks/hooks.go:182`

```go
respBody, _ := io.ReadAll(resp.Body)
resp.Body.Close()
...
slog.Error("hook2 response", ..., "body", string(respBody), ...)
```

O endpoint de webhook é externo e não confiável. `io.ReadAll` lê o corpo **inteiro** para a memória sem
limite; um servidor que responda com um corpo enorme (ou um stream lento até o timeout) consome RAM
proporcional ao tamanho recebido. Em respostas não-2xx esse corpo ainda é logado por completo. Com
fan-out de N URLs em paralelo (goroutine por URL), o pior caso é N × tamanho simultâneo.

**Correção sugerida:** `io.ReadAll(io.LimitReader(resp.Body, 8<<10))` e truncar no log. Sempre drenar/
fechar o body (já é fechado — ok), mas limitar a leitura.

---

### 3. [Alta] `TCERTS_ACME_INTERVAL` permite intervalo de 1 ms (CPU/I/O)

`internal/config/config.go:34-39`

```go
intervalMs, err := strconv.Atoi(intervalMsStr)
if err != nil || intervalMs < 1 {
    return nil, fmt.Errorf("TCERTS_ACME_INTERVAL must be a positive integer, got %q", intervalMsStr)
}
c.AcmeInterval = time.Duration(intervalMs) * time.Millisecond
```

O piso é `1` **milissegundo**. Uma configuração equivocada (`TCERTS_ACME_INTERVAL=1`) coloca o
watcher num loop quente: a cada 1 ms ele relê e reparseia o `acme.json` inteiro, faz `x509.ParseCertificate`
+ 4× MD5 + SHA-256 por FQDN (`certmodel.BuildCertJSON`) e — se Redis configurado — dispara um `SyncRedis`
completo (ver item 4). Isso satura CPU, disco e Redis. O loop usa `WaitAndContinue` (correto, respeita
`ctx`), mas o intervalo minúsculo é o problema.

**Correção sugerida:** impor um piso sensato (ex.: `intervalMs < 250`) ou documentar/clampar o mínimo.

---

### 4. [Média] `SyncRedis` completo a cada tick mesmo sem mudanças (CPU/Rede)

`internal/reconcile/reconcile.go:243-245` e `248-389`

`SyncCerts` chama `SyncRedis` ao final de **todo** ciclo de polling:

```go
if r.getBus() != nil {
    r.SyncRedis(ctx)
}
```

`SyncRedis` faz, incondicionalmente a cada tick (default 3 s):
- **PULL:** `SCAN` de todas as chaves + `GetCert` para cada uma (N GETs).
- **PUSH:** `ScanFQDNs` + `ReadCertJSON` de cada FQDN local + `GetCert` de cada FQDN no Redis (mais ~2N
  operações).

Total ≈ **3N round-trips ao Redis + N leituras de disco a cada 3 s**, independentemente de haver qualquer
mudança. Com muitos certificados e/ou muitos nós (todos varrendo o mesmo prefixo no mesmo Redis), a carga
cresce O(N×nós) continuamente. O subscriber já entrega novidades por evento; a reconciliação completa
poderia ser periódica e espaçada, não a cada tick do `acme.json`.

**Correção sugerida:** desacoplar a cadência de `SyncRedis` da de `SyncCerts` (timer próprio, bem mais
largo), e/ou só rodar o PUSH para FQDNs efetivamente alterados no ciclo (já existe o mapa `updates`).

---

### 5. [Média] PUSH descarta cert re-emitido com mesmo `NotAfter` (inconsistência)

`internal/reconcile/reconcile.go:347-353`

```go
remote, _ := bus.GetCert(ctx, fqdn)
if remote != nil && local.NotAfterUnix <= remote.NotAfterUnix {
    continue                      // (A)
}
if remote != nil && remote.CertMD5 == local.CertMD5 {
    continue                      // (B)
}
```

`SyncCerts` grava localmente quando `NotAfterUnix` é igual **mas o hash do cert difere**
(tiebreaker em `reconcile.go:187`, citado em `AGENTS.md` como parte do invariante central). Já o PUSH usa
`<=` na linha (A), de modo que um cert re-emitido com **mesma validade e cert diferente** (ex.: re-key
mantendo `NotAfter`) é gravado em disco localmente mas **nunca propagado** ao Redis/aos outros nós — a
checagem por hash (B), que existiria justamente para isso, fica inalcançável porque (A) já fez `continue`.

Resultado: divergência silenciosa entre o que o nó escreve em disco e o que publica. Probabilidade baixa
(renovações do Let's Encrypt sempre estendem `NotAfter`), mas é uma inconsistência real entre os dois
"portões de escrita".

**Correção sugerida:** inverter a ordem — checar igualdade de `CertMD5` primeiro (skip se idêntico) e usar
`<` em vez de `<=`, espelhando o tiebreaker de `SyncCerts`.

---

### 6. [Média] Shutdown não aguarda `SyncCerts` em voo; corrida `hookWg.Add` vs `Wait`

`cmd/cert-watcher/main.go:100-119`

```go
go func() {
    for {
        if !reconcile.WaitAndContinue(ctx, cfg.AcmeInterval) { return }
        rec.SyncCerts(ctx)        // não checa ctx internamente após iniciar
    }
}()

sig := <-sigCh
cancel()
rec.Wait()        // hookWg.Wait()
rec.CloseBus()
```

A goroutine de polling **não é aguardada** (não há join). No shutdown, `cancel()` + `rec.Wait()` rodam,
mas um `SyncCerts` que já tenha começado continua executando em paralelo: ele grava arquivos e, ao final,
faz `r.hookWg.Add(1)` para despachar hooks (`reconcile.go:227-235`).

Dois problemas decorrem:
1. **Corrida no WaitGroup:** se nesse instante o contador estiver em 0, ter um `Add(positivo)` concorrente
   com `Wait()` é exatamente o padrão proibido pelo contrato de `sync.WaitGroup` ("Add com delta positivo
   a partir de zero deve *happen-before* o `Wait`"). Pode fazer o `Wait` retornar antes dos hooks recém-
   despachados, ou — no pior caso — panic de reuso.
2. **Gravação após o "shutdown gracioso":** `SyncCerts` em voo pode ainda estar escrevendo em disco / no
   Redis depois que `rec.Wait()` retornou e `CloseBus()` foi chamado, contrariando a garantia de §11.5.

**Correção sugerida:** tornar a goroutine de polling joinável (ex.: `sync.WaitGroup`/canal `done`) e
aguardá-la **antes** de `rec.Wait()`; assim nenhum `SyncCerts` novo inicia e o que está em voo termina
antes do `hookWg.Wait()`.

---

### 7. [Média] Conjunto de arquivos do cert não é atômico como grupo

`internal/certstore/certstore.go:107-133`

`writeCertFilesToDir` grava `fullchain.pem`, `cert.pem`, `chain.pem`, `privkey.pem`, `cert.md5` e
`cert.json` cada um via `WriteAtomic` (temp + rename — atômico **por arquivo**). Mas o conjunto não é
atômico: durante uma rotação, um leitor externo (Traefik, outro consumidor, ou um hook que leia o
diretório) que não tome o lock por-FQDN pode ler `cert.pem` já novo e `privkey.pem` ainda antigo →
par cert/chave descasado momentaneamente. Os escritores são serializados pelo lock por-FQDN
(`reconcile.go`), mas **leitores não pegam o lock**.

Isso é inerente ao contrato em disco de 6 arquivos separados; vale ao menos documentar a janela e,
idealmente, ordenar as gravações para minimizar o risco (ex.: gravar `privkey.pem` e `fullchain.pem`
antes do `cert.json`, que costuma ser o "sinal" lido por consumidores). `cert-get` (one-shot) não é
afetado porque grava num `DEST_DIR` próprio.

---

### 8. [Baixa] `Subscribe` sobrescreve `b.cancel` sem cancelar o anterior

`internal/redisbus/redisbus.go:122-162`

```go
func (b *Bus) Subscribe(ctx context.Context, handler func(fqdn string)) {
    innerCtx, cancel := context.WithCancel(ctx)
    b.mu.Lock()
    b.cancel = cancel     // sobrescreve sem cancelar o cancel anterior
    b.mu.Unlock()
    b.wg.Add(1)
    go func() { ... }()
}
```

Hoje `StartSubscriber` é chamado uma única vez por bus (no boot, se conectado; ou pelo watchdog após
reconectar — caminhos mutuamente exclusivos), então não dispara na prática. Mas a função é frágil: se
algum dia for chamada 2× no mesmo bus, a primeira goroutine **nunca é cancelada** (vaza até o fim do
processo) e passam a existir dois subscribers concorrentes; `Close()` só cancela o último `b.cancel`.

**Correção sugerida:** no início de `Subscribe`, se `b.cancel != nil`, cancelar e aguardar antes de
registrar o novo (ou tornar `Subscribe` idempotente).

---

### 9. [Baixa] Handler do subscriber roda síncrono no loop de pub/sub

`internal/redisbus/redisbus.go:147-151`

```go
case msg, ok := <-ch:
    if !ok { break loop }
    handler(msg.Payload)     // HandleRedisEvent: GET no Redis + escrita em disco sob lock
```

`handler` (= `HandleRedisEvent`) faz GET no Redis + leitura/escrita em disco sob o lock por-FQDN,
**bloqueando** o consumo do canal. Se o handler ficar lento (disco lento, ou contenda do lock por-FQDN
com um `SyncRedis` longo), as mensagens acumulam no canal interno do go-redis (buffer default ~100) e,
ao estourar, **eventos são descartados** ("pub/sub overflow"). O impacto é mitigado pelo `SyncRedis`
periódico (que recupera o que foi perdido), por isso severidade baixa — mas sob carga há perda de
pontualidade.

**Correção sugerida:** processar o evento de forma assíncrona (worker pool com deduplicação por FQDN) ou,
no mínimo, registrar quando o buffer satura.

---

### 10. [Baixa] Arquivos temporários órfãos em caso de crash

`internal/certstore/certstore.go:82-101`

`WriteAtomic` cria `.tmp-<name>-*` no diretório destino e, se o processo morre entre `CreateTemp` e
`Rename`, o arquivo temporário fica para trás (não há limpeza de órfãos no boot). `ScanFQDNs` lista só
diretórios no topo de `saveDir`, então os temporários ficam dentro das pastas de FQDN sem serem
recolhidos — acúmulo lento de lixo em disco ao longo de muitos crashes.

**Correção sugerida:** varredura de limpeza de `.tmp-*` na inicialização (ou ignorá-los explicitamente é
o que já ocorre — mas removê-los evita o acúmulo).

---

### 11. [Baixa] Campos de validade no `cert.json` ficam obsoletos

`internal/certmodel/certmodel.go:28-29, 164-182`

`IsCurrentlyValid` (`is_currently_valid`) e `SecondsToExpiry` (`seconds_to_expiry`) são calculados **no
momento da gravação** e persistidos. Quando o `cert.json` é lido tempos depois (ou puxado do Redis e
regravado), esses campos não refletem o "agora". `cert-get` está correto porque usa `IsValidNow()`
(recalcula a partir de `NotBeforeUnix`/`NotAfterUnix`), mas um consumidor que confie no campo
`is_currently_valid` do arquivo terá dado enganoso (um cert expirado pode aparecer com
`is_currently_valid: true`).

**Correção sugerida:** documentar que esses campos são "snapshot na gravação", ou marcá-los como derivados
e instruir consumidores a usar os `*_unix`.

---

### 12. [Baixa] Poluição de log quando `acme.json` está ausente/ inválido

`internal/reconcile/reconcile.go:142-150`

Quando o `acme.json` não existe ou está inválido, cada ciclo de polling loga em `Warn`
("sync_certs skip, cannot parse acme.json"). Com o intervalo default de 3 s, isso são ~20 linhas/min
indefinidamente até o arquivo aparecer — pode encher o storage de logs em cenários de boot demorado.
(É o comportamento previsto em `docs/13`: "logar e continuar"; a ressalva é apenas o **volume**.)

**Correção sugerida:** logar a transição de estado (apareceu/sumiu) em vez de repetir a cada tick, ou
rebaixar para `Debug` após a primeira ocorrência.

---

### 13. [Nit] Código inalcançável em `cert-get`

`cmd/cert-get/main.go:148-150`

```go
if best != nil && bestSource == "" {
    bestSource = "local"
}
```

`bestSource` é sempre atribuído junto com `best` dentro de `checkCert`, logo nunca é `""` quando
`best != nil`. Bloco morto; pode ser removido.

---

## Pontos verificados e considerados corretos

Para registro, os seguintes aspectos foram analisados e **não** apresentaram problema:

- **Comparação de recência** em `SyncCerts`/`HandleRedisEvent`/PULL de `SyncRedis` é consistente
  (escreve se local ausente ou `incoming.NotAfterUnix > local`). A única divergência é o PUSH (item 5).
- **Sem laços de escrita (ping-pong)** entre nós: o `SourceTable` impede republicar certs de origem
  `redis`, e empate de `NotAfter` não dispara reescrita no PULL/subscriber. O próprio evento publicado é
  reentregue ao subscriber do nó (auto-eco do pub/sub do Redis), mas resulta em no-op (não há reescrita).
- **Segurança de nil:** todos os retornos `*CertJSON` são checados antes do uso.
- **Captura de variável de loop** no despacho de hooks: parâmetros são passados explicitamente
  (`reconcile.go:229`), sem o bug clássico de closure.
- **Resiliência de Redis em runtime:** mesmo sem watchdog ativo (ele só inicia se o boot falhou), o
  `SyncRedis` por tick refaz `Ping` e recupera quando o Redis volta; o subscriber do go-redis reconecta
  internamente. A recuperação ocorre — a ressalva é o custo (item 4).
- **Ordem de locks:** não há aquisição aninhada de dois locks por-FQDN nem inversão de ordem entre
  `SourceTable.mu`, locks por-FQDN e `busMu`; não foi identificado deadlock.
- **`WriteAtomic`** usa sufixo aleatório (`os.CreateTemp`) e `rename` no mesmo diretório — correto contra
  leitura parcial de um arquivo individual.

---

## Recomendações priorizadas

1. Limitar buffers de hook (item 1) e leitura de resposta de webhook (item 2) — risco direto de RAM.
2. Impor piso de `TCERTS_ACME_INTERVAL` (item 3) — risco direto de CPU.
3. Tornar a goroutine de polling joinável no shutdown (item 6) — correção de garantia de §11.5.
4. Desacoplar/espaçar `SyncRedis` da cadência de polling (item 4) — escalabilidade.
5. Alinhar o gate de PUSH ao tiebreaker de `SyncCerts` (item 5) — consistência.

Após aplicar correções, validar com `go test -race ./...` (árbitro de concorrência segundo `docs/16`).
