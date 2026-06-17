## 11. Segurança de gravação e concorrência

### 11.1 Escrita atômica

Gravar em arquivo temporário no **mesmo diretório** e fazer `rename` para o destino final (evita que o
Traefik/consumidor leia um PEM pela metade). Vale para **todos** os arquivos, incluindo em `cert-get`.
O arquivo temporário deve ter um sufixo aleatório para evitar colisões entre goroutines paralelas.

### 11.2 Lock por FQDN

Mutex em memória por FQDN: `sync_certs`, `sync_redis` e o subscriber podem tocar o mesmo FQDN
concorrentemente. Toda sequência leitura-comparação-escrita de um FQDN deve ocorrer sob o lock exclusivo
daquele FQDN.

### 11.3 Permissões

Diretórios `0755`; `privkey.pem` e `cert.json` `0600`; demais arquivos `0644`.

### 11.4 Concorrência de estado compartilhado

Todo estado acessado por múltiplas goroutines concorrentes deve ter sua sincronização explicitamente especificada
e implementada. Regras obrigatórias:

- **Tabela de origens (`SourceTable`):** protegida por `sync.RWMutex`. `Get` usa `RLock`/`RUnlock`;
  `Set` e `LoadFromDisk` usam `Lock`/`Unlock`.
- **Campo `bus` em `Reconcile`:** se o bus pode ser trocado após a inicialização (ex.: reconexão Redis),
  proteger o campo por `sync.RWMutex`. Acessar sempre via getter protegido; nunca usar o campo diretamente
  em métodos que possam ser chamados concorrentemente.
- **`cancel` do subscriber em `Bus`:** proteger por `sync.Mutex` quando atribuído no `Subscribe` e lido no
  `Close`, pois podem ser chamados de goroutines diferentes.
- O comando `go test -race ./...` deve passar sem detecção de races em todos os pacotes.

### 11.5 Rastreamento de goroutines de hook para shutdown gracioso

As goroutines disparadas para executar hooks devem ser rastreadas via `sync.WaitGroup` no `Reconcile`.
O shutdown deve aguardar a conclusão de todos os hooks antes de encerrar o processo:

```
cancelar ctx  →  hookWg.Wait()  →  fechar bus Redis  →  sair
```

Não usar goroutines aninhadas (`go func() { go hook1(); go hook2() }()`) sem rastreamento — hooks em
andamento seriam abruptamente interrompidos em shutdown. No Hook 2, **cada URL da lista
`TCERTS_WEBHOOK_URL` gera uma entrada própria no `hookWg`** (`wg.Add(1)` por URL), de forma que o shutdown
aguarde todas as goroutines de todas as URLs. Não agrupar todas as URLs em uma única goroutine sem
rastreamento individual.

### 11.6 Ciclo de vida do subscriber Redis

O subscriber deve ter um ciclo de vida desacoplado do contexto do chamador. A implementação
recomendada: `Subscribe(ctx, handler)` cria um contexto filho (`context.WithCancel`) e armazena o
cancel em `b.cancel`. `Close()` então pode parar o subscriber de forma independente, sem depender de
quem detém o contexto externo.

```go
func (b *Bus) Subscribe(ctx context.Context, handler func(string)) {
    innerCtx, cancel := context.WithCancel(ctx)
    b.mu.Lock()
    b.cancel = cancel
    b.mu.Unlock()
    // goroutine usa innerCtx
}

func (b *Bus) Close() {
    b.mu.Lock()
    if b.cancel != nil {
        b.cancel()
    }
    b.mu.Unlock()
    b.wg.Wait()
    b.client.Close()
}
```
