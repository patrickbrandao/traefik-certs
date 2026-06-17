## 16. Testes

### 16.1 Requisito mínimo

`go test ./...` deve passar sem erros. `go test -race ./...` deve passar sem nenhuma race condition detectada.
O detector de corridas do Go (`-race`) é o árbitro definitivo para problemas de concorrência — qualquer acesso
a map ou campo compartilhado sem sincronização será detectado.

### 16.2 Cobertura mínima por pacote

| Pacote | Casos obrigatórios |
|--------|--------------------|
| `certmodel` | `DecomposePEM` com 1, 2 e N blocos; erro para PEM vazio. `CoversWildcard`: positivos, negativos, ápice, dois níveis de profundidade. `IsValidNow`: válido, expirado, futuro, boundary inclusivo em `not_before` e `not_after`. `BuildCertJSON`: `sans` lidos do x509, não do argumento; `is_currently_valid` inclusivo. |
| `acme` | `ParseACME`: arquivo inexistente, vazio, JSON inválido, entrada sem cert/key (deve retornar 0 entradas sem erro), Traefik v2/v3, chaves com capitalização variável, wildcard sanitizado, múltiplos resolvers. |
| `certstore` | `WriteAtomic`: cria arquivo, permissões corretas, sobrescreve existente, cria diretórios intermediários. `Lock`: serializa acessos concorrentes ao mesmo FQDN. `WriteCertFiles`/`WriteCertFilesFlat`: produzem os 6 arquivos com permissões corretas. |
| `config` | Validação de cada variável de ambiente inválida: interval não-numérico ou ≤ 0, URL Redis com scheme errado/host vazio/sintaxe inválida, timeout não-parsável, retries negativo, log level desconhecido. `TCERTS_WEBHOOK_URL`: múltiplas URLs válidas separadas por vírgula → parseia lista correta (após trim); entradas vazias (`,`, trailing comma, espaços) descartadas silenciosamente; URL com scheme inválido (ex.: `ftp://`) ou host vazio → erro fatal. |
| `redisbus` | Extração de FQDN: TrimPrefix para prefixo básico, customizado, com colons. `New` retorna erro para endereço inalcançável (sem `os.Exit`). |
| `reconcile` | `SourceTable`: Set/Get, Get ausente, sobreescrita, acesso concorrente sem races (com `-race`). `WaitAndContinue`: retorna `true` após intervalo, retorna `false` para ctx cancelado, cancela mid-wait. Hook 2 (webhook) com fan-out paralelo: 2+ URLs em servidor de teste, todas recebem POST; uma URL que sempre retorna 500 → falha após retries sem abortar as demais; logs contêm `webhook_url` distinto por evento. |

### 16.3 Geração de certificados em testes

Testes que precisem de PEM/x509 válidos devem gerar certificados programaticamente com
`crypto/x509` + `crypto/ecdsa` (ou RSA) + `crypto/rand` no helper de teste — nunca hardcodar PEMs (frágeis
e difíceis de auditar). Exemplo:

```go
func makeCert(t *testing.T, dnsNames []string, notBefore, notAfter time.Time) (fullchain, privkey string) {
    priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    tmpl := &x509.Certificate{
        SerialNumber: big.NewInt(1),
        DNSNames:     dnsNames,
        NotBefore:    notBefore,
        NotAfter:     notAfter,
    }
    der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
    // encode der → PEM, encode priv → PEM …
}
```
