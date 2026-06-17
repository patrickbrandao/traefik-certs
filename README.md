# traefik-certs (tcerts)

Extrai certificados Let's Encrypt do `acme.json` gerado pelo Traefik, grava cada certificado em disco (um diretório por FQDN) e distribui entre nós de um cluster via Redis.

## O que faz

Em ambientes com Traefik em múltiplos nós (ex.: Docker Swarm), apenas um nó produz o `acme.json`. O `tcerts`:

1. Le o `acme.json` (somente leitura) e extrai cada certificado para arquivos individuais por FQDN.
2. Publica os certificados no Redis para que os demais nós os recebam.
3. Aprende certificados de outros nós via Redis e os grava localmente.
4. A cada escrita originada do `acme.json`, dispara hooks: scripts locais e/ou webhooks HTTP.
5. Oferece o utilitario `cert-get` para que outros containers coletam o certificado mais recente de um FQDN.

A regra central de toda sincronizacao e: vence sempre o registro mais recente (maior `not_after`). Nenhuma escrita e cega — o certificado novo so e gravado se for estritamente mais novo que o existente.

## Binarios

| Binario | Funcao |
|---------|--------|
| `cert-watcher` | Daemon. Faz polling do `acme.json`, grava em disco, publica e consome o Redis, dispara hooks. |
| `cert-get <fqdn> <destino>` | Utilitario pontual. Le disco e Redis, seleciona o melhor certificado valido para o FQDN e grava os arquivos PEM em `<destino>`. |

O `CMD` da imagem Docker e `cert-watcher`. Para rodar `cert-get`, sobrescreva o entrypoint.

## Arquivos gerados em disco

Para cada FQDN, o `cert-watcher` cria `$TCERTS_SAVEDIR/<fqdn>/` com:

| Arquivo | Conteudo | Permissao |
|---------|----------|-----------|
| `fullchain.pem` | Cadeia completa: leaf + intermediarios | `0644` |
| `cert.pem` | Apenas o certificado leaf | `0644` |
| `chain.pem` | Intermediarios (fullchain menos cert.pem) | `0644` |
| `privkey.pem` | Chave privada | `0600` |
| `cert.md5` | MD5 hex do `cert.pem` | `0644` |
| `cert.json` | Objeto completo com PEMs e metadados | `0600` |

Certificados wildcard (`*.example.com`) sao gravados no diretorio `example.com` (prefixo `*.` removido). O matching real e feito pelos SANs dentro do `cert.json`, nao pelo nome do diretorio.

## Variaveis de ambiente

| Variavel | Padrao | Aplica a | Descricao |
|----------|--------|----------|-----------|
| `TCERTS_SAVEDIR` | `/certs` | ambos | Diretorio raiz onde os certificados sao gravados (um subdiretorio por FQDN). |
| `TCERTS_ACME_JSON` | `/etc/letsencrypt/acme.json` | cert-watcher | Caminho completo do `acme.json`. |
| `TCERTS_ACME_INTERVAL` | `3000` | cert-watcher | Intervalo de polling do `acme.json` em milissegundos. Deve ser inteiro positivo. |
| `TCERTS_REDIS_URL` | *(vazio)* | ambos | URL do Redis. Formatos: `redis://[:senha@]host:porta[/db]` ou `rediss://` (TLS). Vazio = modo local sem distribuicao. |
| `TCERTS_REDIS_PREFIX` | `tcerts` | ambos | Prefixo das chaves Redis (`<prefix>:cert:<fqdn>`) e do canal de eventos (`<prefix>:events`). |
| `TCERTS_HOOK_DIR` | *(vazio)* | cert-watcher | Diretorio com executaveis de hook local. Cada script recebe `<dir> <fqdn>` como argumentos. Vazio = ignorado. |
| `TCERTS_HOOK_TIMEOUT` | `30s` | cert-watcher | Timeout por script de hook local (formato `time.ParseDuration`). |
| `TCERTS_WEBHOOK_URL` | *(vazio)* | cert-watcher | URLs de webhook separadas por virgula. Cada URL recebe um POST com o `cert.json`. Vazio = ignorado. |
| `TCERTS_WEBHOOK_BEARER` | *(vazio)* | cert-watcher | Token Bearer adicionado ao header `Authorization` de todos os webhooks. |
| `TCERTS_WEBHOOK_TIMEOUT` | `10s` | cert-watcher | Timeout do POST do webhook (formato `time.ParseDuration`). |
| `TCERTS_WEBHOOK_RETRIES` | `3` | cert-watcher | Numero de tentativas do POST com backoff exponencial. Inteiro >= 0. |
| `TCERTS_WEBHOOK_REDACT_KEY` | `false` | cert-watcher | Se `true`, omite `pem.privkey` apenas no corpo do POST (o arquivo em disco permanece completo). |
| `TCERTS_LOG_LEVEL` | `info` | ambos | Nivel de log: `debug`, `info`, `warn`, `error`. Saida em JSON estruturado. |
| `TCERTS_NODE_ID` | hostname | ambos | Identificador do no, usado apenas em logs. |

Valores invalidos em qualquer variavel causam erro fatal no boot com mensagem clara.

## Build

```sh
# Via Docker (caminho suportado — produz imagem estatica)
./build.sh

# Com Go 1.23+ instalado localmente
go build ./cmd/cert-watcher ./cmd/cert-get
go test -race ./...
```

O `build.sh` gera as tags `traefik-certs:alpine`, `traefik-certs:latest` e `traefik-certs:distroless`.

## Exemplo de deploy

O `run.sh` mostra a invocacao completa do `cert-watcher` como container daemon:

```sh
#!/bin/sh

# Variaveis
    NAME="traefik-certs";
    LOCAL="$NAME.intranet.br";
    FQDN=$(hostname -f);
    DATADIR=/storage/$NAME;
    IMAGE=traefik-certs:latest;

    WEBHOOK_URL="https://ws.$FQDN/webhook/cert-watcher";
    # Para multiplos endpoints, separe por virgula:
    # WEBHOOK_URL="https://ws.$FQDN/webhook/cert-watcher,https://backup.$FQDN/webhook/cert-watcher";
    REDIS_URL="redis://redis-db:6379";

    # Pasta onde o Traefik salva o acme.json
    TRAEFIK_LETSENCRYPT_DIR="/storage/traefik-app/letsencrypt";

# Diretorios de dados persistentes
    mkdir -p $DATADIR;
    mkdir -p $DATADIR/logs;
    mkdir -p $DATADIR/certs;

# Criar e rodar
    docker rm -f $NAME 2>/dev/null;
    docker run \
        -d --restart=always \
        --name $NAME -h $LOCAL \
        \
        --network network_public \
        --ip=10.249.255.252 \
        \
        -e "TCERTS_REDIS_URL=$REDIS_URL" \
        \
        -e "TCERTS_ACME_JSON=/etc/letsencrypt/acme.json" \
        -e "TCERTS_WEBHOOK_URL=$WEBHOOK_URL" \
        -e "TCERTS_WEBHOOK_BEARER=9563113a3b0c11f0b6ea000c2994c680" \
        \
        -e "TCERTS_SAVEDIR=/data/certs" \
        \
        -v $DATADIR:/data \
        -v $TRAEFIK_LETSENCRYPT_DIR:/etc/letsencrypt \
        \
        $IMAGE;
```

Para usar `cert-get` em um container consumidor:

```sh
docker run --rm \
    -v /storage/traefik-certs/certs:/certs:ro \
    traefik-certs:alpine \
    /app/cert-get example.com /destino
```

## Redis e resiliencia

O Redis e opcional. Com `TCERTS_REDIS_URL` vazio, o `cert-watcher` opera em modo local — extrai e grava certificados em disco sem distribuicao.

Se o Redis estiver configurado mas inacessivel no boot, o daemon inicia normalmente e tenta reconectar com backoff exponencial. Ao reconectar, executa uma sincronizacao completa para nivelar o estado entre os nos.

## Seguranca

- O `acme.json` nunca e modificado.
- Todas as escritas em disco sao atomicas (arquivo temporario + chmod + rename).
- Por FQDN, um mutex serializa escritas concorrentes.
- `privkey.pem` e `cert.json` sao gravados com permissao `0600`.
