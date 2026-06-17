#!/bin/sh

# Variaveis
    NAME="traefik-certs";
    LOCAL="$NAME.intranet.br";
    FQDN=$(hostname -f);
    DATADIR=/storage/$NAME;
    IMAGE=traefik-certs:latest;

    WEBHOOK_URL="https://ws.$FQDN/webhook/cert-watcher";
    # Para múltiplos endpoints, separe por vírgula:
    # WEBHOOK_URL="https://ws.$FQDN/webhook/cert-watcher,https://backup.$FQDN/webhook/cert-watcher";
    REDIS_URL="redis://redis-db:6379";

    # pasta onde o traefik salva o acme.json
    TRAEFIK_LETSENCRYPT_DIR="/storage/traefik-app/letsencrypt";

# Diretorio de dados persistentes:
    mkdir -p $DATADIR;
    mkdir -p $DATADIR/logs;
    mkdir -p $DATADIR/certs;

# Imagem construida localmente.


# Criar e rodar:
    docker rm -f $NAME 2>/dev/null;
    docker run \
        -d --restart=always \
        --name $NAME -h $LOCAL \
        \
        --network network_public \
        --ip=10.249.255.252 \
        --ip6=2001:db8:10:249::255:252 \
        --mac-address "02:ca:f2:55:02:52" \
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
        \
        -v $TRAEFIK_LETSENCRYPT_DIR:/etc/letsencrypt \
        \
        $IMAGE;


exit 0;

        # --entrypoint tail \
        # $IMAGE tail -f /dev/null;





exit 0;


# Rodar cert-watcher (daemon padrão)
docker run \
    --rm \
    -e TCERTS_REDIS_URL=redis://redis:6379 \
    traefik-certs:alpine;

# Rodar cert-get (sobrescreve CMD)
docker run --rm traefik-certs:alpine /app/cert-get example.com /certs

