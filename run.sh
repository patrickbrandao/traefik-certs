#!/bin/sh


# Nome de DNS
    NAME="traefik-certs"
    LOCAL="$NAME.intranet.br"
    FQDN=$(hostname -f)

    DATADIR=/storage/$NAME

    IMAGE=traefik-certs:latest

    WEBHOOK_URL=https://n8n.$FQDN/webhook/cert-watcher

    # pasta onde o traefik salva o acme.json
    TRAEFIK_LETSENCRYPT_DIR=/storage/traefik-app/letsencrypt

# Diretorio de dados persistentes:
    mkdir -p $DATADIR
    mkdir -p $DATADIR/logs
    mkdir -p $DATADIR/certs

# Imagem construida localmente.


# Remover atual:
    (
        docker stop  $NAME
        docker rm    $NAME
        docker rm -f $NAME
    ) 2>/dev/null


# Criar e rodar:
    docker run \
        -d --restart=always \
        --name $NAME -h $LOCAL \
        --network network_public \
        \
        -e "TCERTS_ACME_JSON=/etc/letsencrypt/acme.json" \
        -e "TCERTS_WEBHOOK_URL=$WEBHOOK_URL" \
        -e "TCERTS_WEBHOOK_BEARER=66e732e895f2a25dd66b135cefea8f6d" \
        \
        -e "TCERTS_SAVEDIR=/data/certs" \
        \
        -v $DATADIR:/data \
        \
        -v $TRAEFIK_LETSENCRYPT_DIR:/etc/letsencrypt \
        \
        $IMAGE #sleep 9999999


exit 0

# /opt/entrypoint.sh /opt/acme-json-watcher.py

