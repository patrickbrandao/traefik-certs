
# Container de Debian + Scripts CertWatcher - para envio colecao de chaves e certificados
#========================================================================================

# Objetivo:
#   - montar container nos diretorios dos certificados obtidos via ACME (Traefik)
#
#   - montar em diretorios que contenham certificados wildcard comprados
#
#   - criar arquivos de chaves e certificados com objetivo de facilitar o uso
#     por containers dinamicos e temporarios que precisam de TLS/SSL em portas dinamicas
#
#   - obter certificados via API HTTP
#
#   - entregar certificados para webhooks
#
#
# Procedimentos
# * Localiza e exporta certificados do LetsEncrypt
#   para arquivos (privkey.pem e cert.pem) para uso em containers
#   dinamicos.
#
# * Solucao criada para servidores que usam protocolos
#   complexos de interagir integrar com Traefik e que precisam de certificados validos
#
# * Permite isolar acesso dos containers aos certificados
#   especificos que eles precisam para evitar vazamento
#   de chaves privadas
#
# * Variaveis de ambiente exigidas:
#   # - diretorio dentro do container para exportas os dominios e certificados (domains/FQDN/)
#   TCERTS_SAVEDIR=/data/certs
#
#   # - caminho dentro do container para o acme.json (json de storage de certificados do Traefik)
#   TCERTS_ACME_JSON=/etc/letsencrypt/acme.json
#
#   # - url de webhook para enviar certificados e chaves capturadas
#   TCERTS_WEBHOOK_URL=""
#
#   # - opcional: http header 'Authorization: Bearer xxxxxx', informe o xxxxxxx
#   TCERTS_WEBHOOK_BEARER=""
#
#   # - script de hook responsavel por processar os dominios e enviar
#   #   para fora (webhook) e demais eventos, por padrao chama um script interno
#   TCERTS_HOOK_SCRIPT=""
#
# * Scripts de boot em /opt/
#


# Preparando e instalando
#-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

    # entre no diretorio que contem o Dockerfile

    # construir imagem:
    sh  build.sh

    # Diretorio de dados persistentes:
    mkdir -p /storage/traefik-certs

    # Criar o container:
    sh  run.sh


    # Entrar no container:
    docker exec -it traefik-certs /bin/bash



# Teste de construcao
#-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

#------- debian
    # - criar container debian
    docker run -d --name teste -h teste.intranet.br debian:bookworm sleep 99999

    # - obter shell no container
    docker exec -it teste bash

    # - instalar pacotes do Dockerfile

    # - iniciar supervisor manualmente
    /opt/entrypoint.sh /opt/acme-json-watcher.py


#------- alpine:3.21.3
    docker run -d --name teste -h teste.intranet.br alpine:3.21.3 sleep 99999
    docker exec -it teste ash




# Teste de webhook, enviando certificado auto-assinado do OpenSSL
#-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

    # Ler arquivo e codificar em base64 continuo
    _base64_inline(){
        bi_file="$1"
        cat "$bi_file" 2>/dev/null | base64 | while read line; do echo -n "$line"; done
    }

    # Variaveis da webhook
    wh_url="https://n8n.intranet.br/webhook/cert-watcher"
    wh_bearer=ab3c4d525fd8451d8ffd52a7e659f191

    # Variaveis do certificado a enviar
    wh_domain="xpto.intranet.br"

    cert=/etc/ssl/certs/ssl-cert-snakeoil.pem
    pkey=/etc/ssl/private/ssl-cert-snakeoil.key

    # carregar conteudo para o json
    hw_content_md5=$(md5sum "$cert" | awk '{print $1}')
    hw_content_fullchain=$(_base64_inline "$cert")
    hw_content_chain=$(_base64_inline "$cert")
    hw_content_cert=$(_base64_inline "$cert")
    hw_content_pkey=$(_base64_inline "$pkey")

    # construir json
    wh_json="{"
    wh_json="$wh_json \"type\": \"certificate\","
    wh_json="$wh_json \"domain\": \"$wh_domain\","
    wh_json="$wh_json \"md5\": \"$hw_content_md5\","
    wh_json="$wh_json \"version\": \"$wh_version\","
    wh_json="$wh_json \"fullchain\": \"$hw_content_fullchain\","
    wh_json="$wh_json \"chain\": \"$hw_content_chain\","
    wh_json="$wh_json \"cert\": \"$hw_content_cert\","
    wh_json="$wh_json \"privkey\": \"$hw_content_pkey\""
    wh_json="$wh_json}"

    # enviar para webhook
    curl -X POST \
        --connect-timeout 3 \
        --max-time 9 \
        -H "X-DOMAIN: $wh_domain" \
        -H "Accept: application/json" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $wh_bearer" \
        -d "$wh_json" \
        "$wh_url"













