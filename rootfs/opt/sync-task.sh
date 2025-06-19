#!/bin/sh

# Tarefa de importacao dos certificados e acionamentos

# Funcoes
    _log(){ now=$(date "+%Y-%m-%d-%T"); xlog="$now|HOOK-SCRIPT|$@"; echo "$xlog"; echo "$xlog" >> /data/logs/cert-dump.log; }

    # Ler arquivo e codificar em base64 continuo
    _base64_inline(){
        bi_file="$1"
        cat "$bi_file" 2>/dev/null | base64 | while read line; do echo -n "$line"; done
    }

    # Chamar webhook
    _call_cert_webhook(){
        wh_url="$1"
        wh_bearer="$2"
        wh_domain="$3"
        wh_crtdir="$4"
        wh_version="$5"

        # enviar authorization?
        wh_auth=""
        [ "x$wh_bearer" = "x" ] || wh_auth="-H 'Authorization: Bearer $wh_bearer'"

        # json do conteudo do diretorio
        hw_content_md5=$(head -1 "$wh_crtdir/cert.md5")
        hw_content_fullchain=$(_base64_inline "$wh_crtdir/fullchain.pem")
        hw_content_chain=$(_base64_inline "$wh_crtdir/chain.pem")
        hw_content_cert=$(_base64_inline "$wh_crtdir/cert.pem")
        hw_content_pkey=$(_base64_inline "$wh_crtdir/privkey.pem")

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

        # Permitir varias URLs de webhook separadas por pipe '|'
        wh_url_parts=$(echo "$wh_url" | sed 's#|# #g')
        for _url in $wh_url_parts; do
            _log "Webhook call: $_url, domain=$wh_domain wh_crtdir=$wh_crtdir"
            curl -X POST \
                --connect-timeout 3 \
                --max-time 9 \
                -H "X-DOMAIN: $wh_domain" \
                -H "Accept: application/json" \
                -H "Content-Type: application/json" \
                $wh_auth \
                -d "$wh_json" \
                "$_url"; stdno="$?"
            _log "Webhook return: $stdno"

        done
    }


# Iniciando
    _log "Iniciando coleta de certificados"

# Diretorio de saida
    mkdir -p "$TCERTS_SAVEDIR"

    # - por FQDN do certificado
    mkdir -p $TCERTS_SAVEDIR/domains


# Extrair certificados do Traefik
	DB_VERSION=$(date "+%s")

    # Importar (codigo incorporado no init escrito em python)
    if [ -f "$TCERTS_ACME_JSON" ]; then
    	DB_VERSION=$(stat -c "%Z" $TCERTS_ACME_JSON)
        # ACME JSON Presente
        egrep -q '{' "$TCERTS_ACME_JSON"; stdno="$?"
        if [ "$stdno" = "0" ]; then
            # importar
            _log "Analise de certificados importados de: $TCERTS_ACME_JSON"
        else
            _log "Arquivo JSON do traefik vazio, requer registro de containers: $TCERTS_ACME_JSON"
        fi
    else
        _log "Nota: arquivo nao existe: $TCERTS_ACME_JSON"
    fi


# Detectar alteracoes nos certificados, gravar md5 e acionar webhook
    # diretorio de certificados, sub-diretorio domains precisa existir
    if [ -d "$TCERTS_SAVEDIR" ]; then
        # varrer certificados
        find "$TCERTS_SAVEDIR/domains" | egrep cert.md5 | while read crtmd5file; do
            domaindir=$(dirname "$crtmd5file")
            domainname=$(basename "$domaindir")
            prevmd5file=$(echo $crtmd5file | sed 's#/cert.md5#/.prev.md5#g')

            # - md5 atual
            md5act=$(head -1 "$crtmd5file" 2>/dev/null)

            # - md5 anterior
            md5old=$(head -1 "$prevmd5file" 2>/dev/null)
            [ "x$md5old" = "x" ] && md5old="d41d8cd98f00b204e9800998ecf8427e"

            _log " Verificando [$crtmd5file]/[$prevmd5file] ~ ($md5act)"
            changed=0
            if [ -f "$prevmd5file" ]; then
                # Existe, comparar
                if [ "$md5old" = "$md5act" ]; then
                    # igual, nao mudou
                    continue
                else
                    # mudou!
                    _log "INFO: $domainname [dir=$domaindir] md5 alterado ($md5old -> $md5act)."
                    # atualizar md5 local
                    changed=1
                    echo "$md5act" > "$crtmd5file"
                fi
            else
                # Nao existe, inicializar
                changed=2
                echo "$md5act" > "$crtmd5file"
            fi

            # tem webhook?
            [ "x$TCERTS_WEBHOOK_URL" = "x" ] && continue;

            # ignorar acionamento de webhook se nada foi alterado
            # e se o boot das webhooks ja foi invocado
            [ "$changed" = "0" -a -f "/run/wh_boot" ] && continue

            # requer acionamento de webook para envio dos certificados e chaves
            _call_cert_webhook \
                "$TCERTS_WEBHOOK_URL" "$TCERTS_WEBHOOK_BEARER" \
                "$domainname" "$domaindir" \
                "$DB_VERSION"

        done
    else
        _log "Alerta: diretorio de certificados importados ausente: $TCERTS_SAVEDIR"
    fi

    # Criar flag de que o webhook foi acionado no boot
    date > /run/wh_boot

# Fim!
    _log "Coleta de certificados concluida."


exit 0




