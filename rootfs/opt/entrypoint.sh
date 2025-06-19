#!/bin/sh

EXEC_CMD="$@"

# Funcoes
#========================================================================================================

    initlogfile="/data/logs/init.log"
    lastlogfile="/data/logs/last.log"
    _log(){ now=$(date "+%Y-%m-%d-%T"); echo "$now|$@"; echo "$now|$@" >> $initlogfile; }
    _eval(){ _log "Running: $@"; out=$(eval "$@" 2>&1); sn="$?"; _log "Output[$sn]: $out"; }

#========================================================================================================

    # Preparacao fundamental
    mkdir -p /data/logs

    # Limpar logs do ultimo boot
    cp $initlogfile $lastlogfile
    echo -n > $initlogfile

#========================================================================================================

    # Variaveis globais
    [ "x$TCERTS_ACME_JSON"       = "x"  ] && export TCERTS_ACME_JSON="/etc/letsencrypt/acme.json"
    [ "x$TCERTS_SAVEDIR"         = "x"  ] && export TCERTS_SAVEDIR="/data/certs"
    [ "x$TCERTS_HOOK_SCRIPT"     = "x"  ] && export TCERTS_HOOK_SCRIPT="/opt/sync-task.sh"
    [ "x$TCERTS_WEBHOOK_URL"     = "x"  ] && export TCERTS_WEBHOOK_URL=""
    [ "x$TCERTS_WEBHOOK_BEARER"  = "x"  ] && export TCERTS_WEBHOOK_BEARER=""

    # Tornar publico no env
    export TCERTS_ACME_JSON="$TCERTS_ACME_JSON"
    export TCERTS_SAVEDIR="$TCERTS_SAVEDIR"
    export TCERTS_HOOK_SCRIPT="$TCERTS_HOOK_SCRIPT"
    export TCERTS_WEBHOOK_URL="$TCERTS_WEBHOOK_URL"
    export TCERTS_WEBHOOK_BEARER="$TCERTS_WEBHOOK_BEARER"

    # Manifesto de variaveis de ambiente:
    _log "env-var: TCERTS_ACME_JSON=$TCERTS_ACME_JSON"
    _log "env-var: TCERTS_SAVEDIR=$TCERTS_SAVEDIR"
    _log "env-var: TCERTS_HOOK_SCRIPT=$TCERTS_HOOK_SCRIPT"
    _log "env-var: TCERTS_WEBHOOK_URL=$TCERTS_WEBHOOK_URL"
    _log "env-var: TCERTS_WEBHOOK_BEARER=$TCERTS_WEBHOOK_BEARER"

    # Criar diretorios basicos
    mkdir -p "$TCERTS_SAVEDIR"
    mkdir -p "$TCERTS_SAVEDIR/domains"

    # Fazer extracao de certificados
    _log "Calling: /opt/acme-json-watcher.py fetch"
    /opt/acme-json-watcher.py fetch

    # Chamar eventos iniciais
    _log "Calling: /opt/sync-task.sh"
    /opt/sync-task.sh

    # INICIAR:
    _log "Start entrypoint [$0 $@] cmd [$EXEC_CMD]"

    # Rodar CMD
    if [ "x$EXEC_CMD" = "x" ]; then
        _log "Start default CMD: [sleep 252288000]"
	    exec "sleep" "252288000"
	    stdno="$?"
    else
        FULLCMD="exec $EXEC_CMD"
    	_log "Start CMD: [$EXEC_CMD] [$FULLCMD]"
        eval $FULLCMD
    	stdno="$?"
    fi
    _log "Entrypoint end, stdno=$stdno"


exit $stdno

