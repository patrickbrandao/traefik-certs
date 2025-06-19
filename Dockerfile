
#========================================================================
#
# Container Alpine + Python + Scripts - Traefik Dump Certs (JSON to .pem)
#
#========================================================================

# Alpine 3.21
FROM alpine:3.21.3

# Variaveis globais de ambiente
ENV MAINTAINER="Patrick Brandao <patrickbrandao@gmail.com>"

# Preparar o debian com todos os pacotes
RUN ( \
    apk update && \
    apk upgrade && \
    apk add \
        bash grep sed mawk ca-certificates \
        curl python3 || exit 11; \
)

# Copiar arquivos personalizados:
ADD rootfs/opt/  /opt/

# Finalizar, ajustes e limpeza
RUN ( \
    chmod +x /opt/*; \
    rm -rf /var/cache/apk/* 2>/dev/null; \
)

# Script de inicializacao
ENTRYPOINT ["/opt/entrypoint.sh"]
CMD ["/opt/acme-json-watcher.py"]

