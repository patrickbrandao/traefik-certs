#!/bin/sh

# Remover containers
docker rm -f traefik-certs;

# Remover imagens
docker rmi traefik-certs:alpine;
docker rmi traefik-certs:latest;
docker rmi traefik-certs:distroless;

