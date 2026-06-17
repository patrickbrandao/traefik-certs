#!/bin/sh

# Alpine
docker build \
    -f Dockerfile.alpine \
    -t traefik-certs:alpine \
    -t traefik-certs:latest \
    .;

# Distroless
docker build \
    -f Dockerfile.distroless \
    -t traefik-certs:distroless \
    .;

