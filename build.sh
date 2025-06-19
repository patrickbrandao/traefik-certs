#!/bin/sh

IMAGE=traefik-certs

find . | grep DS_Store | while read x; do rm $x; done
docker build . -t $IMAGE

exit 0

