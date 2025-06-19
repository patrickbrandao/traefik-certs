#!/bin/sh

IMAGE=traefik-certs

# Remover containers
    docker ps -a | egrep $IMAGE | sort -R | awk '{print $1}' | \
	    while read did; do docker stop $did; docker rm $did; done

# Remover imagens
    docker rmi $IMAGE


exit 0

