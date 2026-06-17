#!/bin/sh

# Tag versionada
	VERSION="20260617";

# Tag e push da imagem MCP server
	docker tag traefik-certs:latest tmsoftbrasil/traefik-certs:$VERSION;
	docker tag traefik-certs:latest tmsoftbrasil/traefik-certs:latest;
	docker push tmsoftbrasil/traefik-certs:$VERSION;
	docker push tmsoftbrasil/traefik-certs:latest;

