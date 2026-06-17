## 1. Objetivo

Em um cluster (ex.: Docker Swarm com Traefik em N nós), um único Traefik produz o `acme.json`.
O `tcerts`:

1. Lê o `acme.json` (somente leitura — **nunca escreve nesse arquivo**), extrai cada certificado para
   arquivos individuais por FQDN em um volume local.
2. Distribui esses certificados aos demais nós via Redis (chave durável por FQDN + canal de eventos).
3. Aprende, dos demais nós, certificados que ainda não possui, gravando-os localmente.
4. Em toda escrita originada do `acme.json`, dispara hooks (scripts locais + webhook).
5. Oferece um utilitário (`cert-get`) para que outros softwares coletem o certificado mais recente de um FQDN.

Regra transversal de toda sincronização: **vence sempre o registro mais recente** (maior `not_after`).
