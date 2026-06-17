## 4. Contrato em disco

Para cada FQDN, cria-se `$TCERTS_SAVEDIR/<fqdn-sanitizado>/` contendo:

| Arquivo          | Conteúdo                                                            | Permissão |
|------------------|--------------------------------------------------------------------|-----------|
| `fullchain.pem`  | Cadeia completa: leaf + intermediários, até a última sub-CA.        | `0644`    |
| `cert.pem`       | Apenas o certificado do FQDN (leaf, primeiro bloco da fullchain).   | `0644`    |
| `chain.pem`      | Intermediários = `fullchain.pem` menos `cert.pem`.                  | `0644`    |
| `privkey.pem`    | Chave privada.                                                      | `0600`    |
| `cert.md5`       | MD5 (hex) do conteúdo de `cert.pem`.                                | `0644`    |
| `cert.json`      | Objeto completo (ver §5), incluindo PEMs e chave privada.           | `0600`    |

Diretórios: `0755`.

**Sanitização do nome do diretório:** remover o prefixo de wildcard. `*.example.com` → `example.com`.
Consequência aceita: um wildcard e o domínio ápice compartilham o mesmo diretório (na prática vêm no mesmo
certificado SAN). O *matching* real (em `cert-get`) é feito pelos SANs do `cert.json`, não pelo nome do diretório.

**Mapeamento certificado → diretórios:** um certificado cobre `domain.main` + `domain.sans`. Para o conjunto
**único** de FQDNs sanitizados, cria-se um diretório por FQDN, todos recebendo a **mesma** bundle. O campo
`fqdn` do `cert.json` é o nome **sanitizado** daquele diretório; o campo `sans` preserva a forma original
(incluindo `*.example.com`).
