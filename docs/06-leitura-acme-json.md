## 6. Leitura e decomposição do `acme.json`

Formato (Traefik v2/v3), por resolver:

```json
{
  "<resolver>": {
    "Account": { "...": "..." },
    "Certificates": [
      {
        "domain": { "main": "example.com", "sans": ["*.example.com"] },
        "certificate": "<base64 do PEM fullchain>",
        "key": "<base64 do PEM da chave privada>",
        "Store": "default"
      }
    ]
  }
}
```

- **Iterar todos os resolvers** e todas as entradas de `Certificates`.
- `certificate` (base64) → decodificar → `fullchain.pem` (um ou mais blocos `CERTIFICATE`).
  - 1º bloco = `cert.pem` (leaf).
  - blocos restantes = `chain.pem`.
- `key` (base64) → decodificar → `privkey.pem`.
- FQDNs de diretório = `domain.main` + `domain.sans` (sanitizados, ver §4). Esses campos **não alimentam
  `sans` no `cert.json`** — ver §5.
- Parsing tolerante: chaves podem variar de capitalização entre versões; o parser deve aceitar tanto
  `Certificates`/`Domain`/`Certificate`/`Key` quanto variações minúsculas.
- **Entradas sem `certificate` ou `key` são ignoradas e logadas em `debug`**
  (nível `slog.Debug` com campos `component`, `resolver`). Nunca logar nem retornar erro para estas entradas.
- O arquivo pode estar sendo reescrito atomicamente pelo Traefik (rename). Tratamento: ler, validar JSON;
  em erro de parse (arquivo parcial/vazio) **pular o ciclo** e tentar no próximo tick.
