## 5. Schema do `cert.json`

Objeto único, "absolutamente completo", também usado como **payload do Redis** e corpo do **webhook**.

```json
{
  "fqdn": "example.com",
  "sans": ["example.com", "*.example.com"],
  "is_wildcard": true,
  "subject_cn": "example.com",
  "issuer_cn": "R11",
  "issuer_org": "Let's Encrypt",
  "serial": "03ab9f...",
  "not_before": "2026-06-01T00:00:00Z",
  "not_before_unix": 1780272000,
  "not_after": "2026-08-30T23:59:59Z",
  "not_after_unix": 1788091199,
  "seconds_to_expiry": 6480000,
  "is_currently_valid": true,
  "fingerprint_sha256": "ab12cd...",
  "cert_md5": "d41d8cd98f00b204e9800998ecf8427e",
  "key_algorithm": "ECDSA",
  "key_bits": 256,
  "signature_algorithm": "ECDSA-SHA384",
  "source": "acme",
  "acme_resolver": "le",
  "updated_at": "2026-06-16T12:00:00Z",
  "pem": {
    "cert": "-----BEGIN CERTIFICATE-----\n...",
    "chain": "-----BEGIN CERTIFICATE-----\n...",
    "fullchain": "-----BEGIN CERTIFICATE-----\n...",
    "privkey": "-----BEGIN PRIVATE KEY-----\n..."
  },
  "hash": {
    "cert": "<md5 de cert.pem>",
    "chain": "<md5 de chain.pem>",
    "fullchain": "<md5 de fullchain.pem>",
    "privkey": "<md5 de privkey.pem>"
  }
}
```

### Regras de preenchimento

- **`sans` — fonte autoritativa:** o campo `sans` do `CertJSON` deve ser lido **exclusivamente** de
  `cert.DNSNames` (parsing x509 do leaf), **nunca** dos campos `domain.main` / `domain.sans` do `acme.json`.
  Os campos JSON de domínio são usados apenas para determinar quais diretórios criar (ver §4). Se `cert.DNSNames`
  estiver vazio e `cert.Subject.CommonName` não estiver, usar `[]string{CommonName}` como fallback.
  Esta regra impede divergência quando o JSON estiver desatualizado ou inconsistente com o certificado real.

- Demais campos x509 (`subject_cn`, `issuer_cn`, `issuer_org`, `serial`, `not_before`, `not_after`,
  `fingerprint_sha256`, `signature_algorithm`, `key_algorithm`, `key_bits`) são extraídos do
  **leaf** (`cert.pem`) por parsing x509.

- `is_wildcard` = existe algum SAN em `sans` iniciando com `*.`.

- `fingerprint_sha256`: SHA-256 do DER do leaf, em hex.

- `serial`: número de série em hex.

- `not_*_unix`: epoch em segundos (UTC).

- `seconds_to_expiry`: `not_after_unix - now` no momento da gravação (informativo, mínimo 0).

- **`is_currently_valid`:** `not_before_unix <= now_unix <= not_after_unix` no momento da gravação.
  Ambos os extremos são **inclusivos**. Em Go: `!now.Before(notBefore) && !now.After(notAfter)`.
  **Não usar** `now.After(notBefore)` no lugar de `!now.Before(notBefore)` — o primeiro é exclusivo no limite.
  O mesmo critério inclusivo deve ser aplicado em qualquer outro ponto do código que verifique validade
  (ex.: `IsValidNow()` em `CertJSON`).

- `cert_md5`: MD5 de `cert.pem` (idêntico a `hash.cert`). **É a identidade do certificado** usada para dedup.

- `key_algorithm` / `key_bits`: derivados da chave pública do leaf (`RSA`/`ECDSA` etc.).

- `source`: origem **local deste nó** — `acme` | `file` | `redis` (ver §7). É reescrito por nó: ao gravar
  a partir do `acme.json` → `acme`; a partir do Redis → `redis`; arquivos pré-existentes sem metadado → `file`.

- `acme_resolver`: nome do resolver no `acme.json` de onde veio (vazio quando origem não-acme).

- `updated_at`: timestamp da gravação local (RFC3339 UTC).

> **Importante:** como `pem.privkey` está presente, o `cert.json` carrega a chave privada. Ele é o payload do
> Redis (necessário para reconstruir os arquivos nos outros nós) e o corpo do webhook. Ver §11.2 e §16.
