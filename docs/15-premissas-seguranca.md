## 15. Premissas de segurança (registradas)

- O Redis trafega em **rede overlay criptografada**; por decisão de projeto **não** se usa TLS nem cifragem
  de payload. Consequência: `cert.json` (com chave privada) transita em claro dentro dessa rede — a segurança
  depende inteiramente do isolamento/criptografia da overlay.
- Cada URL do webhook recebe, por padrão, o `cert.json` **completo, com chave privada**. Use
  `TCERTS_WEBHOOK_REDACT_KEY=true` para redigir `pem.privkey` do corpo enviado a **todas** as URLs, e/ou
  endpoints confiáveis (HTTPS + Bearer) quando apropriado. Atenção: `TCERTS_WEBHOOK_URL` aceita scheme
  `http` além de `https`; ao usar `http://` (típico de testes locais / loopback) sem redação, a chave
  privada trafega em claro fora da rede overlay — avaliar explicitamente este risco.
