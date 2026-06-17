## 10. `cert-get` — utilitário

Invocação: `cert-get <FQDN> <DIR_DESTINO>`  (`$1` = FQDN, `$2` = diretório de destino).

Missão: localizar o **certificado válido mais recente** que atenda ao FQDN e gravar seus arquivos
**achatados** em `$2`.

### 10.1 Fontes e seleção

- Consultar **Redis** (se `TCERTS_REDIS_URL` definido) **e** `$TCERTS_SAVEDIR`.
- "Válido e utilizável": `not_before_unix <= now_unix <= not_after_unix` (ambos inclusivos).
- Ordem de preferência:
  1. **Match exato:** algum certificado cujos `sans` contenham **exatamente** o FQDN pedido. Entre os válidos,
     escolher o de **maior `not_after`**.
  2. **Fallback wildcard:** algum certificado cujos `sans` contenham um wildcard que **cubra** o FQDN.
     Semântica: `*.example.com` cobre `app.example.com`, mas **não** `a.b.example.com` nem o ápice
     `example.com`. Entre os válidos, maior `not_after`.
- Se Redis e local divergirem, vence o de maior `not_after`.
- Resiliência: se o Redis estiver configurado mas inacessível, logar aviso no `stderr` e **prosseguir só com o
  local**; só falhar se nenhum certificado utilizável for encontrado em fonte alguma.

### 10.2 Saída

- **`$2` deve já existir**; `cert-get` **não cria diretórios** (nem `$2`, nem subdiretórios). Se `$2` não
  existir → erro.
- Gravar em `$2` (achatado): `fullchain.pem`, `cert.pem`, `chain.pem`, `privkey.pem`, `cert.md5`, `cert.json`
  (escrita atômica; `privkey.pem`/`cert.json` em `0600`).
- **Sucesso:** exit `0`; imprimir no `stdout` um resumo: FQDN casado, fonte (`redis`/`local`), `not_after`.
- **Falha:** exit `1`; mensagem detalhada do motivo no `stderr` (FQDN não encontrado, todos expirados, `$2`
  inexistente, falha de escrita etc.).
