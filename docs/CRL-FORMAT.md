# Hosted register revocation list

The hosted revocation list of the product register (research backlog E25, B2505, the hosted
part). It is issued **in the open engine's own format, `kshana.register-crl/1`** (defined in the
open engine's product register and its `docs/PRODUCT-REGISTER.md`). The open register tools
therefore read it unchanged:

```
kshana register crl-check crl.json --key <issuer public key hex>
kshana register view register.json --crl crl.json --crl-key <issuer public key hex> --date YYYY-MM-DD
```

A register entry says a product was scored under a method. A revocation says only that the entry
no longer stands. Nothing here describes a product as validated, approved or certified.

## 1. Fetch

`GET /crl` needs no licence and is rate limited per address. The answer is the signed document
itself. It has no envelope and no extra fields, and is served as compact JSON.

## 2. Document (as defined by the open format; summarised here)

The fields appear in this order and no others are allowed:

```json
{"schema":"kshana.register-crl/1",
 "issuer":"<who issues it, free text>",
 "issued":"YYYY-MM-DD",
 "next_update":"YYYY-MM-DD",
 "revoked":[{"id":"<register entry id>","revoked":"YYYY-MM-DD","reason":"<text>"}, ...],
 "signer":"<issuer Ed25519 public key, 64 lowercase hex>",
 "signature":"<Ed25519 signature, 128 lowercase hex>"}
```

* `id` is the register entry's id: 1 to 128 of letters, digits, `.`, `-` and `_`. The register
  publisher chooses it. It refers to an entry in the separate signed register document.
* `revoked` is the date from which the revocation applies.
* `reason` is free text in the open format. This service always writes one of: `score withdrawn`,
  `method superseded`, `product changed`, `evidence error`, `key compromise`, `holder request`.
* **Signature:** Ed25519 (RFC 8032, pure) over the UTF-8 bytes of `kshana.register-crl/1\n`,
  followed by the compact JSON of the document in the field order above, with `signature` set to
  `""` (the field stays present).
* After `next_update`, a reader reports the list as stale, but its revocations still apply. A
  revocation dated after the view date does not apply yet. The reader checks against an issuer
  key it is **given**, and a list signed by any other key is refused.

## 3. This service as issuer

* **Issuer key:** the service's verdict key. It is published with its validity period and history
  at `GET /keys` (see `TLOG-PROOFS.md` §8). Pin it out of band and pass it as `--key` /
  `--crl-key`.
* **Issuer name:** `issuer` is `MERU_CRL_ISSUER`, printable ASCII only. Until the name is set it is
  "Product register revocation list (issuer name to confirm)".
* **Dates:** `issued` is the current UTC date and `next_update` is seven days later. The document
  is re-issued after every revocation and on each new UTC day.
* **Order:** revocations are listed in the order they were made.
* **Nothing else in the document:** sequence numbers and hashes do not go in the document (the
  open format refuses unknown fields). They are returned beside it and recorded in the
  transparency log (§5).

## 4. Revoke (operators only)

`POST /verdict/crl/revoke` requires an operator licence whose token ID is in `MERU_CRL_ADMINS`.
Other licences get 403. The request is:

```json
{"id":"<register entry id>","revoked":"YYYY-MM-DD (optional, default today)",
 "reason":"score_withdrawn|method_superseded|product_changed|evidence_error|key_compromise|holder_request",
 "note":"<private, at most 500 characters, optional>"}
```

* An id that is already revoked gets 409. A bad id, date or reason gets 422.
* Each revocation is appended to `MERU_CRL_LOG` (JSON Lines, append-only, never edited), together
  with the reason code, the revoking licence, the time and the private note. The licence and the
  note are never published.
* The call is metered.

The answer is:

```json
{"revoked":{"id","revoked","reason"},"crl":<the new signed document>,"crl_sha256":"<SHA-256 of the document as served>",
 "seq":<number of revocations>,"tlog":{...}}
```

## 5. Revocations in the transparency log

When a transparency log is kept (`MERU_TLOG_PATH`), each revocation is appended as an entry:

* kind `crl-revocation/1`;
* `pack_sha256` = SHA-256 of the revocation's compact JSON
  `{"id":"…","revoked":"…","reason":"…"}`, exactly as it appears in the document;
* `signer_key_id` = the service key ID.

The answer's `tlog` is one of:

* `{"status":"logged","index","record_sha256","inclusion","sth"}`;
* `{"status":"failed","reason","record_sha256"}`, where the revocation still stands;
* `{"status":"not_kept"}`.

Anyone holding the log can confirm that each revocation in a list was logged, and that a later
list has not dropped a logged one. The proof formats are in `TLOG-PROOFS.md`.

## 6. Test vector

[`crl-vector.json`](crl-vector.json) is the open format's vector. The test
`crl::tests::the_open_format_vector_is_reproduced` checks it in three ways:

* this service's issuing reproduces it byte for byte, including the signature;
* the reader here accepts it;
* the stale, not-yet-applicable, other-key, tampered and extra-field cases behave as described
  above.

The vector's values are:

* **Seed:** a public test seed, not a service key. It is SHA-256 of
  `"register crl test vector"` = `0fbb7a1b9ce44b011a943e06b980ba5b3dfc3ffecb514a9e37602b182aef09c7`.
* **Public key:** `a028f6212dcbd196a38fe8e13927a9d997f4d72ab00341276b9437d8f2273a8d`.
* **SHA-256 of the signing bytes:** `2852716a734dead2a0086f51242861c964d63f99f7ff93165277cbb8caaabb4b`.
