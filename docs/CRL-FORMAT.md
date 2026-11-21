# Register revocation list: format and offline check

The hosted revocation list of the product register (research backlog E25, B2505, the hosted part).
A register entry says a product was **scored under** a method at a stated version. A revocation
says only that the entry no longer stands. Nothing here describes a product as validated,
approved or certified. Evidence class of the list: `RECORD`.

All hashes are SHA-256 as 64 lowercase hex. Times are UTC `YYYY-MM-DDTHH:MM:SSZ`. **Canonical
JSON** means every object's keys in sorted (byte) order, at every depth, with no whitespace.

## 1. Fetch

`GET /crl` needs no licence and is rate limited per address. The answer is a signed document:

```json
{"service":"<string>","method":"crl","evidence_class":"RECORD","utc":"<UTC>","key_id":"<issuer key id>",
 "verdict":{<list body, §2>},"verdict_sha256":"<hex>","signature":"<128 hex>"}
```

A client reads `service` but does not need to hard-code it.

## 2. List body

```json
{"format":"register-crl/1",
 "issuer_key_id":"<key id>",
 "seq":<number of revocations ever made; never decreases>,
 "this_update":"<UTC>",
 "next_update":"<UTC, this_update + 7 days>",
 "entries":[{"entry_id":"<hex>","product_id":"<id>","scored_under":{"method":"<id>","version":"<id>"},
             "verdict_sha256":"<hex>"|null,"reason":"<reason>","revoked_utc":"<UTC>"}, ...],
 "entries_sha256":"<SHA-256 of canonical(entries)>",
 "statement":"<text>"}
```

* `reason` is one of: `score_withdrawn`, `method_superseded`, `product_changed`,
  `evidence_error`, `key_compromise`, `holder_request`.
* `entry_id` = SHA-256 of `canonical({"method": m, "product_id": p, "version": v})`. A client
  computes it from the entry it holds, for example a scorecard's product and method.
* Entries are sorted by `product_id`, then method, then version.
* The list is re-signed after every revocation and at least once a day.
* Lists signed before `entry_id` existed say `"format":"meru-crl/1"` and have no `entry_id`. A
  client may accept them and compute the IDs itself.

## 3. Offline check

1. **Signature.** `body = canonical({"evidence_class","key_id","method","service","utc","verdict"})`
   taken from the document. Check that `verdict_sha256 = SHA-256(body)` and that `signature` is
   the Ed25519 signature over `body` by the issuer's public key for `key_id`. The keys are
   published at `GET /keys` (see `TLOG-PROOFS.md` §8 on that branch) or pinned out of band.
2. **Type.** `method` must be `crl` and `verdict.format` must be `register-crl/1` (or the legacy
   name above).
3. **Currency.** If now is after `next_update`, the list is stale. Fetch a current one and do not
   treat a stale list as "not revoked".
4. **Integrity.** `entries_sha256` must equal SHA-256 of `canonical(entries)`.
5. **Monotonic.** Keep the last `seq` seen. A list with a lower `seq` is older and must not
   replace a newer one.
6. **Lookup.** The entry is revoked if `entry_id` is in `entries`. Equivalently, match on
   (`product_id`, `method`, `version`).

## 4. Revocation records in the transparency log

When the service keeps a transparency log, each revocation is appended as an entry:

* kind `crl-revocation/1`;
* `pack_sha256` = SHA-256 of `canonical(<the revocation object exactly as in entries>)`;
* `signer_key_id` = the issuer key ID.

The answer to `POST /verdict/crl/revoke` includes:

```
"tlog": {"status":"logged","index":i,"record_sha256":"<hex>","inclusion":{...},"sth":{...}}
```

`status` is `failed` (with `reason`) or `not_kept` when no log is kept. A checker that holds the
log can confirm that every revocation in a list is in the log, and that no logged revocation is
missing from a later list. The proof formats are in `TLOG-PROOFS.md`.

## 5. Revoke (operators only)

`POST /verdict/crl/revoke` requires an operator licence whose token ID is in `MERU_CRL_ADMINS`.
The request body is:

```
{product_id, scored_under:{method,version}, verdict_sha256?, reason, note?}
```

An entry that is already revoked gets 409. The private `note` and the revoking licence are kept
in the service's log and are never published.

## 6. Test vector

[`crl-vector.json`](crl-vector.json) holds `public_key` and `list`, a full signed list with two
revocations (RX-100 `product_changed` and RX-007 `evidence_error`, both scored under
`receiver-scorecard` version 1). It was signed at 2026-11-20T00:00:00Z with a **public test
seed**, not a service key: the 32 ASCII bytes `meru-service-test-key-32-bytes!!`. Values:

* public key `6d8589125c2709100f8eabbf6437a8e8e32e9d92b58ca52e3d7fb5bf851c8c67`
* entry_id of RX-007 / receiver-scorecard / 1:
  `3985058471eec2d893e4e14b6287d8ffd4f0c1cd0b495f92c899f2626351ddf8`
* `entries_sha256` `d3b157a0b46fc37a4d58f99d4aa8f5b3c99c76f716a1846b59af7663cd417331`
* `verdict_sha256` `035b6d115404366e8e77ac53f7d2eb8eb1a6ea630d0e4b723c7e5640d13bc5dd`

Ed25519 is deterministic, so the test `crl::tests::crl_vector` reproduces the file byte for
byte. A checker should verify the list with the public key above and find RX-100 and RX-007
revoked. Its `next_update` is 2026-11-27T00:00:00Z, so a checker must report the list as stale
after that date.
