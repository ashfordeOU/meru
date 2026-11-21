# Transparency log: proof format for offline verification

The format of everything the transparency log (`/tlog/`) publishes, and how an open verifier checks
it with no access to the service. Research backlog E25, B2502. Evidence class of every log output:
`RECORD`. An entry shows that a hash was submitted at a time and has been in the log since. It
says nothing about whether the pack or calibration record is correct.

All hashes are SHA-256, written as 64 lowercase hex characters. All times are UTC, written as
`YYYY-MM-DDTHH:MM:SSZ`.

## 1. Entries and leaf data

An entry is the hash of one evidence pack or one calibration record:

```json
{"pack_sha256":"<64 hex>","kind":"<1..64 of A-Z a-z 0-9 . _ - / :>","signer_key_id":"<id>"|null,"logged_utc":"<UTC>","class":"evidence_pack"|"calibration_record"}
```

* `class` was added with the daily root. An entry logged without one has no `class` key at all,
  so the leaf data of older entries is unchanged. If `class` is absent, read the entry as
  `evidence_pack`, except entries whose `kind` is `crl-revocation/1`: those are revocation
  records (the SHA-256 of a revocation-list entry) and are read by kind.
* The **leaf data** is the entry's JSON with no whitespace and the keys **in exactly this
  order**: `pack_sha256`, `kind`, `signer_key_id`, `logged_utc`, then `class` if present.
  `signer_key_id` is always present and may be `null`. Strings use serde_json escaping: `"` and
  `\` are escaped, control characters are written as `\u00XX`, and non-ASCII is left as UTF-8.
  The allowed characters never need escaping.
* `GET /tlog/entry?index=N` returns `{"index":N,"entry":{...},"leaf_hash":"<hex>"}`. The JSON
  object in that answer has sorted keys. Do not hash it as it arrives: rebuild the leaf data in
  the order above.

## 2. Tree hash (RFC 6962 §2.1, RFC 9162 §2.1.1)

```
leaf_hash(d)      = SHA-256(0x00 ‖ d)
node(l, r)        = SHA-256(0x01 ‖ l ‖ r)
MTH([])           = SHA-256("")
MTH([d0])         = leaf_hash(d0)
MTH(D[0:n]), n>1  = node(MTH(D[0:k]), MTH(D[k:n])), k = largest power of two < n
```

On top of the tree is a hash chain:

```
chain(-1) = 32 zero bytes
chain(i)  = SHA-256(0x02 ‖ chain(i-1) ‖ leaf_hash(i))
```

The **chain head** of size `n` is `chain(n-1)`, or 32 zero bytes when `n = 0`. The chain is a
second, independent commitment to the order of entries. A verifier that does not need it can
ignore it.

## 3. Signed tree head: `GET /tlog/sth`

Every signed object is a signed verdict:

```json
{"service":"meru/1","method":"tlog-sth","evidence_class":"RECORD","utc":"<UTC>","key_id":"<id>",
 "verdict":{...},"verdict_sha256":"<hex>","signature":"<128 hex>"}
```

**Signature check.** Build the canonical body:

```
JSON {"evidence_class","key_id","method","service","utc","verdict"}
```

Write it with every object's keys in sorted (byte) order at every depth, and no whitespace.
Then check:

* `verdict_sha256 = SHA-256(body)`.
* `signature` is the Ed25519 signature over `body`, made by the service's published public key
  for `key_id` (§8).

Integers are written without a fraction. The log objects contain no floats.

The STH `verdict` (format `meru-tlog-sth/1`):

```json
{"format":"meru-tlog-sth/1","log_key_id":"<id>","size":<n>,"root_hash":"<hex>","chain_head":"<hex>",
 "timestamp_utc":"<UTC>","merkle":"<text>","statement":"<text>",
 "anchors":[{"authority":"<name>","status":"not_anchored", ...}, {...}]}
```

The anchors are placeholders and send nothing (`MERU_TLOG_ANCHORS`). The time-stamped object is
the daily root (§6).

## 4. Inclusion proof: `GET /tlog/proof?index=i[&size=n]`

```json
{"index":i,"size":n,"leaf_hash":"<hex>","root_hash":"<hex of MTH(D[0:n])>","path":["<hex>", ...]}
```

`POST /verdict/tlog/append` also returns this object as `inclusion`, with `size` equal to the size
at that moment, next to the signed tree head of that size.

**Verify** (RFC 9162 §2.1.3.2):

1. Recompute `leaf_hash` from the entry's leaf data (§1).
2. If `i >= n`, fail. Set `fn = i`, `sn = n - 1`, `r = leaf_hash`.
3. For each `p` in `path`:
   * If `sn == 0`, fail.
   * If `LSB(fn)` is set or `fn == sn`:
     * Set `r = node(p, r)`.
     * If `LSB(fn)` is not set, repeat `fn >>= 1; sn >>= 1` until `LSB(fn)` is set or `fn == 0`.
   * Otherwise set `r = node(r, p)`.
   * Then `fn >>= 1; sn >>= 1`.
4. Pass if `sn == 0` and `r` equals the `root_hash` of a tree head you trust (an STH whose
   signature you checked, or a daily root) for the same `n`.

## 5. Consistency proof: `GET /tlog/consistency?from=m&to=n`

```json
{"from":m,"to":n,"from_root":"<hex>","to_root":"<hex>","path":["<hex>", ...]}
```

`1 <= m <= n <= size`. If `m == n`, `path` is empty and the two roots are equal. The path is
RFC 9162 `SUBPROOF(m, D[0:n], true)`.

**Verify** (RFC 9162 §2.1.4.2):

1. If `m == n`, pass only if `path` is empty and the roots are equal.
2. If `m` is a power of two, prepend `from_root` to `path`.
3. Set `fn = m - 1` and `sn = n - 1`. While `LSB(fn)` is set, do `fn >>= 1; sn >>= 1`.
4. Set `fr = sr = path[0]`.
5. For each `c` in `path[1:]`:
   * If `sn == 0`, fail.
   * If `LSB(fn)` is set or `fn == sn`:
     * Set `fr = node(c, fr)` and `sr = node(c, sr)`.
     * If `LSB(fn)` is not set, repeat `fn >>= 1; sn >>= 1` until `LSB(fn)` is set or `fn == 0`.
   * Otherwise set `sr = node(sr, c)`.
   * Then `fn >>= 1; sn >>= 1`.
6. Pass if `sn == 0`, `fr == from_root` and `sr == to_root`. Both roots must match tree heads you
   already trust.

## 6. Daily root and time-stamps: `GET /tlog/daily?date=YYYY-MM-DD`

The daily root is given only for a completed UTC day, one before the day of the request. It is
the log as it stood at the end of that day. The **daily root object** (format
`meru-tlog-daily-root/1`):

```json
{"chain_head":"<hex>","date":"YYYY-MM-DD","format":"meru-tlog-daily-root/1","log_key_id":"<id>",
 "root_hash":"<hex>","size":<n>}
```

* `size` is the number of entries whose `logged_utc` is before `date + 1 day, 00:00:00Z`.
* `root_hash = MTH(D[0:size])`.
* `chain_head` is the chain head of `size`.
* The **stamped bytes** are this object's canonical JSON: keys sorted, no whitespace, exactly as
  written above.

The answer is a signed verdict (method `tlog-daily-root`, evidence class `RECORD`) whose
`verdict` is:

```json
{"daily_root":{...},
 "daily_root_sha256":"<SHA-256 of the stamped bytes>",
 "anchoring":"QTSP anchoring: interface built, no provider configured" | "<text>",
 "statement":"<text>",
 "timestamps":[
   {"authority":"<name>","status":"stamped"|"token_invalid",
    "gen_time_utc":"<UTC>","token_sha256":"<hex>","token_der_base64":"<base64>",
    "verified_against_configured_anchor":true|false,"reason":null|"<text>"},
   {"authority":"<name>","status":"failed","reason":"<text>"}
 ]}
```

With no authority configured, `timestamps` is `[]` and `anchoring` is the text shown above. A
token is stamped once per authority per day and kept (`<log>.daily/<date>.<authority>.tsr`).
Later requests return the kept token.

**Verify a daily root offline:**

1. Check the signed verdict's signature (§3).
2. Rebuild the stamped bytes from `daily_root` and check `daily_root_sha256`.
3. Check that `root_hash` is consistent with any tree head you hold, using a consistency proof
   from `size` to that head's size (§5). An inclusion proof against `root_hash` with `size` (§4)
   shows an entry was in the log by the end of that day.
4. For each timestamp, base64-decode `token_der_base64`. It is a DER `TimeStampResp` (RFC 3161
   §2.4.2) whose token is CMS SignedData. Check:
   * status granted;
   * `TSTInfo.messageImprint` = SHA-256 of the stamped bytes (hash algorithm id-sha256,
     2.16.840.1.101.3.4.2.1);
   * the CMS signature over the signed attributes;
   * the messageDigest attribute equals the hash of the encapsulated TSTInfo;
   * the ESS signing-certificate (v1 or v2) attribute names the signer certificate;
   * the signer certificate has critical extended key usage `timeStamping` and nothing else;
   * the chain from the signer certificate to the authority's root, which you obtain from the
     authority itself, not from this service;
   * validity at `genTime`.

   `openssl ts -verify -data <stamped bytes file> -in <token.tsr> -CAfile <authority root>`
   performs the same checks. The service checked each token against its configured anchor
   before keeping it (`verified_against_configured_anchor`). That check is information, not a
   substitute for your own.
5. The request had `certReq` TRUE and a nonce equal to the first 8 bytes of the stamped bytes'
   SHA-256, read as a big-endian unsigned integer. The token echoes that nonce, so a verifier
   may also check it.

**What a time-stamp means:** the authority states that the daily root's hash existed at
`genTime`. It says nothing about any pack.

**QTSP anchoring: interface built, no provider configured.** Which authorities is a contract for
the owner. Configuration is `MERU_TLOG_TSA_{1,2}_URL` (https) with `MERU_TLOG_TSA_{1,2}_ANCHOR`
(a PEM of the authority's root) and optional `_NAME`.

## 7. Test vectors

### 7.1 RFC 6962 (Certificate Transparency reference suite)

The leaf data (hex) is the following eight values:

* `""`
* `00`
* `10`
* `2021`
* `3031`
* `40414243`
* `5051525354555657`
* `606162636465666768696a6b6c6d6e6f`

| size | MTH(D[0:size]) |
|---|---|
| 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| 1 | `6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d` |
| 2 | `fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125` |
| 3 | `aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77` |
| 4 | `d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7` |
| 5 | `4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4` |
| 6 | `76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef` |
| 7 | `ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c` |
| 8 | `5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328` |

**Inclusion of index 0 in size 8.** The path is:

* `96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7`
* `5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e`
* `6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4`

**Consistency from size 6 to size 8.** The path is:

* `0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a`
* `ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0`
* `d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7`

The test `tlog::tests::rfc_6962_reference_vectors` asserts all of these.

### 7.2 This log's entries

[`tlog-vectors.json`](tlog-vectors.json) holds five entries (`pack_sha256` = SHA-256 of
`"vector i"`, `signer_key_id` `kid-vector`, `logged_utc` `2026-11-20T0i:00:00Z`). The classes
are, in order:

1. none
2. `evidence_pack`
3. `calibration_record`
4. `evidence_pack`
5. `calibration_record`

For each entry the file gives the exact leaf data string and leaf hash. It also gives:

* `root_3` and `root_5`;
* `chain_head_5`;
* the inclusion proof of index 2 in size 5;
* the consistency proof from size 3 to size 5.

The test `tlog::tests::meru_entry_vectors` asserts the file byte for byte, so a change to the leaf
encoding breaks the build.

Excerpt:

```
leaf 0 data  {"pack_sha256":"b5ad45dc932b245a2f88f729ce30a4a098c868bd549de8bf8d8641b37a5e8501","kind":"kshana-dossier/1","signer_key_id":"kid-vector","logged_utc":"2026-11-20T00:00:00Z"}
leaf 0 hash  daa5dec9e6bf803f06455afa747f80fae39ca14922ae8e91cbcad4263ef36898
root_5       cb451fcf8acd96d640384218c8ab28380398dcf5850465fd72448e5bff545e94
inclusion 2 in 5: leaf 865fb9be…3a125, path [806a222d…ae95e, c42db437…f0594, 268fa698…5682f]
consistency 3 → 5: from_root 6ecd73fa…58276, path [865fb9be…3a125, 806a222d…ae95e, c42db437…f0594, 268fa698…5682f]
```

### 7.3 Time-stamp tokens

Static token vectors are not published because the synthetic authority's keys are generated on
every run and no key is kept. To produce tokens for a verifier's own tests, use the same recipe
as `src/tlog_tsa_synthetic.rs`:

1. With OpenSSL, create a P-256 test CA (critical basicConstraints CA:TRUE).
2. Create a TSA certificate signed by it, with critical keyUsage digitalSignature and critical
   extendedKeyUsage timeStamping.
3. Run `openssl ts -reply` with `signer_digest = sha256` and `ess_cert_id_alg = sha256` on the
   query.

The end-to-end test `end_to_end_daily_root_timestamped_by_two_synthetic_authorities` checks each
token against its own CA and over the stamped bytes. It also checks that a token fails over other
bytes and against the other authority's CA.

## 8. The service's verification keys: `GET /keys`

Public, read-only and rate limited per address. The answer is a signed verdict (method
`service-keys`, evidence class `RECORD`), signed with the current key. Its `verdict` is:

```json
{"format":"meru-service-keys/1","current_key_id":"<id>",
 "keys":[{"key_id":"<id>","algorithm":"Ed25519","public_key":"<64 hex>","not_before":"<UTC>",
          "not_after":"<UTC>"|null,"status":"current"|"retired","endorsed_by_previous_key":true|false}, ...],
 "history":[<history line>, ...],
 "history_head_sha256":"<hex>"}
```

A key verifies verdicts whose `utc` falls in `[not_before, not_after)`. `not_after` is null for the
current key. Without a key history (`MERU_KEY_HISTORY` unset), `keys` holds only the current key
with null validity, `history` is `[]`, and a `note` says so.

**History line.** The history is kept as JSON Lines, append-only, one line per key in order:

```json
{"record":{"format":"meru-key-history/1","seq":k,"key_id":"<id>","algorithm":"Ed25519",
           "public_key":"<64 hex>","not_before":"<UTC>","previous_key_id":"<id>"|null,
           "previous_record_sha256":"<hex; 64 zeros for seq 0>"},
 "record_sha256":"<hex>","signature":"<128 hex>","previous_key_endorsement":"<128 hex>"|null}
```

**Verify the history:**

1. For each line, `record_sha256 = SHA-256(canonical(record))`. The canonical form has sorted
   keys and no whitespace.
2. `seq` runs 0, 1, 2, … and each `previous_record_sha256` equals the previous line's
   `record_sha256`.
3. `signature` is the Ed25519 signature by the record's own `public_key` over
   `canonical(record)`. This shows the service held that key.
4. For `seq > 0`:
   * `previous_key_id` equals the previous record's `key_id`, and `not_before` is later than the
     previous record's.
   * If `previous_key_endorsement` is present, it is the Ed25519 signature by the **previous**
     record's `public_key` over the canonical JSON of the following statement:

     ```json
     {"format":"meru-key-endorsement/1","next_key_id":"<this key_id>",
      "next_public_key":"<this public_key>","previous_key_id":"<previous key_id>"}
     ```

     An endorsed rotation is a chain of custody from the key you already trust. A null
     endorsement means the rotation was not endorsed. It is recorded as such, so it stays
     visible.
5. A key ID or public key never appears twice.
6. Each key's `not_after` is the next record's `not_before`. The last record is the current key.

**Trust.** Pin the first key, or any key, through a channel other than this service: a
published fingerprint or a contract annex (to confirm). Then follow endorsed rotations from
it. `history_head_sha256` lets two parties compare the history they hold.

**Operation.**
* At start, with `MERU_KEY_HISTORY` set, the service appends a record if its key is not the
  last one in the history.
* It refuses to start if the history does not verify, if a retired key or key ID comes back, or
  if `MERU_KEY_ENDORSEMENT` does not verify.
* To endorse at a rotation, run `meru key-endorse --next-public-key <hex> --next-key-id <id>`
  with the **outgoing** key's signer settings. Give the printed signature to the new deployment
  as `MERU_KEY_ENDORSEMENT`.
* The calibration lineage key signs only an internal record and is not published here.

**Test vectors.** [`key-history-vectors.jsonl`](key-history-vectors.jsonl) holds a two-record
history: key A (`not_before` 2026-01-01T00:00:00Z), then key B (`not_before`
2026-06-01T00:00:00Z) endorsed by A. These are public test keys with seeds SHA-256 of
`"meru keys test a"` and SHA-256 of `"meru keys test b"`. They are not service keys. Ed25519 is
deterministic, so the test `keys::tests::key_history_vectors` reproduces the file byte for byte.
