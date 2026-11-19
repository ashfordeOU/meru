# Deploying meru

meru runs only on Ashforde's own servers (or a contracted Sovereign install). Nothing in this
directory holds a key; keys live in a key vault and the environment.

## 1. Keys (custody)

There are three keys. None of them is ever on a laptop, in git, in a chat or in a container image.

| Key | What it does | Where it lives | If it leaks |
|---|---|---|---|
| **Vendor licence key** (exists today) | Signs customer licences | AWS KMS (`KSHANA_PRO_SIGNER=kms`, key custody S7-a) | Anyone could mint licences. Rotate: new key, retire the old one in a revocation list signed by the **root** key |
| **meru verdict key** (new) | Signs every verdict | AWS KMS, Ed25519 key (`MERU_SIGNER=kms`) | Anyone could forge verdicts. Rotate: new KMS key, ship its public key to clients, keep the old one trusted for one release |
| **meru lineage seed** (new) | Signs the F1 internal lineage record only | Secrets manager, injected as `MERU_LINEAGE_KEY` | Low impact (internal record); rotate at will |

Create the verdict key (once):

```
aws kms create-key --key-spec ECC_NIST_EDWARDS25519 --key-usage SIGN_VERIFY \
  --description "meru verdict signing" --region eu-central-1
aws kms create-alias --alias-name alias/meru-verdict --target-key-id <key id>
```

Grant the server's instance or task role **only** `kms:Sign` and `kms:GetPublicKey` on that key.
Nobody gets `kms:ScheduleKeyDeletion` day to day. Turn on CloudTrail for the key.

The verdict public key is what customers pin. Print it from the server's first log line
(`key <id>`) or with `aws kms get-public-key`, then:

* build it into Pro releases: `KSHANA_VERDICT_KEY=<64 hex>` at build time (the client then
  needs no `--trust`);
* publish it on the Ashforde site so customers can check a saved verdict independently.

During a rotation set `KSHANA_VERDICT_KEY=<new>,<old>` so both are trusted for one release.

## 2. Revocation list

meru refuses to start in licence mode unless `MERU_REVOCATIONS` points at a signed list (or is
explicitly `none` for development). Build it from the issuance register with the vendor tools:

```
kshana-pro license revocations build --register <register.jsonl> --out revocations.txt
```

Copy it to `/etc/meru/revocations.txt`. meru re-reads it within 30 s of a change. To cancel a
licence: `kshana-pro license revoke <token id>`, rebuild the list, copy it. An older list is
refused, so a list cannot be rolled back to un-revoke a token.

## 3. Environment (`/etc/meru/meru.env`, mode 0600)

```
MERU_SIGNER=kms
MERU_KMS_KEY_ID=alias/meru-verdict
MERU_KMS_REGION=eu-central-1
MERU_LINEAGE_KEY=<from the secrets manager>
MERU_LICENCE_PUBKEY=<vendor licence public key(s), comma separated>
MERU_LICENCE_ROOT_KID=<root key id>
# Limits (defaults shown)
MERU_RATE_PER_MIN=10
MERU_DAILY_QUOTA=200
MERU_PROBE_DISTINCT_PER_HOUR=60
MERU_PROBE_BLOCK_S=3600
MERU_OUTPUT_SIGFIGS=3
```

AWS credentials come from the instance or task role, never from this file.

## 4. Run

* **Plain host:** binary at `/usr/local/bin/meru`, `deploy/meru.service` (systemd, hardened,
  loopback only), `deploy/nginx.conf` in front for TLS and per-address limits.
* **Container:** `deploy/Dockerfile` (build context: a directory holding `meru/` and
  `kshana-pro/`). Push only to a **private** registry. Put it behind a TLS load balancer
  with the same limits as `nginx.conf`.

## 5. Watch

* `meter.jsonl`: one line per call (who, what, outcome, hashes; never request contents). It is
  the billing record and the abuse record. Back it up daily.
* Log lines with `[meru][ALERT]`: a probe pattern (a licence paused), a revocation list that
  failed to load, or a meter write failure. Route them to email or chat.
* A probe alert means someone may be trying to copy a method: review that licence's meter
  lines and decide whether to revoke.

## 6. Before go-live checklist

- [ ] Verdict key in KMS; role has Sign + GetPublicKey only; CloudTrail on
- [ ] Verdict public key built into the Pro release and published
- [ ] Revocation list built from the real register and installed
- [ ] TLS certificate valid; HTTP redirects to HTTPS
- [ ] `[meru][ALERT]` lines routed to a person
- [ ] Meter log backed up
- [ ] Customer terms forbid reverse engineering and systematic querying (legal)
