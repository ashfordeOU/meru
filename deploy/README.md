# Deploying meru

meru runs only on Ashforde's own servers, inside Arksa's cloud, or as a contracted instance beside a
Sovereign install (section 7: deployment profiles). Nothing in this
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
# Anti-extraction (README "Anti-extraction")
MERU_FINGERPRINT_KEYS=/etc/meru/fp-keys.json   # meru fingerprint-keys rotate /etc/meru/fp-keys.json
MERU_RATE_PER_IP_PER_MIN=60
MERU_AUDIT_DELAY_MS=3000
```

The fingerprint key file holds every epoch ever used: back it up with the secrets, never prune
it (ownership tests of old verdicts need the old epochs).

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
* `extraction_alert` and `honeypot` meter lines: a sweep (one licence or several together) or a
  probe of internal-looking paths. The licence's verdicts are delayed for 24 h. Review, then
  revoke or clear; `meru ownership` tests suspect numbers found elsewhere.

## 6. Before go-live checklist

- [ ] Verdict key in KMS; role has Sign + GetPublicKey only; CloudTrail on
- [ ] Verdict public key built into the Pro release and published
- [ ] Revocation list built from the real register and installed
- [ ] TLS certificate valid; HTTP redirects to HTTPS
- [ ] `[meru][ALERT]` lines routed to a person
- [ ] Meter log backed up
- [ ] Customer terms forbid reverse engineering and systematic querying (legal)
- [ ] Customer terms disclose verdict fingerprinting and query auditing (before `MERU_FINGERPRINT_KEYS` is set)
- [ ] Fingerprint key file created, backed up with the secrets

## 7. Deployment profiles (`MERU_PROFILE`)

Sections 1–6 describe the **public** profile (the default): the internet-facing service for
Kshana Pro customers behind nginx. The same binary runs in two more profiles (README
"Deployment profiles and the service credential"). Unknown values stop the service at start.

### 7a. `arksa-internal`: next to Arksa in Arksa's cloud

* **Network.** Private network only, no public endpoint, no public load balancer, no public DNS
  name. meru refuses to start on a public listen address; `0.0.0.0` is allowed with a warning for
  a container whose network the orchestrator keeps private. Two shapes:
  * **Sidecar / same host:** `MERU_ADDR=127.0.0.1:8099`; Arksa calls `http://127.0.0.1:8099`
    (the Arksa client accepts plain HTTP on loopback only).
  * **Separate internal host or pod:** meru on a private address (`MERU_ADDR=10.x.y.z:8099`,
    or `0.0.0.0:8099` inside a private-only network); TLS on the private network with an
    internal certificate authority, for example an nginx that listens only on the private
    interface (below). Arksa calls `https://meru.<internal zone>` and trusts the internal CA.
    Firewall / security group: inbound 443 (or 8099) from Arksa's service subnet only.
* **Do not** reuse `deploy/nginx.conf` as is: it is the public front (port 80/443 on every
  interface, certbot certificates). For the internal front, bind to the private address and
  drop the public redirect:

  ```
  server {
      listen 10.0.5.10:443 ssl;            # private interface only
      server_name meru.internal.example;    # internal DNS only
      ssl_certificate     /etc/meru/tls/internal.crt;   # issued by the internal CA
      ssl_certificate_key /etc/meru/tls/internal.key;
      client_max_body_size 4m;              # batches; match MERU_MAX_BODY
      allow 10.0.4.0/24;                    # Arksa's service subnet
      deny  all;
      location = /health { proxy_pass http://127.0.0.1:8099; }
      location /verdict/ {
          limit_except POST { deny all; }
          proxy_pass http://127.0.0.1:8099;
          proxy_http_version 1.1;
          proxy_set_header Connection "";
          proxy_request_buffering on;
          proxy_read_timeout 620s;
      }
      location / { return 404; }
  }
  ```

* **Keys.** The same three keys as section 1. The verdict key may be the public service's KMS key
  (Arksa then pins the same public key) or a separate KMS key for the internal instance (Arksa
  pins that one); a separate key keeps the two instances' verdicts apart.
* **Credential.** One service credential (README, "Service credential"), issued into the vendor
  register with `--feature meru-service:arksa --product service`, delivered to Arksa through its
  secret store (never in a repository or an image). meru needs only the vendor public key(s)
  (`MERU_LICENCE_PUBKEY`) and the signed revocation list (`MERU_REVOCATIONS`), exactly as public.
* **Environment** (in addition to section 3; anti-extraction settings other than the audit
  window are not needed, fingerprint keys are not used for the service credential):

  ```
  MERU_PROFILE=arksa-internal
  MERU_ADDR=127.0.0.1:8099                # or the private address
  MERU_SERVICE_CLIENTS=arksa
  MERU_SERVICE_RATE_PER_MIN=600
  MERU_TENANT_TAG=plain                   # Arksa's own cost data
  MERU_MAX_BODY=4194304                   # room for recalibration batches
  MERU_BATCH_MAX=16
  ```

* **Metering.** The meter log is Arksa's cost record per tenant and mission:
  `meru meter summary --log /var/lib/meru/meter.jsonl --from <unix> --to <unix> --json`. Back it
  up like the public one.
* **Watch.** `audit (record only, service credential)` stderr lines and `extraction_alert` meter
  lines with `"service":"arksa"` are information, not alerts: Arksa's design sweeps look like
  extraction. Route `[meru][ALERT]` lines as in section 5 (revocation list, meter write).

### 7b. `sovereign-contracted`: alongside a Sovereign install

A contracted instance of this same binary beside a Sovereign Arksa install. Where it runs and who
administers it is set by the contract; meru is never compiled into Arksa. Same network rules as 7a
(private network only; meru refuses a public listen address).

Provisioning, per contracted instance (done by Ashforde, the vendor):

1. **Verdict key.** A key for this instance only: an Ed25519 key in the customer's KMS/HSM if the
   contract provides one (`MERU_SIGNER=kms`), otherwise a seed generated for the instance and
   handed over in the customer's secret store (`MERU_KEY`). Record its public key; the Sovereign
   Arksa install pins it (`ARKSA_VERDICT_KEY`).
2. **Lineage seed.** A fresh `MERU_LINEAGE_KEY` for the instance.
3. **Service credential.** Issue one token per instance into the vendor register:
   `--licensee "<customer> Sovereign (meru service)" --product service --feature
   meru-service:arksa --days <contract term or less>`. The register note names the contract.
   Delivered to the customer's Arksa through their secret store.
4. **Vendor public key(s)** (`MERU_LICENCE_PUBKEY`, `MERU_LICENCE_ROOT_KID`), as public.
5. **Revocation list.** Build it from the register (`kshana-pro license revocations build`) and
   install it at `MERU_REVOCATIONS`.
6. **Environment:** `MERU_PROFILE=sovereign-contracted`, `MERU_TENANT_TAG` as the contract says
   (default `hashed`; `plain` if the contract allows tenant names in the meter log; `off` if it
   allows none), `MERU_ADDR` on the private network.

**Revocation lists offline.** An air-gapped or offline install receives the signed list as a file
(removable media or the customer's transfer process). Copy it over `MERU_REVOCATIONS`; meru checks
the file every 30 s, verifies its signature against the vendor keys, and refuses a list older than
the one in force, so a list cannot be rolled back. The vendor sends a new list when a credential is
rotated or revoked and at the interval the contract sets; the start line and the
`revocation list <n> loaded` stderr line show the sequence in force. Credential rotation before
expiry: issue the next token, deliver it, then revoke the old token ID in the next list.

**Metering** stays on: the meter log on the instance is the usage record the contract refers to
(`meru meter summary` per tenant and method). Whether and how it is reported back to Ashforde is
set by the contract.

**Updates.** A new meru release is a new stripped binary or image (section 4) delivered through the
contract's update path; keys, credential and revocation list stay in place.
