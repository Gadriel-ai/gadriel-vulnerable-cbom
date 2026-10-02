# Expected findings — ground truth

Every expectation below was derived by reading the real detection
logic in a `preflight` checkout (branch `integrate/worktree-cleanup-2026-10`,
2026-10-02):
`gadriel-crypto-inventory/src/{material,protocol_scan,library_scan,policy,scoring,registry}.rs`
and `gadriel-scanners-sast/src/crypto_source_scan.rs`. Where a fixture
exercises a documented gap or a naming mismatch, that is called out —
this file is a ground-truth reference, not an aspirational spec.

## Tier 1 — `tier-1-material-basics/keys/`

| File | Expected asset(s) | Notes |
|---|---|---|
| `rsa2048_private_unencrypted.pem` | `RSA-2048` algorithm + private-key material, both `Resolved` | Classical strength 112 bits; quantum-vulnerable (Shor), not classically weak → `QuantumVulnerableUnscored` absent overlay, `Tier 1` with the repo's overlay (see tier 6) |
| `rsa1024_private_weak.pem` | `RSA-1024` algorithm + private-key material | Classically weak (below 112-bit strength) **and** quantum-vulnerable → `Tier0FixNow` wins (classically-weak takes priority per `scoring.rs`) |
| `ec_p256_private.pem` | EC private-key material, curve `nist/P-256` | Algorithm name emitted is **`ECDSA-P-256`** (hyphenated) — the D-12 registry's row is `ECDSA-P256` (no hyphen). **Documented gap**: this asset is `Unrated`, not quantum-vulnerable, until the naming is reconciled. |
| `ed25519_private.pem` | `Ed25519` algorithm + private-key material | Matches registry row `Ed25519` exactly → quantum-vulnerable, not classically weak → `Tier 3` with the repo's overlay |
| `dsa1024_private.pem` | Unresolved private-key material (`DSA PRIVATE KEY` PEM label) | `material.rs` deliberately does not parse DSA key fields in P0 — inventoried, `unresolved += 1` |
| `encrypted_private_key.pem` | `KeyMaterial`, `encrypted: true`, `Resolution::Partial` | `ENCRYPTED PRIVATE KEY` label — D-4 never attempts decryption; no algorithm claimed |
| `self_signed_expired_cert.pem` | Certificate, `self_signed: true`, `role: TrustAnchor` | `not_after` is 2020-02-01 — `evaluate_operational` emits a **High**-severity `CODE-W4-CRYPTO-2xx` expired-certificate finding |
| `self_signed_expiring_soon_cert.pem` | Certificate, expires ~10 days after generation | `evaluate_operational` emits a **Medium**-severity expiring-within-30-days finding |
| `certificate_request.csr.pem` | Unresolved related-crypto-material, format `"CSR"` | CSR fields are not extracted in P0 |
| `keystore_placeholder.jks` | Unresolved `KeyMaterial`, format `"JKS"` | Magic-byte sniff only; bag parsing is P1+ |
| `authorized_keys` | `KeyMaterial` (public), algorithm `Ed25519` | OpenSSH public-key line, `Resolution::Partial` |
| `id_ed25519_openssh` | `KeyMaterial` (private), `encrypted: false` | `openssh-key-v1` envelope, cipher `none` |
| `id_ed25519_openssh_encrypted` | `KeyMaterial` (private), `encrypted: true` | Cipher name != `none` in the outer envelope |
| `jwk_private_ec.json` | `KeyMaterial` (private, since `"d"` is present), format `"JWK"` | `kty: EC` → `ECDSA-P-256` algorithm ref (same naming-gap caveat as above) |

## Tier 2 — `tier-2-source-api/`

**Java** (`CryptoDemo.java`): `MD5`/`SHA1` weak digests; `DES`/`3DES`
weak ciphers (classically weak via the registry's `3DES`/`DES` rows
once the policy layer normalizes — see note below); `AES-GCM` and
`SHA-256` strong, no finding; `KeyPairGenerator.getInstance("RSA")`
resolves to bare `"RSA"` with `classical_bits: None` (the documented
receiver-chain gap — `.initialize(2048)` is never correlated);
`PBEWithMD5AndDES` weak PBE; `PBKDF2WithHmacSHA256` strong;
`SHA1withRSA` → `RSA-SHA-1`; `SHA256withRSA` → `RSA-SHA-256`;
`Signature.getInstance("Ed25519")` → bare `Ed25519`, joins the
cross-arm Ed25519 component.

> **Note on Java's `Cipher.getInstance("DES/ECB/...")`/`"DESede/CBC/..."`:**
> `parse_java_transformation` emits names `DES-ECB`/`3DES-CBC` (with
> the mode suffix) — these do **not** exact-match the registry's bare
> `DES`/`3DES` rows, so they land `Unrated`, not `Tier0FixNow`. Another
> documented naming-granularity gap, not a bug in this test repo.

**Python** (`weak_crypto.py`): `hashlib.md5`/`sha1` weak (name-based);
`hashlib.new("sha1")` weak (arg-based); `DES.new`/`ARC4.new` weak
name-based, matching the registry's bare `DES`/`RC4` rows exactly;
`RSA.generate(2048)` → bare `"RSA"` (no size, same gap as Java);
`hmac.new(key, msg, "sha1")` → `HMAC-SHA-1` (literal arg, resolves);
`hmac.new(key, msg, hashlib.sha256)` → **`Unresolved`** (variable
digestmod, by design). `out_of_scope_patterns.py`'s `jwt.encode(...)`
calls produce **no asset at all, not even Unresolved** — `jwt.encode`
has no entry in `crypto_source_scan.rs`'s table. This is the one
"total gap" fixture in this repo.

**Go** (`weak.go`): every call is name-based and always resolves —
`md5.New`, `sha1.Sum` weak; `sha256.New` strong; `des.NewCipher`,
`des.NewTripleDESCipher`, `rc4.NewCipher` weak (`DES`/`3DES`/`RC4`,
exact registry matches); `rsa.GenerateKey` → bare `"RSA"`;
`ecdsa.GenerateKey` → bare `"ECDSA"` (no registry row named bare
`ECDSA` → `Unrated`); `ed25519.GenerateKey` → `Ed25519`, joins the
cross-arm component; `bcrypt.GenerateFromPassword` strong KDF.

**JS/TS** (`weak.js`/`weak.ts`): `createHash('md5'|'sha1')` weak;
`createHash('sha256')` strong; `createCipheriv('aes-256-gcm', ...)`
strong; `createDecipheriv('rc4', ...)` → name `"RC4"`, exact registry
match, weak; `createCipheriv('des-ede3-cbc', ...)` → name `"DES-CBC"`
(the parser keys off the first hyphen-split token, so this is **not**
classified as 3DES — documented parser gap); `createHmac('sha1', ...)`
→ `HMAC-SHA-1` (hyphenated — does not match the registry's
`HMAC-SHA1`, another naming-granularity gap → `Unrated`, not weak).

## Tier 3 — `tier-3-protocol-config/`

- `nginx.conf`: TLS 1.0/1.1/1.2 all recorded (legacy kept, not
  filtered) → `evaluate`'s `legacy_tls_reason` fires a **High**
  finding for 1.0 and 1.1; a cipher-suite asset with 3 entries; two
  `ECDH-X25519`/`ECDH-prime256v1` algorithm assets. The second
  `server` block (TLS 1.3 only) contributes no legacy finding.
- `apache.conf`: `-all +TLSv1 +TLSv1.1 +TLSv1.2 +TLSv1.3` → both
  legacy versions recorded and findable; the strong vhost contributes
  none.
- `haproxy.cfg`: `ssl-min-ver TLSv1.0` → High finding; the strong
  frontend's `TLSv1.2` → no finding.
- `sshd_config`: `diffie-hellman-group1-sha1` (weak, registry row
  `DH-Group1-SHA1`... **actually emitted as `"DH-Group1-SHA1"`,
  matches no registry row → `Unrated`**, another granularity gap);
  `3des-cbc` → `3DES-CBC` (same gap pattern, `Unrated`); `arcfour` →
  bare `"RC4"`, **exact match, weak**; `hmac-sha1` → `HMAC-SHA-1`
  (gap, `Unrated`); `ssh-rsa` → bare `"RSA"` (gap, `Unrated`);
  `ssh-ed25519` → `Ed25519`, joins the cross-arm component;
  `mlkem768x25519-sha256` → exact registry match, `Monitor`
  (`NoneKnown` quantum threat, pure PQC hybrid).
- `main.tf`: `ELBSecurityPolicy-2016-08` → TLS 1.0 → weak finding;
  `ELBSecurityPolicy-TLS13-1-3-2021-06` → TLS 1.3 → no finding;
  `customer_master_key_spec = "RSA_2048"` → **joins the global
  `RSA-2048` component** (see README's bom-ref note); `SYMMETRIC_DEFAULT`
  → `AES-256-GCM`, `Monitor`; GCP `RSA_SIGN_PSS_2048_SHA256` →
  `RSA-PSS-2048` (no registry row, `Unrated`); Azure `key_type = "RSA"`
  → bare `"RSA"` (gap, `Unrated`, `Resolution::Partial`);
  `minimum_protocol_version = "TLSv1_2016"` → TLS 1.0 → weak finding;
  `"TLSv1.4_2099"` → **Unresolved, not dropped** (unrecognised value).

## Tier 4 — `tier-4-dependencies/`

`Cargo.lock`: `ring`/`rustls` → general-purpose (`library:ring@0.17.8`
etc.); `aes-gcm` → specific `AES-GCM`; `ed25519-dalek` → specific
`Ed25519` (**joins the global cross-arm component**); `sha2` →
specific `SHA-2`; `argon2` → specific `Argon2`; `rsa` crate → specific
`RSA` (`Purpose::Mixed`); `serde`/`tokio` → **no asset** (ordinary
deps).

`package-lock.json`: `jsonwebtoken`/`node-forge`/`crypto-js`/`jose` →
general; `bcrypt`/`bcryptjs` → specific `bcrypt`; `tweetnacl` →
general; `express`/`lodash` → no asset.

`yarn.lock`: `tweetnacl` → general; `libsodium-wrappers` → general.

`requirements.txt`: `cryptography`/`pyjwt`/`passlib`/`pynacl` →
general; `argon2-cffi` → specific `Argon2`; `bcrypt` → specific
`bcrypt`; `requests`/`flask` → no asset.

`poetry.lock`: `pynacl` → general; `passlib` → general;
`requests` → no asset.

`go.sum`: `golang.org/x/crypto` → general (deduped across its two
`h1:`/`go.mod h1:` lines); `github.com/golang-jwt/jwt/v5` → general
(the `/v5` module-path suffix matches via the `pattern/` prefix rule);
`github.com/spf13/cobra` → no asset.

## Tier 5 — `tier-5-composite-and-chains/`

- `cert-chain/`: `root_ca_cert.pem` is `self_signed: true`,
  `is_ca: true` → `role: TrustAnchor`. `intermediate_ca_cert.pem`'s
  issuer DN matches the root's subject DN → `issuer_cert_ref` set (A1
  M4 chain linking). `leaf_cert.pem`'s issuer matches the
  intermediate's subject → `issuer_cert_ref` set, one hop further.
  Three certificates, two resolved chain links.
- `vendor/thirdparty/weak_vendored_key.pem` (RSA-1024) → every
  occurrence tagged `Scope::Vendored`.
- `examples/demo/demo_key.pem` → `Scope::Example`.
- `tests/fixtures/fixture_key.pem` → `Scope::Test`.
- `dev/certs/dev_ca.pem` → `Scope::Test` (the `dev/certs` special-case
  in `classify_scope`).

## Tier 6 — `tier-6-overlay-scored/` + `.gadriel/crypto-overlay.yaml`

| bom_ref | Overlay | Expected tier |
|---|---|---|
| `crypto/algorithm/RSA-2048` | Complete, (5+5+5+4)/4 = 4.75 | **Tier 1**, Mosca **exposed** (migration 8y > horizon 5y) |
| `crypto/algorithm/Ed25519` | Complete, (2+2+1+2)/4 = 1.75 | **Tier 3**, Mosca **not exposed** (migration 2y ≤ horizon 10y) |
| `crypto/algorithm/RSA-3072` | Partial (`sensitivity` only) | Stays `QuantumVulnerableUnscored` — never guessed |

`rsa3072_partial_overlay_key.pem` is the only fixture in the repo
producing a bare `RSA-3072` algorithm asset, so it is the clean,
unambiguous test of "partial overlay never promotes a tier."

### Measured, real end-to-end run (2026-10-02, this repo, `gadriel` release build)

```
Certificates:            6
Algorithms:              127
Keys / related material: 22
Protocols:               22
Considered / emitted / unresolved: 149 / 177 / 4

Tier 0 - Fix now:               21
Quantum-vulnerable (unscored):  3
Monitor:                        19
Unrated - attest:               70
Tier 1 (scored, overlay):       7
Tier 2 (scored, overlay):       0
Tier 3 (scored, overlay):       7
```

**Important nuance this run surfaced**: the CLI's own stdout tally
above counts tiers **per raw occurrence**, before cross-arm
deduplication — `scoring::score_with_overlay` runs on the flat,
unmerged asset list. That's why "Tier 1" reads 7, not 1: `RSA-2048`
has 7 real occurrences across this repo (6 material-arm keys + 1
Terraform KMS reference), and `score_with_overlay` scores each
occurrence independently (all 7 agree: Tier 1). Likewise Tier 3 = 7
is every `Ed25519` occurrence (material, library, source-API ×4,
protocol). The **emitted CBOM document**, by contrast, correctly
collapses all 7 `RSA-2048` occurrences into **one** component (see
below) — the CLI summary and the CBOM component count are answering
two different questions ("how many hits" vs. "how many distinct
assets"), not disagreeing with each other.

A real bug was found and fixed while producing this measurement:
`build_document` originally emitted one CycloneDX component **per raw
occurrence** rather than one per distinct `bom_ref()`, so `RSA-2048`
alone produced 7 separate components all sharing the identical
`bom-ref` — invalid as a dependency-graph key, and silently losing the
"one canonical asset, many occurrences" model the crate's own docs
describe. Fixed in `gadriel-crypto-inventory/src/cbom.rs`
(`merge_assets_by_bom_ref`); confirmed on this exact run: 177 raw
assets → **94 distinct CBOM components**, every `bom-ref` unique,
`RSA-2048`'s one component carries all 7 occurrences.

A second, crash-level bug was found and fixed first (it blocked any
scan from completing at all): `algorithm_component` passed Java/
OpenSSL-style mode/padding spellings (`"GCM"`, `"PKCS5Padding"`,
`"OAEPWithSHA-256AndMGF1Padding"`) straight into CycloneDX 1.7's
closed `mode`/`padding` enums, which rejected every value that wasn't
already lowercase/schema-spelled — i.e. it failed on the single most
common real-world Java cipher call,
`Cipher.getInstance("AES/GCM/NoPadding")`. Fixed via `cdx_mode_str`/
`cdx_padding_str` normalisation functions in the same file.

## Tier 7 — `tier-7-negative-controls/`

Zero `CODE-W1-CRYPTO-0xx` (classically-weak) findings anywhere in this
tier. `Ed25519`/`RSA` key-generation calls here still correctly join
the global quantum-vulnerable components (that is accurate behavior,
not a false positive — Ed25519/RSA are quantum-vulnerable regardless
of where they're generated). `AES-GCM`/`Argon2` dependencies and
`AESGCM`/`Ed25519PrivateKey.generate()` calls are `Monitor`-tier, no
finding.

## Smoke-check summary (what `scripts/score.py` actually asserts)

Exhaustively re-deriving every occurrence above on every run is
brittle; the scorer instead checks the small set of facts that would
regress if any arm, the policy module, or the overlay mechanism broke:

1. `.security/cbom-summary.json` reports `material.emitted >= 10`,
   `library.emitted >= 15` (counts are approximate — new fixtures may
   shift them; the scorer checks `>=`, not `==`).
2. `.security/cbom.cyclonedx.json` contains components named
   `RSA-2048`, `RSA-1024`, `Ed25519`, `MD5`, `RC4` with
   `gadriel:crypto:tier` properties: `RSA-2048` → `tier1-scored`,
   `Ed25519` → `tier3-scored`, `RSA-1024` → `tier0-fix-now`,
   `RSA-3072` → `quantum-vulnerable-unscored`.
3. `.security/crypto-findings.json` contains at least one `High`
   finding with `cwe == "CWE-324"` (expired certificate) and at least
   one `High` finding with `reason` mentioning `"MD5"`.
4. The RSA-2048 CBOM component's `evidence.occurrences` array has
   entries from more than one `Arm` (proving cross-arm correlation
   actually happened, not just one arm's output).
