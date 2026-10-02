# Taxonomy

Every fixture in this corpus belongs to exactly one **discovery arm**
(where a tool has to look) and triggers zero or more **policy
categories** (what's wrong with what it found). This page is the map
between the two, and between both and the external vocabularies
(NIST, CycloneDX, CWE) a tool's output should be checked against.

## Discovery arms

A crypto asset discovery tool has to look in at least four places.
Missing any one of them silently understates an organization's real
cryptographic footprint.

| Arm | What it is | Where fixtures live | Real-world example of what's missed if this arm doesn't exist |
|---|---|---|---|
| **A1 — Material** | Keys, certificates, and keystores that exist as files | `tier-1-material-basics/`, `tier-5-composite-and-chains/`, `tier-8-unlabeled/` | A private key checked into a repo that no source-code scanner looks at, because it isn't source code |
| **A2 — Source-API** | Cryptographic algorithms invoked from application code | `tier-2-source-api/` | `MessageDigest.getInstance("MD5")` buried in a password-reset flow, never touching a config file or a dependency manifest |
| **A3 — Protocol/config** | TLS/SSH/KMS settings declared in infrastructure config | `tier-3-protocol-config/` | An nginx vhost still offering TLS 1.0 that no application-code scan would ever see |
| **A4 — Library/dependencies** | Cryptographic libraries pulled in transitively | `tier-4-dependencies/` | A dependency on a single-purpose MD5/DES library nobody's code directly calls, still shipping in the build |

## Policy categories

Every finding in [`EXPECTED-FINDINGS.md`](EXPECTED-FINDINGS.md) falls
into one of these. The CWE mapping is what a tool's own findings
output should cite; the "quantum?" column is the dimension this
corpus is most centrally about.

| Category | Condition | CWE | Quantum? |
|---|---|---|---|
| Classically-weak algorithm | MD5, SHA-1, DES, 3DES, RC4, RC2, ECB mode, etc. — broken or weak *regardless of key size and regardless of a quantum computer ever existing* | CWE-327 (broken/risky crypto) | No |
| Quantum-vulnerable algorithm | RSA, DSA, (EC)DH, ECDSA — secure today against classical attackers, broken by a sufficiently large fault-tolerant quantum computer running Shor's or related algorithms | CWE-327 | **Yes** |
| Legacy protocol/cipher | TLS ≤ 1.1, SSLv3, weak SSH kex/ciphers, non-PQC-hybrid KEX where one is expected | CWE-326 (inadequate encryption strength) / CWE-327 | Partially (the protocol's *key exchange* may be quantum-vulnerable even when its symmetric cipher isn't) |
| Expiring/expired certificate | Not-after date in the past, or inside a configurable warning window | CWE-324 (use of a key past its expiration) | No |
| Unencrypted private key at rest | A private key file with no passphrase/KDF protecting it | CWE-312 (cleartext storage of sensitive information) | No |
| Vulnerable crypto dependency | A pinned library version with a known weakness, or a single-purpose library implementing only a weak primitive | CWE-1104 (use of unmaintained third-party components) / CWE-327 | Depends on the primitive |

## Quantum-vulnerability tiers (D-16/D-14)

"Quantum-vulnerable" is not one bucket. An RSA-2048 TLS key with a
two-year rotation cycle and an RSA-2048 code-signing root key with a
twenty-year validity period carry wildly different migration urgency
even though both are, cryptographically, in exactly the same amount
of danger from the same future computer. This corpus's tiering
reflects that:

| Tier | Meaning | What activates it |
|---|---|---|
| **Tier 0 — Fix now** | Classically weak *today*, no quantum computer required | Code-derived only (see `tier-1` through `tier-4`) |
| **Monitor** | Quantum-vulnerable, PQC migration path exists and isn't urgent by default heuristics | Code-derived only |
| **Unrated — attest** | Quantum-vulnerable, insufficient code-derived signal to rank | Code-derived only |
| **Quantum-vulnerable (unscored)** | Quantum-vulnerable, *no* business-context overlay entry exists for this asset | Default state for any quantum-vulnerable asset absent an overlay |
| **Tier 1 / 2 / 3 (scored)** | Quantum-vulnerable, ranked by migration urgency using real business context (sensitivity, lifecycle pressure, regulatory exposure, migration complexity) | A complete four-factor entry in `.gadriel/crypto-overlay.yaml` — see [`overlay-context.md`](overlay-context.md) |
| **Mosca-exposed** | `migration_time_years > protection_horizon_years` — the data will still need protecting *after* migration would finish if started today | Same overlay entry, a derived flag, not a separate tier |

See [`quantum-readiness.md`](quantum-readiness.md) for why this
distinction exists at all, and [`overlay-context.md`](overlay-context.md)
for the exact scoring formula.

## Scope tags

A1 material fixtures also carry a `Scope` (`Production` / `Vendored` /
`Example` / `Test`), exercised by `tier-5-composite-and-chains/`'s
deliberate placement under `vendor/`, `examples/`, `tests/`, and
`dev/certs/`. A tool that can't distinguish a vendored third-party
cert from a production one will over-report — scope tagging is a
precision mechanism, not a recall one, and belongs in this taxonomy
for that reason.
