# gadriel-vulnerable-cbom

A **vulnerable-by-design** test repository for `gadriel`'s ADR-241
cryptographic asset discovery and CycloneDX CBOM feature — the crypto
equivalent of BenchmarkJava/DVWA/WebGoat, but for the four discovery
arms (A1 material, A2 source-API, A3 protocol/config, A4 library), the
D-6 policy findings, and the D-14/D-16 context-overlay tier scoring.

Every fixture in this repo is grounded directly in `gadriel`'s real
detection logic (read from source, not guessed) so a scan against this
repo produces known, reproducible, explainable results — not "probably
detects something."

## Why this exists

A SAST/SBOM tool's test suite proves its *unit* logic works in
isolation. It does not prove the tool finds real things in a real
checkout, at real file paths, through real parsers, with real
cross-file/cross-arm correlation. This repo is that second kind of
test: run the actual compiled `gadriel` binary against it and compare
what comes out to what's documented here.

## Tiers (simple → advanced)

| Tier | Arm / feature | What it exercises |
|---|---|---|
| 1 — `tier-1-material-basics/` | A1 (material) | Every PEM label, OpenSSH, JWK, keystore-magic-byte, and CSR shape `material.rs` parses; weak (RSA-1024, DSA) and strong (Ed25519, EC P-256) keys; an expired cert and a soon-to-expire cert |
| 2 — `tier-2-source-api/` | A2 (source-API) | Java/Python/Go/JS/TS calls — name-based (always resolves) and argument-based (literal vs. variable → `Resolved` vs. `Unresolved`), plus one documented **total gap** (a call shape the scanner's table doesn't cover at all) |
| 3 — `tier-3-protocol-config/` | A3 (protocol/config) | nginx, Apache, HAProxy, `sshd_config`, and Terraform (AWS ELB/KMS, GCP KMS, Azure Key Vault, CloudFront) — legacy TLS, weak ciphers, weak SSH algorithms, PQC hybrid KEX, and one unrecognised value kept as `Unresolved` |
| 4 — `tier-4-dependencies/` | A4 (library) | All six lockfile shapes (`Cargo.lock`, `package-lock.json`, `yarn.lock`, `requirements.txt`, `poetry.lock`, `go.sum`) with both general-purpose and single-algorithm crypto libraries, and ordinary non-crypto deps that must **not** match |
| 5 — `tier-5-composite-and-chains/` | Cross-cutting | A 3-level certificate chain (root CA → intermediate → leaf) to exercise A1 M4 chain-of-trust linking, plus deliberate placement under `vendor/`, `examples/`, `tests/`, and `dev/certs/` paths to exercise `Scope` tagging (`Vendored`/`Example`/`Test`) |
| 6 — `tier-6-overlay-scored/` | D-14/D-16 | A real `.gadriel/crypto-overlay.yaml` driving Tier 1, Tier 2 (via tier-3's own RSA-2048 KMS reference — see below), Tier 3, a Mosca-exposed case, a Mosca-not-exposed case, and a **partial** overlay entry that must stay unscored |
| 7 — `tier-7-negative-controls/` | False-positive guard | Strong/current algorithms only (AES-GCM, SHA-256+, Ed25519/Ed448/P-384, Argon2) across Java/Python/config/deps — must produce zero classically-weak findings |

## The one fact that governs how to read results

`AlgorithmAsset::bom_ref()` is **`crypto/algorithm/<name>` — name only,
content-addressed, with no file path in it.** Every occurrence of the
same algorithm name *anywhere in this repo* collapses into **one**
CBOM component with multiple `occurrences[]`. Concretely:

- Every `RSA-2048` across tier 1 (the PEM key), tier 3 (`aws_kms_key`'s
  `RSA_2048` spec), tier 5 (every cert-chain key), and tier 6 is **one
  component**, scored once by the tier-6 overlay entry.
- Every `Ed25519` across tier 1 (the PEM key), tier 2 (Go's
  `ed25519.GenerateKey`, Java's `Signature.getInstance("Ed25519")`),
  tier 3 (`sshd_config`'s `ssh-ed25519`), and tier 7 (the negative
  control's own `KeyPairGenerator.getInstance("Ed25519")`) is also
  **one component**.

This is real `gadriel` behavior, not a quirk of this repo — see
`docs/EXPECTED-FINDINGS.md` for the full accounting.

## Running it

```bash
# From a gadriel checkout with the release binary built:
cd /path/to/gadriel-vulnerable-cbom
/path/to/gadriel/target/release/gadriel code cbom . --csv
/path/to/gadriel/target/release/gadriel code report --format html

# Or via the scan pipeline (also exercises the D-6 findings.json merge):
/path/to/gadriel/target/release/gadriel scan --crypto .
```

Then open `.security/reports/cbom.html` and compare the Overview, tier
cards, Register, relationship graph, and coverage/provenance views
against `docs/EXPECTED-FINDINGS.md`.

## Scoring a run

```bash
python3 scripts/score.py /path/to/gadriel/target/release/gadriel .
```

Runs `gadriel code cbom` against this repo and checks the smoke
assertions in `docs/EXPECTED-FINDINGS.md` (tier counts, specific
algorithm presence, specific policy findings) against the real
`.security/cbom.cyclonedx.json` and `.security/cbom-summary.json`
output. Exits non-zero and prints every failed assertion.

## What this repo deliberately does NOT claim

- It does not claim 100% coverage of every gadriel-crypto-inventory
  code path — it covers every *documented* branch of the six arm
  files plus the policy/scoring modules, grounded in a direct read of
  that source on 2026-10-02.
- Several fixtures are **documented gaps**, not bugs: a naming
  mismatch between `material.rs`'s curve-name formatting
  (`ECDSA-P-256`) and the D-12 registry's key (`ECDSA-P256`, no
  hyphen) means EC-curve keys currently land in `Unrated`, not
  `Monitor`/quantum-vulnerable. This is called out explicitly rather
  than silently worked around, because a test corpus that hides a
  real detection gap is worse than one that documents it.
