# Scoring a tool against this corpus

## What's implemented today

[`scripts/score.py`](../scripts/score.py) is a **smoke-check scorer**:
it runs `gadriel code cbom . --csv`, then checks a fixed set of
ground-truth assertions from
[`EXPECTED-FINDINGS.md`](EXPECTED-FINDINGS.md) (specific components
exist, specific tiers were assigned, specific policy findings fired)
against the real output. It prints PASS/FAIL per assertion and exits
non-zero on any failure. It is `gadriel`-specific — it shells out to a
`gadriel` binary and parses `gadriel`'s CycloneDX output format.

This is deliberately a correctness check, not a benchmark score: it
answers "did this specific run regress," which is what you want in
CI, and nothing in it computes precision or recall.

## The general method, for scoring any tool

`EXPECTED-FINDINGS.md` documents every intended component across
tiers 1–7 (tier 8 is held out — see [`blind-tier.md`](blind-tier.md)).
To score a different CBOM/crypto-discovery tool against this corpus
by hand, or in a scorer you write for it:

1. **Build the expected set.** Flatten `EXPECTED-FINDINGS.md`'s tables
   into `(algorithm_or_asset_name, expected_property)` pairs — e.g.
   `(RSA-1024, tier=Tier 0)`, `(MD5, classically-weak finding present)`.
2. **Build the actual set** from the tool's own output, normalized to
   the same shape. If the tool emits CycloneDX, its
   `cryptoProperties.assetType`/`algorithmProperties` fields and any
   vendor-specific tier/priority property are the equivalent of
   gadriel's `gadriel:crypto:tier` property.
3. **Compute, per tier (not pooled across tiers):**
   - **Recall** = (expected items the tool found) / (all expected items)
   - **Precision** = (expected items the tool found) / (all items the tool reported)
4. **Report tier 7 (negative controls) separately, as a false-positive
   rate, not a recall number.** A tool that reports *zero* findings on
   tier 7 is behaving correctly — do not average tier 7 into an
   overall recall score, or a tool that over-reports everywhere will
   look artificially better for correctly avoiding false positives on
   a tier designed to have none.
5. **If you want to include tier 8**, see
   [`blind-tier.md`](blind-tier.md) — open a scoring-request issue with
   your raw findings for that tier; a maintainer checks it against the
   held answer key and reports your score, not the key.

## Worked example

Suppose a tool reports, against `tier-1-material-basics/`:

- Found: `RSA-1024` (correct, expected as Tier 0), `DSA-1024` (correct,
  expected as Tier 0), `Ed25519` (correct, expected as a strong
  negative case — i.e., correctly *not* flagged as weak)
- Missed: the expired certificate finding
- Extra: flagged the `encrypted_private_key.pem` as unencrypted (false
  positive — it's passphrase-protected by construction)

That's 2 of 3 expected weak-material findings recalled (67%), one
false positive against 3 total reports (67% precision), scored
separately from the fact that it correctly did not flag the strong
negative cases.

## Why tiers are scored separately, not as one number

A single pooled score across tiers 1–7 would let a tool's strong
performance on, say, tier 4 (dependency lockfiles — comparatively
mechanical) mask weak performance on tier 2 (source-API calls, which
need real parsing, not just pattern matching). Reporting per-tier
numbers is part of this corpus's design, not an afterthought — see
[`taxonomy.md`](taxonomy.md) for why the four discovery arms are
treated as genuinely separate capabilities.

## Future work

A general-purpose, tool-agnostic scorer (reading `EXPECTED-FINDINGS.md`
and a *generic* CycloneDX CBOM file, with no `gadriel`-specific
parsing) is a natural extension of `scripts/score.py` and is not yet
built. Contributions welcome — see [`CONTRIBUTING.md`](../CONTRIBUTING.md).
