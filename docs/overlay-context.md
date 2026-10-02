# The context overlay: turning "quantum-vulnerable" into a ranked priority

A static scan of a repository can tell you an asset uses RSA-2048. It
cannot tell you whether that RSA-2048 key protects a decommissioned
test service or a twenty-year financial record, and those two cases
have nothing in common from a migration-planning standpoint even
though they look identical to a parser. Closing that gap needs real
business context that doesn't live in source code — which is exactly
why `tier-6-overlay-scored/` and `tier-8-unlabeled/` exist, and why a
quantum-vulnerable asset is **unscored by default**, never guessed.

## The schema

A context overlay (`.gadriel/crypto-overlay.yaml` in this corpus; see
the file at this repo's own root) supplies, per asset (keyed by its
content-addressed `bom_ref`, e.g. `crypto/algorithm/RSA-2048`), up to
six fields:

| Field | Range/type | Meaning |
|---|---|---|
| `sensitivity` | 1–5 | How damaging exposure of the protected data would be |
| `lifecycle_pressure` | 1–5 | How soon this asset would need rotating/retiring on its own schedule, independent of PQC |
| `regulatory_exposure` | 1–5 | How much a compliance regime (PCI-DSS, HIPAA, GDPR, etc.) constrains this asset's handling |
| `migration_complexity` | 1–5 | How hard migrating *this specific asset* will be (hardware dependency, certificate-chain depth, number of downstream consumers) |
| `protection_horizon_years` | number | Mosca's `x` — how many years this data must stay protected |
| `migration_time_years` | number | Mosca's `y` — how many years migrating this asset is estimated to take |

`business_service` and `system_owner` are also accepted, for
attribution in a report — they do not affect scoring.

## The scoring formula

Scoring requires **all four** of `sensitivity`, `lifecycle_pressure`,
`regulatory_exposure`, and `migration_complexity` to be present. A
partial entry — even three out of four — is deliberately left
unscored rather than having a missing factor silently default to
anything. (`tier-6-overlay-scored/rsa3072_partial_overlay_key.pem`
exists specifically to test that a tool does not quietly "fill in" a
missing factor.)

When all four are present, the weighted score is their simple average:

```
weighted_score = (sensitivity + lifecycle_pressure + regulatory_exposure + migration_complexity) / 4.0
```

And the tier follows directly from that average:

| `weighted_score` | Tier |
|---|---|
| ≥ 4.0 | **Tier 1** — highest migration priority |
| ≥ 2.5 and < 4.0 | **Tier 2** |
| < 2.5 | **Tier 3** — lowest migration priority among scored assets |

This is intentionally a plain equal-weighted average rather than a
more elaborate weighting scheme. A four-factor average is auditable
by inspection — anyone reading an overlay entry can recompute the
tier by hand. A migration-prioritization system that can't be checked
by a human with a calculator tends not to survive contact with an
actual audit.

## Mosca exposure is separate from tiering

Independently of the tier above, an asset is flagged **Mosca-exposed**
when:

```
migration_time_years > protection_horizon_years
```

This can be true for a Tier 2 or Tier 3 asset and false for a Tier 1
one — tiering answers *"how much should we care, relative to other
assets"*; Mosca exposure answers a different, binary question:
*"is there currently enough runway to migrate this before the data's
own required protection window closes."* Both numbers belong in a
CBOM; collapsing them into one score would hide exactly the cases
(low business priority, but already past its own migration runway)
that most need surfacing precisely because nothing else would flag
them. See [`quantum-readiness.md`](quantum-readiness.md) for why this
inequality is Mosca's, not an invention of this corpus.

## What this tier tests

`tier-6-overlay-scored/` includes, by construction:

- An entry that lands in Tier 1 (all four factors high)
- An entry that lands in Tier 3 (all four factors low)
- An entry that is Mosca-exposed
- An entry that is **not** Mosca-exposed despite otherwise similar
  factors, to confirm the two mechanisms are actually independent in
  a tool's implementation and not accidentally coupled
- A partial entry (three of four factors) that must stay unscored
