# Why "found a key" and "must migrate urgently" are different questions

This corpus exists because of a gap between two true statements that
get conflated constantly in vendor marketing: *"we can find your
RSA/ECC keys"* and *"we can tell you which ones actually need to move
to post-quantum cryptography first."* The first is a file-parsing
problem. The second needs Mosca's theorem and real business context,
which no static scan of a repository contains on its own.

## Mosca's theorem

Michele Mosca's 2015 framing, still the standard way the PQC migration
community reasons about urgency, is a single inequality:

```
x + y > z   →   migrate now
```

Where:

- **x** = how many years the data/key must stay protected (its
  *protection horizon* — a code-signing root's horizon might be
  decades; an ephemeral session key's might be minutes)
- **y** = how many years the migration itself will take (procurement,
  re-issuance, rotation, downstream re-validation — often longer than
  people assume for anything with a hardware or certificate-chain
  dependency)
- **z** = how many years until a cryptographically-relevant quantum
  computer (a "CRQC") exists and can break the algorithm in question

If the time needed to protect the data plus the time needed to
migrate it exceeds the time left before the threat arrives, migrating
later is not a deferral — it is a decision that the data will be
broken. This corpus's **Mosca-exposed** flag (see
[`taxonomy.md`](taxonomy.md)) is exactly this inequality evaluated
per-asset once `x` and `y` are known from a context overlay; `z` is a
threat-model constant the overlay doesn't need to supply per-asset.

## Harvest-now-decrypt-later

The reason `x` (protection horizon) often dwarfs intuition: an
adversary does not need a quantum computer *today* to defeat today's
RSA/ECC traffic. Recording encrypted traffic or exfiltrating encrypted
data today and decrypting it once a CRQC exists is a documented
nation-state-level strategy. This means the relevant clock for a
long-lived secret started when it was first encrypted, not when
migration begins — which is why `tier-8-unlabeled/`'s own existence
(see [`blind-tier.md`](blind-tier.md)) matters for a benchmark like
this one: a key an organization doesn't know it has is a key whose
harvest-now clock nobody is watching.

## What NIST has actually standardized

As of this corpus's writing, NIST has published three finalized
post-quantum standards:

| Standard | Mechanism | Replaces |
|---|---|---|
| **FIPS 203** (ML-KEM, née CRYSTALS-Kyber) | Key encapsulation (key exchange) | RSA/ECDH key exchange |
| **FIPS 204** (ML-DSA, née CRYSTALS-Dilithium) | Digital signatures | RSA/ECDSA/DSA signatures |
| **FIPS 205** (SLH-DSA, née SPHINCS+) | Digital signatures (hash-based, stateless) | RSA/ECDSA/DSA signatures, where a hash-based security assumption is preferred over a lattice-based one |

Two consequences for how this corpus is built:

1. **Key size does not save you.** RSA-4096 is exactly as
   quantum-vulnerable as RSA-1024 — Shor's algorithm's advantage over
   classical factoring does not degrade the way brute-force attacks
   degrade with key size. `tier-8-unlabeled/` deliberately includes a
   large modern RSA key specifically to test whether a tool's tiering
   logic mistakes "large key" for "not urgent."
2. **Hybrid is the present, not just the future.** Because migrating a
   whole protocol stack to a pure-PQC key exchange overnight is
   impractical, current real-world deployments increasingly run
   *hybrid* key exchange (classical + PQC KEM combined, so the result
   is safe if either one is). `tier-3-protocol-config/` includes a PQC
   hybrid KEX fixture precisely so a tool is tested on recognizing
   this as a mitigation in progress, not an unrelated protocol
   setting to ignore.

## What this means for a CBOM

A Cryptography Bill of Materials that only lists "here are your RSA
keys" has told an organization almost nothing actionable. A CBOM
that's actually useful for PQC migration planning has to carry, per
asset: the algorithm (quantum-vulnerable or not), enough context to
place it on Mosca's inequality, and — because an organization has
finite migration capacity — a *ranking*, not just a list. That ranking
is what tiers 1–3 (see [`overlay-context.md`](overlay-context.md)) are
for, and why this corpus tests them as a first-class feature rather
than an afterthought bolted onto "found a key."
