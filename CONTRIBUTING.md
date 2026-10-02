# Contributing

This corpus is only useful if its ground truth is trustworthy. That
shapes every rule below more than usual for a benchmark/fixture repo.

## Ways to contribute

- **Add a fixture** for a detection case not yet covered (a new
  algorithm, a new config format, a new encoding/evasion technique).
- **Report a corpus defect**: a fixture that doesn't actually exercise
  what its tier claims, an `EXPECTED-FINDINGS.md` entry that's wrong,
  or a negative control (tier 7) that a correct tool *should* flag
  (meaning it's not actually a negative control).
- **Build or improve tooling**: `scripts/score.py` is currently
  `gadriel`-specific — see [`docs/scoring.md`](docs/scoring.md)'s
  "Future work" section for the tool-agnostic scorer this corpus
  wants.
- **Extend `tier-8-unlabeled/`** once a revision's answer key is
  published (see [`docs/blind-tier.md`](docs/blind-tier.md)) — adding
  a new held-out item for the next revision.

## Rules for any fixture PR

1. **Every fixture must have a documented, reproducible expected
   result** added to `EXPECTED-FINDINGS.md` (or, for tier 8 material,
   held privately per `docs/blind-tier.md` — contact the maintainers
   before adding anything there, don't open a public PR for it).
2. **State whether material is real or synthetic, and if real, strip
   it to the minimum needed to trigger detection.** A fixture does not
   need a key's full entropy to prove a parser finds it; it does need
   to be a structurally valid instance of whatever format it claims
   to be (a "PEM file" that isn't valid PEM tests nothing).
3. **Never include real, currently-valid credentials, even
   accidentally.** If you generate a fixture from a real-world
   template, change every identifying value (domain, subject, org
   name) to an obviously fake placeholder before committing.
4. **Negative controls are first-class, not filler.** If you add a
   vulnerable fixture to a tier, consider whether a matching strong
   fixture belongs in `tier-7-negative-controls/` so recall gains
   don't come at the cost of untested precision.
5. **Ground every claim in a cited source read, not a guess**, the
   same way the existing tiers are grounded in a direct read of
   `gadriel`'s detection logic. If you're adding a fixture meant to
   test a different tool, cite that tool's actual parsing logic or
   documentation in the PR description.
6. **Run the existing scorer before opening a PR**
   (`python3 scripts/score.py <gadriel-binary> .`) and include its
   output in the PR description.

## Reporting a security issue with this repo itself

This repo's entire purpose is to contain intentionally "vulnerable"
cryptographic material — that is not a security report. If you find
something that genuinely is a security issue (for example: real,
non-synthetic credentials accidentally committed, or a fixture that
could be mistaken for, and misused as, a real trust anchor), open an
issue titled `security` rather than a normal PR, and a maintainer will
respond before any public discussion of specifics.
