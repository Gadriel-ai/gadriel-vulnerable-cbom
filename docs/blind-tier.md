# The blind tier (`tier-8-unlabeled/`)

## Why a vulnerable-by-design corpus needs a held-out set

Every other tier in this repo publishes its ground truth in
[`EXPECTED-FINDINGS.md`](EXPECTED-FINDINGS.md). That is correct for a
corpus whose job is to prove a *specific* detector works — you want
the answer key open so anyone can check a tool's output line by line.

It is the wrong design for a corpus whose job is also to measure
**honest recall on cases nobody tuned for**. Once an answer key is
public, a tool (or a tool's author) can special-case its way to a
perfect score on exactly those fixtures without generalizing at all —
the benchmark stops measuring detection and starts measuring whether
someone read the benchmark's own source. OWASP Benchmark, most ML
train/test splits, and most CTF scoring infrastructures all solve this
the same way: keep a held-out slice whose answers are not shipped with
the challenge.

`tier-8-unlabeled/` is that slice for this repo.

## What's published and what isn't

**Published** (in this file, openly): that the tier exists, that it
contains real cryptographic material, that each item was placed using
a distinct technique chosen to test something a naive file-type- or
line-pattern-based scanner would miss, and that every item *is*
findable by *some* legitimate static-analysis technique — content
sniffing independent of file extension, decoding a common encoding
before pattern-matching, looking past a binary format's logical EOF,
and mining version-control history, not just the working tree. This
is a point about detection *breadth*, not a cleverness contest — none
of it is adversarial against a specific tool, and none of it requires
guessing a secret transform; every technique here is a documented,
common real-world way sensitive material ends up overlooked.

**Not published anywhere in this repo**: which files, which
algorithms, which exact technique maps to which file, or a count of
how many items there are. No commit message, code comment, filename,
or variable name in `tier-8-unlabeled/` describes its own contents.

## Ground truth and disclosure

The answer key is held by the maintainers outside of this repository.
If you are scoring a tool against this tier and want to verify your
own findings:

- Open an issue titled `blind-tier scoring request` with your tool's
  raw output for `tier-8-unlabeled/` attached (findings only — you do
  not need to share the rest of your scan). A maintainer will confirm
  precision/recall against the held answer key and report back the
  score, not the key itself.
- The key is published on a rolling basis: once a tier-8 revision has
  been live for **12 months**, its answer key moves into
  `EXPECTED-FINDINGS.md` and a new, disjoint set of held-out items
  replaces it. This mirrors how OWASP Benchmark and similar corpora
  age out old answer keys rather than leaving them held back forever.

## What this tier deliberately does not test

- It is not an obfuscation arms race. Nothing here is encrypted,
  packed, or protected in a way that requires reversing attacker-grade
  evasion — every technique is something a defensive secret-scanner
  already has a documented, known-good countermeasure for.
- It is not a trick question. Every item is a real, validly-formed
  cryptographic artifact (a real key, not a string that merely looks
  like one), generated solely for this repository and never used
  anywhere else — see the root `README.md`'s synthetic-material notice.
