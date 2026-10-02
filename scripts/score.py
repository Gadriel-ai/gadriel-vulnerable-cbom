#!/usr/bin/env python3
"""
Smoke-check scorer for gadriel-vulnerable-cbom.

Usage:
    python3 scripts/score.py /path/to/gadriel/target/release/gadriel [repo-root]

Runs `gadriel code cbom <repo-root> --csv` against this repo, then
checks the small set of ground-truth facts documented in
docs/EXPECTED-FINDINGS.md's "Smoke-check summary" section against the
real .security/ output. Prints PASS/FAIL per assertion and exits 1 if
anything failed.
"""
import json
import subprocess
import sys
from pathlib import Path


def run_gadriel(binary: str, repo_root: Path) -> None:
    result = subprocess.run(
        [binary, "code", "cbom", ".", "--csv"],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        sys.exit(f"gadriel exited {result.returncode}")


def load_json(path: Path):
    if not path.exists():
        sys.exit(f"missing expected output file: {path}")
    return json.loads(path.read_text())


def component_properties(component: dict) -> dict:
    return {p["name"]: p["value"] for p in component.get("properties", [])}


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    binary = sys.argv[1]
    repo_root = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(__file__).resolve().parent.parent

    run_gadriel(binary, repo_root)

    summary = load_json(repo_root / ".security" / "cbom-summary.json")
    cbom = load_json(repo_root / ".security" / "cbom.cyclonedx.json")
    findings = load_json(repo_root / ".security" / "crypto-findings.json")

    components = cbom.get("components", [])
    by_name = {}
    for c in components:
        by_name.setdefault(c.get("name"), []).append(c)

    failures = []

    def check(label: str, condition: bool) -> None:
        status = "PASS" if condition else "FAIL"
        print(f"[{status}] {label}")
        if not condition:
            failures.append(label)

    # 1. Population counts, loose lower bounds.
    check(
        "material.emitted >= 10",
        summary.get("considered_emitted_unresolved", {}).get("material", {}).get("emitted", 0) >= 10
        or summary.get("emitted", 0) >= 10,  # tolerate either summary shape
    )

    # 2. Specific algorithm components exist with the expected tier.
    expected_tiers = {
        "RSA-2048": "tier1-scored",
        "Ed25519": "tier3-scored",
        "RSA-1024": "tier0-fix-now",
        "RSA-3072": "quantum-vulnerable-unscored",
        "MD5": "tier0-fix-now",
    }
    for name, expected_tier in expected_tiers.items():
        matches = by_name.get(name, [])
        check(f'component "{name}" exists', len(matches) > 0)
        if matches:
            tiers = {component_properties(c).get("gadriel:crypto:tier") for c in matches}
            check(f'"{name}" tier == {expected_tier!r} (got {tiers})', expected_tier in tiers)

    check('component "RC4" exists', len(by_name.get("RC4", [])) > 0)

    # 3. Cross-arm correlation on RSA-2048: more than one occurrence
    # recorded across however many RSA-2048 components the CBOM
    # emitted (bom-refs are name-only/content-addressed, so this is
    # normally exactly one component with a multi-entry occurrence
    # list — see cryptoProperties.oid / evidence.occurrences in the
    # emitted document).
    rsa_components = by_name.get("RSA-2048", [])
    if rsa_components:
        total_occurrences = sum(
            len(c.get("evidence", {}).get("occurrences", [])) for c in rsa_components
        )
        check("RSA-2048 has multiple recorded occurrences (cross-arm correlation)", total_occurrences > 1)

    # 4. Policy findings.
    findings_list = findings if isinstance(findings, list) else findings.get("findings", [])
    has_expired_cert = any(
        f.get("failure", {}).get("cwe") == "CWE-324" and f.get("severity") == "high"
        for f in findings_list
    )
    check("an expired-certificate (CWE-324, high) finding exists", has_expired_cert)

    has_md5_finding = any(
        "MD5" in json.dumps(f.get("what_we_measured", "")) and f.get("severity") == "high"
        for f in findings_list
    )
    check("a high-severity MD5 finding exists", has_md5_finding)

    print()
    if failures:
        print(f"{len(failures)} assertion(s) failed:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("All smoke assertions passed.")


if __name__ == "__main__":
    main()
