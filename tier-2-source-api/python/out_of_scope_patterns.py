"""
Advanced-tier negative control: crypto usage shapes the A2 scanner's
current table does NOT cover at all (not even as Unresolved -- there
is simply no matching ArgBased/NameBased entry for these call sites).
Included deliberately so a scan of this repo documents real detection
boundaries instead of silently having 100% coverage look accidental.
See docs/EXPECTED-FINDINGS.md's "known gaps" section.
"""
import jwt


def jwt_algorithm_from_variable(payload, secret, algorithm_name):
    # jwt.encode is not in crypto_source_scan.rs's ARG_BASED table at
    # all (no entry for Language::Python, suffix "jwt.encode") -- this
    # produces NO crypto asset whatsoever, resolved or unresolved.
    return jwt.encode(payload, secret, algorithm=algorithm_name)


def jwt_hs256_literal(payload, secret):
    # Same gap: even a literal "HS256" argument here is invisible to
    # this arm, because the call itself was never added to the table.
    return jwt.encode(payload, secret, algorithm="HS256")
