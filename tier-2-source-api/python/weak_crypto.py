"""
Deliberately vulnerable-by-design A2 (source-API arm) fixture, Python.
Matched against crypto_source_scan.rs's PYTHON_NAME_BASED table (direct
calls, always resolve) and the ARG_BASED table (hashlib.new / hmac.new,
literal vs. variable argument).
"""
import hashlib
import hmac

from Crypto.Cipher import AES, DES, ARC4
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import ec


def weak_digests():
    hashlib.md5(b"weak")          # weak, name-based
    hashlib.sha1(b"weak")         # weak, name-based
    hashlib.sha256(b"ok")         # strong, name-based
    hashlib.new("sha1")           # weak, arg-based literal
    hashlib.new("sha256")         # strong, arg-based literal


def weak_ciphers(key, nonce):
    DES.new(key, DES.MODE_ECB)            # weak: DES, name-based
    ARC4.new(key)                          # weak: RC4, name-based
    AES.new(key, AES.MODE_GCM, nonce)      # strong, name-based


def weak_keygen():
    RSA.generate(2048)             # name-based, resolves to bare "RSA"
    ec.generate_private_key(ec.SECP256R1())  # name-based, resolves to bare "ECDSA"


def hmac_literal_digest(key, msg):
    # Legacy calling convention: digestmod as a literal string ->
    # resolves via parse_python_hmac_digestmod.
    return hmac.new(key, msg, "sha1")      # weak: HMAC built on SHA-1


def hmac_variable_digestmod_is_unresolved(key, msg):
    # Modern spelling: digestmod=hashlib.sha256 is an attribute
    # reference, not a string literal -- deliberately left Unresolved
    # by the scanner rather than guessed (see crypto_source_scan.rs's
    # module doc comment). This is the tier-2 "indirect" case.
    return hmac.new(key, msg, hashlib.sha256)
