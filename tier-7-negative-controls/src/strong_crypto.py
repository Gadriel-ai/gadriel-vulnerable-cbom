"""False-positive guard, Python side -- strong/current algorithms only."""
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519


def strong_digest():
    hashlib.sha256(b"ok")
    hashlib.new("sha256")


def strong_keygen():
    ed25519.Ed25519PrivateKey.generate()


def strong_aead(key, nonce, data):
    AESGCM(key).encrypt(nonce, data, None)
