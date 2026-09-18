"""
auth.py — shared password-hashing helpers.

Imported by BOTH seed_db.py (when storing accounts) and victim_server.py (when
verifying a login), so the two sides always hash passwords the exact same way.

We use salted PBKDF2-HMAC-SHA256 (from the standard library `hashlib`). Each
account gets its own random salt, which is stored alongside the hash. This
protects the *stored* credentials if users.db is ever stolen; it does NOT stop
online guessing against the /login endpoint — that is what the attack tool
demonstrates.
"""

import hashlib
import hmac
import os

# PBKDF2 parameters. Higher iteration counts are slower to brute-force offline.
_ALGORITHM = "sha256"
_ITERATIONS = 200_000
_SALT_BYTES = 16


def generate_salt() -> str:
    """Return a fresh random salt as a hex string."""
    return os.urandom(_SALT_BYTES).hex()


def hash_password(password: str, salt: str) -> str:
    """
    Hash `password` with the given hex `salt` using PBKDF2-HMAC-SHA256.

    Returns the derived key as a hex string. Given the same password and salt,
    this always returns the same value — that is how login verification works.
    """
    derived = hashlib.pbkdf2_hmac(
        _ALGORITHM,
        password.encode("utf-8"),
        bytes.fromhex(salt),
        _ITERATIONS,
    )
    return derived.hex()


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    """
    Return True if `password` hashes (with `salt`) to `expected_hash`.

    Uses a constant-time comparison to avoid leaking information through timing.
    """
    computed = hash_password(password, salt)
    return hmac.compare_digest(computed, expected_hash)
