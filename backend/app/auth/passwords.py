"""
Password hashing and policy.

Hashing uses argon2-cffi (Argon2id, the reference C implementation). TraceLayer never implements its own
crypto: this module only chooses parameters and a policy.
"""

import hashlib
import secrets
from functools import lru_cache

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.config import get_settings

MIN_LENGTH = 12
MAX_LENGTH = 256  # bounds hashing cost; Argon2 handles long inputs but we don't need unbounded ones

# A short deny-list of passwords that meet the length rule but are still trivially guessable.
_COMMON = {
    "password1234", "123456789012", "qwertyuiopas", "passwordpassword", "letmein12345", "welcome12345",
    "administrator", "changeme1234", "tracelayer123", "iloveyou1234", "1234567890ab", "qwerty123456",
    "password123!", "admin1234567", "trustno1trustno1", "correcthorsebatterystaple",
}  # fmt: skip


@lru_cache
def _hasher() -> PasswordHasher:
    s = get_settings()
    return PasswordHasher(time_cost=s.argon2_time_cost, memory_cost=s.argon2_memory_kib,
                          parallelism=s.argon2_parallelism)  # fmt: skip


def hash_password(password: str) -> str:
    return _hasher().hash(password)


# Verifying against this when the account does not exist keeps response time uniform (no user enumeration).
@lru_cache
def _dummy_hash() -> str:
    return _hasher().hash(secrets.token_urlsafe(16))


def verify_password(stored_hash: str | None, password: str) -> bool:
    try:
        return _hasher().verify(stored_hash or _dummy_hash(), password[:MAX_LENGTH]) and stored_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    return _hasher().check_needs_rehash(stored_hash)


def policy_errors(password: str, email: str | None = None) -> list[str]:
    errors = []
    if len(password) < MIN_LENGTH:
        errors.append(f"must be at least {MIN_LENGTH} characters")
    if len(password) > MAX_LENGTH:
        errors.append(f"must be at most {MAX_LENGTH} characters")
    lowered = password.lower()
    if lowered in _COMMON or len(set(password)) < 5:
        errors.append("is too common or too repetitive")
    if email and email.split("@")[0].lower() in lowered and len(email.split("@")[0]) >= 4:
        errors.append("must not contain your email name")
    return errors


def new_secret() -> str:
    """256-bit URL-safe secret for session tokens, invitations and reset codes."""
    return secrets.token_urlsafe(32)


def digest(secret: str) -> str:
    """Secrets are high-entropy, so a fast hash is the right tool (no need for a password KDF)."""
    return hashlib.sha256(secret.encode()).hexdigest()
