"""Identifier helpers. Prefixed ids make logs and URLs self-describing (evt_, det_, inv_ ...)."""

import hashlib
import secrets


def new_id(prefix: str) -> str:
    """Random id for mutable objects (investigations, analyses, runs)."""
    return f"{prefix}_{secrets.token_hex(8)}"


def content_id(prefix: str, digest_input: str) -> str:
    """Deterministic id derived from content; identical content -> identical id."""
    return f"{prefix}_{hashlib.sha256(digest_input.encode()).hexdigest()[:20]}"
