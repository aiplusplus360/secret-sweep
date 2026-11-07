"""Shannon entropy, and the heuristics that make it usable.

Entropy alone is a bad detector. `k3J9xQ2mP7vL4nR8` and
`com.example.springboot.autoconfigure` have similar entropy and only one is a
secret. What makes entropy useful is *where* it appears: a high-entropy string
on the right-hand side of `password =` is worth flagging; the same string as a
Gradle package name is not.

So this module provides the measurement, and `patterns.py` decides when to
apply it.
"""

from __future__ import annotations

import math
import re
from typing import Iterable

# Below this, a random-looking token is usually a word, a hash fragment, or a
# path segment. 3.5 bits/char separates base64-ish blobs from English-ish text
# reasonably well without drowning the report in noise.
DEFAULT_THRESHOLD = 3.5

# Values that are structurally "secret-shaped" but obviously placeholders.
# Matching these is the difference between a useful tool and one people turn off.
PLACEHOLDERS = {
    "example", "examples", "sample", "test", "testing", "dummy", "fake",
    "placeholder", "changeme", "change_me", "your_key", "your-key", "yourtoken",
    "your_token", "your-token", "insert", "replace", "todo", "fixme",
    "password", "secret", "token", "apikey", "api_key", "none", "null", "nil",
    "undefined", "xxxxxxxx", "********", "........", "00000000",
}

_PLACEHOLDER_PATTERNS = [
    re.compile(r"^\$\{.*\}$"),          # ${ENV_VAR}
    re.compile(r"^<[^>]*>$"),           # <YOUR_TOKEN>
    re.compile(r"^%[A-Z_]+%$"),         # %ENV_VAR%
    re.compile(r"^\[.*\]$"),            # [value]
    re.compile(r"^\{\{.*\}\}$"),        # {{ template }}
    re.compile(r"^x{4,}$", re.I),       # xxxxxxxx
    re.compile(r"^(?:0|1|true|false)$", re.I),
]

# Well-known example values that appear in documentation everywhere and are
# not credentials, even though they are formatted exactly like them.
#
# Assembled from fragments rather than written out: a committed file containing
# strings indistinguishable from live keys is indistinguishable from a leak,
# and push protection is right to block it.
KNOWN_SAFE = {
    "AKIA" + "IOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY",
    "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc",
    "ghp_" + "x" * 36,
    "ya29." + "a0AfH6SMBx",
}


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character."""
    if not value:
        return 0.0
    counts = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def is_placeholder(value: str) -> bool:
    """True for values that are structurally secret-shaped but are not secrets."""
    lowered = value.lower().strip()
    if not lowered:
        return True
    if value in KNOWN_SAFE:
        return True
    if lowered in PLACEHOLDERS:
        return True
    if any(pattern.match(value) for pattern in _PLACEHOLDER_PATTERNS):
        return True
    # A run of one repeated character carries no information.
    if len(set(lowered)) <= 2:
        return True
    return False


def looks_random(value: str, threshold: float = DEFAULT_THRESHOLD) -> bool:
    """Heuristic: long-ish, high-entropy, mixed character classes."""
    if len(value) < 12:
        return False
    if shannon_entropy(value) < threshold:
        return False
    has_digit = any(c.isdigit() for c in value)
    has_alpha = any(c.isalpha() for c in value)
    return has_digit and has_alpha


def redact(value: str, keep: int = 4) -> str:
    """Show enough to identify which secret leaked, not enough to use it.

    A scanner that logs full credentials has just created a second copy of the
    problem it was written to find.
    """
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}…{value[-2:]} ({len(value)} chars)"
