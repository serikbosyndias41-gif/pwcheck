"""Configurable password generator using a cryptographically secure source.

Only the `secrets` module is used (never `random`). At least one
character from every selected class is guaranteed, and the result is
shuffled with secrets.SystemRandom so positions are unpredictable.
"""

import secrets
import string

MIN_LENGTH = 8
MAX_LENGTH = 128
DEFAULT_LENGTH = 16
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"
AMBIGUOUS = set("Il1O0")


class GeneratorError(ValueError):
    """Raised when generator options are invalid."""


def _build_pools(lower, upper, digits, symbols, exclude_ambiguous):
    candidates = []
    if lower:
        candidates.append(string.ascii_lowercase)
    if upper:
        candidates.append(string.ascii_uppercase)
    if digits:
        candidates.append(string.digits)
    if symbols:
        candidates.append(SYMBOLS)
    if exclude_ambiguous:
        candidates = ["".join(c for c in chars if c not in AMBIGUOUS) for chars in candidates]
    return candidates


def generate_password(
    length: int = DEFAULT_LENGTH,
    lower: bool = True,
    upper: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    """Return a random password meeting the selected options."""
    if isinstance(length, bool) or not isinstance(length, int):
        raise GeneratorError("Length must be a whole number.")
    if not MIN_LENGTH <= length <= MAX_LENGTH:
        raise GeneratorError(f"Length must be between {MIN_LENGTH} and {MAX_LENGTH}.")

    pools = _build_pools(lower, upper, digits, symbols, exclude_ambiguous)
    if not pools:
        raise GeneratorError("Select at least one character type.")

    chars = [secrets.choice(pool) for pool in pools]
    combined = "".join(pools)
    chars += [secrets.choice(combined) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)
