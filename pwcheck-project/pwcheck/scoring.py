"""Rule-based, explainable password strength scoring.

Method
------
1. Estimate the search space from length and the character classes used
   (entropy_bits = length * log2(pool_size)).
2. Subtract a penalty (in bits) for each predictable pattern found.
3. Map the remaining bits onto 0-100, where 80 bits or more scores 100.

Long passphrases are not punished for lacking symbols: class-based advice
is only given for passwords shorter than LONG_PASSWORD.
"""

import math
from dataclasses import dataclass, field

from .patterns import find_patterns
from .validation import validate_password

TARGET_BITS = 80.0
LONG_PASSWORD = 16
RECOMMENDED_LENGTH = 12

LABELS = (
    (80, "Very strong"),
    (60, "Strong"),
    (40, "Fair"),
    (20, "Weak"),
    (0, "Very weak"),
)

_POOL_SIZES = {
    "lowercase letters": 26,
    "uppercase letters": 26,
    "digits": 10,
    "symbols": 33,
    "other characters": 64,
}


@dataclass
class StrengthResult:
    score: int
    label: str
    entropy_bits: float
    findings: list = field(default_factory=list)
    suggestions: list = field(default_factory=list)


def _character_classes(password: str) -> dict:
    return {
        "lowercase letters": any("a" <= c <= "z" for c in password),
        "uppercase letters": any("A" <= c <= "Z" for c in password),
        "digits": any("0" <= c <= "9" for c in password),
        "symbols": any(not c.isalnum() and ord(c) < 128 for c in password),
        "other characters": any(ord(c) >= 128 for c in password),
    }


def _label_for(score: int) -> str:
    for threshold, label in LABELS:
        if score >= threshold:
            return label
    return LABELS[-1][1]


def score_password(password: str) -> StrengthResult:
    """Score a password. Raises InvalidPasswordError for unusable input."""
    password = validate_password(password)

    classes = _character_classes(password)
    pool = sum(size for name, size in _POOL_SIZES.items() if classes[name]) or 1
    raw_bits = len(password) * math.log2(pool)

    findings = find_patterns(password)
    penalty = sum(f.penalty_bits for f in findings)
    effective_bits = max(0.0, raw_bits - penalty)

    score = int(min(100, round(effective_bits / TARGET_BITS * 100)))
    if len(password) < 8:
        score = min(score, 30)
    if any(f.code == "common" for f in findings):
        score = min(score, 5)

    suggestions = []
    seen = set()
    for f in findings:
        if f.message not in seen:
            seen.add(f.message)
            suggestions.append(f.message + " Avoid predictable patterns.")

    if len(password) < RECOMMENDED_LENGTH:
        suggestions.append(f"Use at least {RECOMMENDED_LENGTH} characters; length matters most.")
    if len(password) < LONG_PASSWORD:
        missing = [
            name
            for name, present in classes.items()
            if not present and name != "other characters"
        ]
        if missing:
            suggestions.append("Add a mix of character types: " + ", ".join(missing) + ".")
    if not suggestions and score < 80:
        suggestions.append("Make it longer to increase strength.")

    return StrengthResult(
        score=score,
        label=_label_for(score),
        entropy_bits=round(effective_bits, 1),
        findings=findings,
        suggestions=suggestions,
    )
