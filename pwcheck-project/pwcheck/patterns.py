"""Detection of predictable patterns in passwords.

Findings deliberately contain NO fragment of the password: the messages
describe the kind of weakness only, so feedback can be shown or logged
without leaking the secret.
"""

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

_DATA_FILE = Path(__file__).parent / "data" / "common_passwords.txt"

KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890")
_LEET = str.maketrans("0134578@$!", "oieastbasi")
_COMMON_BASE_MIN = 5


@dataclass(frozen=True)
class Finding:
    code: str
    message: str
    penalty_bits: float


@lru_cache(maxsize=1)
def load_common_passwords() -> frozenset:
    """Load the local common-password list.

    The file is read as plain text, one entry per line. No pickle or other
    deserialisation is used, and nothing is fetched over the network.
    """
    try:
        with open(_DATA_FILE, encoding="utf-8") as fh:
            return frozenset(
                line.strip().lower()
                for line in fh
                if line.strip() and not line.startswith("#")
            )
    except OSError:
        return frozenset()


def _normalise(password: str) -> str:
    return password.lower().translate(_LEET)


def _is_common(password: str) -> bool:
    common = load_common_passwords()
    return password.lower() in common or _normalise(password) in common


def _has_common_base(password: str) -> bool:
    """Common word plus a short suffix, e.g. 'password123' or 'dragon!!'."""
    norm = _normalise(password)
    for word in load_common_passwords():
        if len(word) >= _COMMON_BASE_MIN and norm.startswith(word) and len(norm) - len(word) <= 4:
            return True
    return False


def _sequence_runs(password: str):
    """Yield lengths of ascending/descending alphanumeric runs (>= 3), e.g. abc, 321."""
    s = password.lower()
    n = len(s)
    i = 0
    while i < n - 2:
        if not (s[i].isalnum() and s[i + 1].isalnum()):
            i += 1
            continue
        step = ord(s[i + 1]) - ord(s[i])
        if step in (1, -1):
            j = i + 1
            while j + 1 < n and s[j + 1].isalnum() and ord(s[j + 1]) - ord(s[j]) == step:
                j += 1
            run = j - i + 1
            if run >= 3:
                yield run
            i = j
        else:
            i += 1


def _keyboard_walks(password: str):
    """Yield lengths of keyboard-row runs (>= 4), forwards or backwards."""
    s = password.lower()
    rows = [r for row in KEYBOARD_ROWS for r in (row, row[::-1])]
    n = len(s)
    i = 0
    while i < n - 3:
        best = 0
        for row in rows:
            length = 4
            if s[i : i + length] in row:
                while i + length < n and s[i : i + length + 1] in row:
                    length += 1
                best = max(best, length)
        if best:
            yield best
            i += best
        else:
            i += 1


def find_patterns(password: str) -> list:
    """Return a list of Finding objects describing predictable structure."""
    findings = []

    if _is_common(password):
        findings.append(Finding("common", "This is a very commonly used password.", 1000.0))
    elif _has_common_base(password):
        findings.append(
            Finding("common_base", "This is a common password with a small change added to it.", 30.0)
        )

    for run in _sequence_runs(password):
        findings.append(
            Finding("sequence", "Contains characters in alphabetical or numeric order.", 5.0 * run)
        )

    for run in _keyboard_walks(password):
        findings.append(Finding("keyboard", "Contains a run of neighbouring keyboard keys.", 5.0 * run))

    for match in re.finditer(r"(.)\1{2,}", password):
        findings.append(
            Finding(
                "repeat",
                "Repeats the same character several times in a row.",
                4.0 * len(match.group(0)),
            )
        )

    for match in re.finditer(r"(.{2,4})\1+", password):
        findings.append(
            Finding("repeat_block", "Repeats the same group of characters.", 4.0 * len(match.group(0)))
        )

    if re.search(r"(?<!\d)(19|20)\d{2}(?!\d)", password):
        findings.append(Finding("year", "Contains something that looks like a year.", 8.0))

    return findings
