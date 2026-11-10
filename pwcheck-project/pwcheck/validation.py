"""Input validation for passwords supplied by the user.

Validation runs BEFORE any scoring so that hostile or malformed input
(huge strings, control characters, wrong types) never reaches the
scoring logic. Error messages never echo the password back.
"""

MAX_LENGTH = 128


class InvalidPasswordError(ValueError):
    """Raised when the supplied password cannot be evaluated."""


def validate_password(password: object) -> str:
    """Return the password if acceptable, otherwise raise InvalidPasswordError."""
    if not isinstance(password, str):
        raise InvalidPasswordError("Password must be text.")
    if password == "":
        raise InvalidPasswordError("Password is empty.")
    if len(password) > MAX_LENGTH:
        raise InvalidPasswordError(
            f"Password is longer than the supported maximum of {MAX_LENGTH} characters."
        )
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in password):
        raise InvalidPasswordError("Password contains control characters.")
    return password
