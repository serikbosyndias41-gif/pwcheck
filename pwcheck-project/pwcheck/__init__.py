"""pwcheck - a privacy-first password strength checker and generator."""

from .generator import GeneratorError, generate_password
from .scoring import StrengthResult, score_password
from .validation import InvalidPasswordError, validate_password

__version__ = "1.0.0"
__all__ = [
    "GeneratorError",
    "InvalidPasswordError",
    "StrengthResult",
    "generate_password",
    "score_password",
    "validate_password",
]
