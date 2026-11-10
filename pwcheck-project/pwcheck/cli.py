"""Command-line interface.

Privacy rules enforced here:
* The password is NEVER accepted as a command-line argument (it would
  appear in shell history and process listings). It is read with getpass
  (no echo) or from stdin with --stdin.
* The password is never printed back, logged, stored or transmitted.
"""

import argparse
import getpass
import sys

from . import __version__
from .generator import (
    DEFAULT_LENGTH,
    MAX_LENGTH,
    MIN_LENGTH,
    GeneratorError,
    generate_password,
)
from .scoring import score_password
from .validation import InvalidPasswordError

PRIVACY_NOTE = (
    "Privacy: your password is processed in memory only. "
    "It is not stored, logged or sent anywhere."
)


def _bar(score: int, width: int = 20) -> str:
    filled = round(score / 100 * width)
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def read_password(use_stdin: bool) -> str:
    if use_stdin:
        return sys.stdin.readline().rstrip("\r\n")
    return getpass.getpass("Enter password (input hidden): ")


def print_result(result) -> None:
    print(f"Strength : {result.label} ({result.score}/100) {_bar(result.score)}")
    print(f"Estimated entropy after penalties: {result.entropy_bits} bits")
    if result.suggestions:
        print("How to improve:")
        for tip in result.suggestions:
            print(f"  - {tip}")
    else:
        print("No weaknesses found.")
    print(PRIVACY_NOTE)


def cmd_check(args) -> int:
    try:
        password = read_password(args.stdin)
        result = score_password(password)
    except InvalidPasswordError as exc:
        print(f"Invalid input: {exc}", file=sys.stderr)
        return 2
    except (EOFError, KeyboardInterrupt):
        print("\nNo password entered.", file=sys.stderr)
        return 2
    print_result(result)
    return 0


def cmd_generate(args) -> int:
    try:
        for _ in range(args.count):
            pw = generate_password(
                length=args.length,
                lower=not args.no_lower,
                upper=not args.no_upper,
                digits=not args.no_digits,
                symbols=not args.no_symbols,
                exclude_ambiguous=args.exclude_ambiguous,
            )
            print(pw)
            if args.show_score:
                r = score_password(pw)
                print(f"  -> {r.label} ({r.score}/100)")
    except GeneratorError as exc:
        print(f"Invalid options: {exc}", file=sys.stderr)
        return 2
    return 0


def _ask_yes(prompt: str, default: bool = True) -> bool:
    answer = input(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    return default if not answer else answer.startswith("y")


def _interactive_generate() -> None:
    try:
        raw = input(f"Length ({MIN_LENGTH}-{MAX_LENGTH}, default {DEFAULT_LENGTH}): ").strip()
        length = int(raw) if raw else DEFAULT_LENGTH
        ns = argparse.Namespace(
            length=length,
            count=1,
            no_lower=not _ask_yes("Include lowercase?"),
            no_upper=not _ask_yes("Include uppercase?"),
            no_digits=not _ask_yes("Include digits?"),
            no_symbols=not _ask_yes("Include symbols?"),
            exclude_ambiguous=_ask_yes("Exclude look-alike characters (I l 1 O 0)?", False),
            show_score=True,
        )
    except ValueError:
        print("Invalid options: length must be a whole number.", file=sys.stderr)
        return
    except (EOFError, KeyboardInterrupt):
        print()
        return
    cmd_generate(ns)


def interactive() -> int:
    print(f"pwcheck {__version__} - password strength checker and generator")
    print(PRIVACY_NOTE)
    while True:
        print("\n1) Check a password\n2) Generate a password\n3) Quit")
        try:
            choice = input("Choose an option: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if choice == "1":
            cmd_check(argparse.Namespace(stdin=False))
        elif choice == "2":
            _interactive_generate()
        elif choice == "3":
            return 0
        else:
            print("Please enter 1, 2 or 3.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pwcheck",
        description="Check password strength or generate secure passwords. "
        "Run with no command for an interactive menu.",
        epilog=PRIVACY_NOTE,
    )
    parser.add_argument("--version", action="version", version=f"pwcheck {__version__}")
    sub = parser.add_subparsers(dest="command")

    check = sub.add_parser("check", help="evaluate a password (never read from arguments)")
    check.add_argument("--stdin", action="store_true", help="read the password from standard input")

    gen = sub.add_parser("generate", help="generate a random password")
    gen.add_argument("-l", "--length", type=int, default=DEFAULT_LENGTH)
    gen.add_argument("-n", "--count", type=int, default=1)
    gen.add_argument("--no-lower", action="store_true")
    gen.add_argument("--no-upper", action="store_true")
    gen.add_argument("--no-digits", action="store_true")
    gen.add_argument("--no-symbols", action="store_true")
    gen.add_argument("--exclude-ambiguous", action="store_true", help="omit I, l, 1, O, 0")
    gen.add_argument("--show-score", action="store_true")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "check":
        return cmd_check(args)
    if args.command == "generate":
        if not 1 <= args.count <= 50:
            print("Invalid options: count must be between 1 and 50.", file=sys.stderr)
            return 2
        return cmd_generate(args)
    return interactive()
