# pwcheck - Password Strength Checker and Generator

A privacy-first Python command-line tool that evaluates password strength, explains how to improve it, and generates secure random passwords. It has no third-party dependencies (Python 3.9+).

## Features
- Hidden password input and strict validation (empty, over-long, non-text, control characters).
- Explainable rule-based score (0-100) using length, character variety and predictable patterns: common passwords (including leetspeak), sequences, keyboard walks, repeats, years.
- Clear feedback that never repeats any part of the password.
- Configurable generator on the `secrets` module: length 8-128, character classes, exclude look-alike characters, at least one character from every selected class.
- Automated tests and a privacy notice (`PRIVACY.md`).

## Install and run
```bash
git clone <your-repo-url> && cd pwcheck-project
python -m venv .venv && source .venv/bin/activate   
python -m pwcheck                # interactive menu
```

## Usage
```bash
python -m pwcheck check                         # prompts with hidden input
echo 'myPassw0rd' | python -m pwcheck check --stdin
python -m pwcheck generate                      # 16 chars, all classes
python -m pwcheck generate -l 24 --no-symbols --exclude-ambiguous -n 5 --show-score
python -m pwcheck --help
```
Passwords are deliberately **not** accepted as arguments, since they would be stored in shell history.

Sample output:
```
Strength : Very weak (5/100) [#-------------------]
Estimated entropy after penalties: 0.0 bits
How to improve:
  - This is a very commonly used password. Avoid predictable patterns.
  - Use at least 12 characters; length matters most.
  - Add a mix of character types: uppercase letters, digits, symbols.
Privacy: your password is processed in memory only. It is not stored, logged or sent anywhere.
```

## Project structure
```
pwcheck/
  validation.py   input validation
  patterns.py     predictable-pattern detection, local common-password list
  scoring.py      explainable strength score
  generator.py    secure generator (secrets)
  cli.py          command-line and interactive interface
  data/common_passwords.txt
tests/            unittest-style tests (pytest compatible)
docs/test_plan.md test cases, bug log, limitations
PRIVACY.md        privacy notice
```

## How scoring works
1. `entropy = length * log2(pool size)`, where the pool is built from the character classes used.
2. Pattern penalties (in bits) are subtracted: sequences, keyboard walks, repeats, years, common-word bases. An exact common password is capped at 5/100.
3. `score = bits / 80 * 100`, capped at 100. Passwords under 8 characters are capped at 30.
4. Labels: 0-19 Very weak, 20-39 Weak, 40-59 Fair, 60-79 Strong, 80+ Very strong.

Long passphrases are not told to add symbols, which reduces false positives.

## Security decisions
- **No unsafe deserialisation:** the common-password list is plain text; no pickle, eval or exec.
- **Secure randomness:** `secrets` only; `random` is never used (checked by a test).
- **Privacy by design:** no storage, logging, network access, or echoing of passwords; findings contain no password fragments.
- **Input hardening:** length limit and control-character rejection happen before scoring.
- **No external dependencies:** minimal supply-chain risk.

## Testing
```bash
python -m unittest discover -s tests -v
# or: pip install pytest && python -m pytest
```
See `docs/test_plan.md` for test cases, bug log and limitations.

## Limitations and possible improvements
- Replace the small bundled list with a larger public list.
- Add a passphrase (word-based) generator and a breach-check using k-anonymity (opt-in, since it needs the network).
- Add a simple GUI or web front end.

## Weekly checkpoints
| Week | Where it shows in this repo |
|------|-----------------------------|
| 3 | Structure, brief, MVP, `PRIVACY.md` |
| 4 | `validation.py`, first scoring rules, sample I/O |
| 5 | Modules, `generator.py`, `patterns.py` |
| 6 | Integrated `cli.py`, error handling, safe data loading |
| 7 | `tests/`, `docs/test_plan.md`, bug log |
| 8 | README, release tag `v1.0` |
