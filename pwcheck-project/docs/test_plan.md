# Test Plan and Results

Run all tests: `python -m unittest discover -s tests -v` (or `python -m pytest`).

| ID | Scenario | Input | Expected | Automated in |
|----|----------|-------|----------|--------------|
| T1 | Short, common password | `123456` | Very weak, score <= 5 | test_scoring |
| T2 | Common with leetspeak | `P@ssw0rd` | Flagged as common | test_patterns |
| T3 | Common word plus suffix | `dragon!!` | Flagged `common_base` | test_patterns |
| T4 | Long but predictable | `abcdefghijklmnopqrstuvwxyz` | Score < 60, sequence advice | test_scoring |
| T5 | Repetition | `aaaaaaaaaaaaaaaa` | Score < 20 | test_scoring |
| T6 | Keyboard walk | `Zqwertyz` | Flagged `keyboard` | test_patterns |
| T7 | Long passphrase (false-positive check) | `correct horse battery staple` | Score >= 60, no character-type nagging | test_scoring |
| T8 | Strong random | `k#8Vq!Ld2@ZrT9&w` | Very strong | test_scoring |
| T9 | Unicode input | `Пароль-Қазақстан-2` | Scores without error | test_scoring |
| T10 | Empty input | `` | Rejected, exit code 2 | test_validation, test_cli |
| T11 | Extremely long input | 5000 x `a` | Rejected, exit code 2 | test_cli |
| T12 | Boundary length | 128 / 129 chars | 128 accepted, 129 rejected | test_validation |
| T13 | Control characters / null byte | `bad\x00pass` | Rejected | test_validation, test_cli |
| T14 | Wrong type | `None`, `123`, `b"x"` | Rejected | test_validation |
| T15 | Password never echoed | any | Not present in stdout/stderr | test_cli |
| T16 | Feedback leaks no fragments | `qwertyabc1987` | No fragments in messages | test_patterns |
| T17 | Password as CLI argument | `check mysecret` | Rejected by parser | test_cli |
| T18 | Generator length range | 8 to 128 | Exact length | test_generator |
| T19 | Class guarantee | length 8, all classes, 200 runs | Each class present every time | test_generator |
| T20 | Class selection / ambiguous exclusion | flags | Only allowed characters | test_generator |
| T21 | Invalid generator options | length 7/129/"16"/True, no classes | `GeneratorError`, exit code 2 | test_generator, test_cli |
| T22 | Secure randomness | source inspection | Uses `secrets`, not `random` | test_generator |

## Bug log
| # | Date | Description | Status |
|---|------|-------------|--------|
| 1 | | (record defects found during Week 7 testing here) | |

## Known limitations
- The bundled common-password list is small; a larger list gives better detection.
- Scoring is a heuristic estimate, not a guarantee. Dictionary words and names are only caught if they are in the list.
- Entropy assumes characters are chosen uniformly, which is true for generated passwords but not for human-chosen ones; pattern penalties partly compensate.
