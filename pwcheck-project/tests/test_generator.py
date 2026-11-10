import string
import unittest

from pwcheck.generator import (
    AMBIGUOUS,
    MAX_LENGTH,
    MIN_LENGTH,
    SYMBOLS,
    GeneratorError,
    generate_password,
)


class GeneratorTests(unittest.TestCase):
    def test_default_length(self):
        self.assertEqual(len(generate_password()), 16)

    def test_requested_lengths(self):
        for n in (MIN_LENGTH, 20, 64, MAX_LENGTH):
            self.assertEqual(len(generate_password(n)), n)

    def test_every_selected_class_present(self):
        for _ in range(200):
            pw = generate_password(8)
            self.assertTrue(any(c in string.ascii_lowercase for c in pw))
            self.assertTrue(any(c in string.ascii_uppercase for c in pw))
            self.assertTrue(any(c in string.digits for c in pw))
            self.assertTrue(any(c in SYMBOLS for c in pw))

    def test_class_selection_respected(self):
        pw = generate_password(30, upper=False, symbols=False)
        self.assertTrue(all(c in string.ascii_lowercase + string.digits for c in pw))

    def test_digits_only(self):
        pw = generate_password(12, lower=False, upper=False, symbols=False)
        self.assertTrue(pw.isdigit())

    def test_exclude_ambiguous(self):
        for _ in range(200):
            self.assertFalse(set(generate_password(40, exclude_ambiguous=True)) & AMBIGUOUS)

    def test_invalid_options(self):
        bad_calls = [
            dict(length=MIN_LENGTH - 1),
            dict(length=MAX_LENGTH + 1),
            dict(length="16"),
            dict(length=True),
            dict(length=12.5),
            dict(lower=False, upper=False, digits=False, symbols=False),
        ]
        for kwargs in bad_calls:
            with self.assertRaises(GeneratorError):
                generate_password(**kwargs)

    def test_outputs_differ(self):
        self.assertEqual(len({generate_password(20) for _ in range(100)}), 100)

    def test_uses_secrets_not_random(self):
        import inspect

        import pwcheck.generator as gen

        source = inspect.getsource(gen)
        self.assertIn("import secrets", source)
        self.assertNotIn("import random", source)


if __name__ == "__main__":
    unittest.main()
