import unittest

from pwcheck.validation import MAX_LENGTH, InvalidPasswordError, validate_password


class ValidationTests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(validate_password("Abc!1234"), "Abc!1234")

    def test_empty_rejected(self):
        with self.assertRaises(InvalidPasswordError):
            validate_password("")

    def test_non_string_rejected(self):
        for bad in (None, 123, b"bytes", ["a"]):
            with self.assertRaises(InvalidPasswordError):
                validate_password(bad)

    def test_too_long_rejected_and_boundary_accepted(self):
        validate_password("a" * MAX_LENGTH)
        with self.assertRaises(InvalidPasswordError):
            validate_password("a" * (MAX_LENGTH + 1))

    def test_control_characters_rejected(self):
        for bad in ("abc\x00def", "abc\ndef", "tab\there", "del\x7f"):
            with self.assertRaises(InvalidPasswordError):
                validate_password(bad)

    def test_error_does_not_echo_password(self):
        secret = "S3cret\x00Value"
        try:
            validate_password(secret)
        except InvalidPasswordError as exc:
            self.assertNotIn("S3cret", str(exc))


if __name__ == "__main__":
    unittest.main()
