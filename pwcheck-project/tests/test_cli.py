import contextlib
import io
import unittest
from unittest import mock

from pwcheck import cli


def run(argv, password=None, stdin_text=None):
    out, err = io.StringIO(), io.StringIO()
    patches = []
    if password is not None:
        patches.append(mock.patch("getpass.getpass", return_value=password))
    if stdin_text is not None:
        patches.append(mock.patch("sys.stdin", io.StringIO(stdin_text)))
    with contextlib.ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        stack.enter_context(contextlib.redirect_stdout(out))
        stack.enter_context(contextlib.redirect_stderr(err))
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_check_via_getpass(self):
        code, out, _ = run(["check"], password="k#8Vq!Ld2@ZrT9&w")
        self.assertEqual(code, 0)
        self.assertIn("Very strong", out)

    def test_check_via_stdin(self):
        code, out, _ = run(["check", "--stdin"], stdin_text="password\n")
        self.assertEqual(code, 0)
        self.assertIn("Very weak", out)

    def test_password_never_printed(self):
        for pw in ("MyS3cret!Phrase#77", "qwerty123", "Zz9!Zz9!Zz9!"):
            code, out, err = run(["check"], password=pw)
            self.assertNotIn(pw, out + err)

    def test_empty_input(self):
        code, out, err = run(["check"], password="")
        self.assertEqual(code, 2)
        self.assertIn("empty", err.lower())

    def test_extremely_long_input(self):
        code, _, err = run(["check"], password="a" * 5000)
        self.assertEqual(code, 2)
        self.assertIn("longer", err)

    def test_control_characters(self):
        code, _, _ = run(["check"], password="bad\x00pass")
        self.assertEqual(code, 2)

    def test_password_not_accepted_as_argument(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                cli.main(["check", "mysecret"])

    def test_generate_options(self):
        code, out, _ = run(["generate", "-l", "24", "--no-symbols", "--exclude-ambiguous"])
        pw = out.strip()
        self.assertEqual(code, 0)
        self.assertEqual(len(pw), 24)
        self.assertTrue(pw.isalnum())

    def test_generate_count_and_score(self):
        code, out, _ = run(["generate", "-n", "3", "--show-score"])
        self.assertEqual(code, 0)
        self.assertEqual(out.count("->"), 3)

    def test_generate_invalid(self):
        self.assertEqual(run(["generate", "-l", "3"])[0], 2)
        self.assertEqual(run(["generate", "-n", "0"])[0], 2)
        self.assertEqual(
            run(["generate", "--no-lower", "--no-upper", "--no-digits", "--no-symbols"])[0], 2
        )

    def test_interactive_menu_quit(self):
        with mock.patch("builtins.input", side_effect=["9", "3"]):
            code, out, _ = run([])
        self.assertEqual(code, 0)
        self.assertIn("Please enter 1, 2 or 3", out)


if __name__ == "__main__":
    unittest.main()
