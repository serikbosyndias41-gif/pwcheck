import unittest

from pwcheck.scoring import score_password
from pwcheck.validation import InvalidPasswordError


class ScoringTests(unittest.TestCase):
    def test_short_common_password_is_very_weak(self):
        r = score_password("123456")
        self.assertLessEqual(r.score, 5)
        self.assertEqual(r.label, "Very weak")
        self.assertTrue(r.suggestions)

    def test_long_predictable_password_is_not_strong(self):
        r = score_password("abcdefghijklmnopqrstuvwxyz")
        self.assertLess(r.score, 60)
        self.assertTrue(any("order" in s.lower() for s in r.suggestions))

    def test_repeated_chars_penalised(self):
        self.assertLess(score_password("aaaaaaaaaaaaaaaa").score, 20)

    def test_strong_random_password(self):
        r = score_password("k#8Vq!Ld2@ZrT9&w")
        self.assertGreaterEqual(r.score, 80)
        self.assertEqual(r.label, "Very strong")

    def test_long_passphrase_not_flagged_weak(self):
        r = score_password("correct horse battery staple")
        self.assertGreaterEqual(r.score, 60)
        self.assertFalse(any("character types" in s for s in r.suggestions))

    def test_unicode_password_scores(self):
        r = score_password("Пароль-Қазақстан-2")
        self.assertGreater(r.score, 40)

    def test_score_bounds(self):
        for pw in ("a", "Zz9!" * 32, "x" * 128):
            r = score_password(pw)
            self.assertTrue(0 <= r.score <= 100)

    def test_short_password_capped(self):
        self.assertLessEqual(score_password("Zq9!xK").score, 30)

    def test_invalid_input_raises(self):
        for bad in ("", "a" * 129, None, "a\x00b"):
            with self.assertRaises(InvalidPasswordError):
                score_password(bad)

    def test_deterministic(self):
        self.assertEqual(score_password("Tr0ub4dor&3"), score_password("Tr0ub4dor&3"))

    def test_feedback_never_contains_password(self):
        pw = "Qwerty1987abc!"
        r = score_password(pw)
        text = " ".join(r.suggestions) + r.label
        self.assertNotIn(pw, text)


if __name__ == "__main__":
    unittest.main()
