import unittest

from pwcheck.patterns import find_patterns, load_common_passwords


def codes(pw):
    return {f.code for f in find_patterns(pw)}


class PatternTests(unittest.TestCase):
    def test_common_list_loaded(self):
        self.assertIn("password", load_common_passwords())

    def test_common_detected(self):
        self.assertIn("common", codes("password"))
        self.assertIn("common", codes("PASSWORD"))

    def test_leetspeak_common_detected(self):
        self.assertIn("common", codes("P@ssw0rd"))

    def test_common_with_suffix(self):
        self.assertIn("common_base", codes("dragon!!"))

    def test_sequences(self):
        self.assertIn("sequence", codes("xxabcdxx"))
        self.assertIn("sequence", codes("zz987zz"))

    def test_keyboard_walk(self):
        self.assertIn("keyboard", codes("Zqwertyz"))
        self.assertIn("keyboard", codes("poiuytr"))

    def test_repeats(self):
        self.assertIn("repeat", codes("aaaB7#"))
        self.assertIn("repeat_block", codes("xyzxyzQ9"))

    def test_year(self):
        self.assertIn("year", codes("Kx#1987mP"))

    def test_random_looking_has_no_findings(self):
        self.assertEqual(codes("k#8Vq!Ld2@Zr"), set())

    def test_messages_never_contain_password_fragments(self):
        pw = "qwertyabc1987"
        for f in find_patterns(pw):
            for frag in ("qwerty", "abc", "1987"):
                self.assertNotIn(frag, f.message.lower())


if __name__ == "__main__":
    unittest.main()
