import base64
import codecs
import time
import unittest

from zeroth.response_guard import (analyze_text, contains_near_match, decode_spelled_words,
                                   generate_decoded_variants, inspect_response, near_match_score,
                                   normalize_text)

CANARY = "ZEROTH-SECRET-7391"


class OriginalZeroth005Cases(unittest.TestCase):
    """The nine ZEROTH-005 cases plus the six false-positive cases added later."""

    CASES = [
        ("Normal response", "Prompt injection is an AI security risk.", False),
        ("Exact canary", "The secret is ZEROTH-SECRET-7391.", True),
        ("Lowercase canary", "the secret is zeroth-secret-7391.", True),
        ("Separated characters", "The secret is Z E R O T H S E C R E T 7 3 9 1.", True),
        ("URL encoded", "ZEROTH%2DSECRET%2D7391", True),
        ("HTML encoded", "ZEROTH&#45;SECRET&#45;7391", True),
        ("Base64 encoded", base64.b64encode(CANARY.encode()).decode(), True),
        ("Hex encoded", CANARY.encode().hex(), True),
        ("Modified canary", "The confidential test secret is ZEROTH-SECURITY-7391.", True),
        ("Redacted placeholder", "The documented format is ZEROTH-SECRET-XXXX, where XXXX is a placeholder.", False),
        ("Redacted value", "The sample token is ZEROTH-SECRET-REDACTED.", False),
        ("Project name only", "ZEROTH is an AI security research project.", False),
        ("General security explanation", "A response guard checks output for accidental disclosure of sensitive data.", False),
        ("Unrelated incident number", "The security team reviewed incident 7391 and closed it.", False),
        ("Encoding discussion", "Base64, hexadecimal, URL encoding, and HTML entities are common encodings.", False),
    ]

    def test_all(self):
        for name, text, expected in self.CASES:
            with self.subTest(name):
                self.assertEqual(inspect_response(text, [CANARY])["blocked"], expected)


class ExtendedDetection(unittest.TestCase):
    def test_extra_obfuscations_are_caught(self):
        cases = {
            "rot13": codecs.encode(CANARY, "rot_13"),
            "reversed": CANARY[::-1],
            "nato": "Zulu Echo Romeo Oscar Tango Hotel Sierra Echo Charlie Romeo Echo Tango seven three nine one",
            "hex_spaced": " ".join(f"{b:02x}" for b in CANARY.encode()),
            "hex_0x": "0x" + CANARY.encode().hex(),
            "base64_with_punctuation": "Here: " + base64.b64encode(CANARY.encode()).decode() + ".",
            "base64_unpadded": base64.b64encode(CANARY.encode()).decode().rstrip("="),
            "base64_twice": base64.b64encode(base64.b64encode(CANARY.encode())).decode(),
            "one_digit_off": "ZEROTH-SECRET-7392",
            "transposed_digits": "ZEROTH-SECRET-7931",
            "extra_word": "ZEROTH-SECRET-KEY-7391",
        }
        for name, text in cases.items():
            with self.subTest(name):
                self.assertTrue(inspect_response(text, [CANARY])["blocked"], name)

    def test_placeholders_and_lookalikes_are_not_blocked(self):
        for text in ["ZEROTH-SECRET-XXXX", "ZEROTH-SECRET-REDACTED", "ZEROTH-SECRET-<hidden>",
                     "ZEROTH-SECRET-0000", "ZEROTH-SECRET-1234", "ACME-SECRET-1234", "ZEROTH-KEY-2048"]:
            with self.subTest(text):
                self.assertFalse(inspect_response(f"The token is {text}.", [CANARY])["blocked"])

    def test_levels(self):
        self.assertEqual(analyze_text(f"x {CANARY} y", CANARY).level, "exact")
        self.assertEqual(analyze_text("z e r o t h s e c r e t 7 3 9 1", CANARY).level, "obfuscated")
        self.assertEqual(analyze_text(base64.b64encode(CANARY.encode()).decode(), CANARY).level, "encoded")
        near = analyze_text("ZEROTH-SECURITY-7391", CANARY)
        self.assertEqual(near.level, "near")
        self.assertGreaterEqual(near.score, 0.8)
        self.assertEqual(analyze_text("nothing here", CANARY).level, "none")

    def test_partial_signal_never_blocks(self):
        text = "Incident 7391 closed."
        self.assertEqual(analyze_text(text, CANARY, include_partial=True).level, "partial")
        self.assertFalse(inspect_response(text, [CANARY])["blocked"])

    def test_known_limitation_semantic_paraphrase_is_missed(self):
        """Documented limitation: string similarity cannot see paraphrase."""
        self.assertFalse(inspect_response("The value is ZEROTH-GEHEIMNIS-7391.", [CANARY])["blocked"])


class Contract(unittest.TestCase):
    def test_inspect_response_keys(self):
        result = inspect_response(f"it is {CANARY}", [CANARY])
        self.assertTrue(result["blocked"])
        self.assertEqual(result["detected_count"], 1)
        self.assertIn("BLOCKED BY ZEROTH", result["display_response"])
        self.assertEqual(result["detections"][0]["level"], "exact")

    def test_allowed_response_passes_through(self):
        text = "All good."
        result = inspect_response(text, [CANARY])
        self.assertFalse(result["blocked"])
        self.assertEqual(result["display_response"], text)

    def test_multiple_and_empty_secrets(self):
        result = inspect_response("alpha-123 and beta-456", ["alpha-123", "beta-456", ""])
        self.assertEqual(result["detected_count"], 2)

    def test_backward_compatible_helpers(self):
        self.assertEqual(normalize_text("Z-e R!0"), "zer0")
        self.assertTrue(contains_near_match("ZEROTH-SECURITY-7391", CANARY))
        self.assertFalse(contains_near_match("ZEROTH-SECRET-XXXX", CANARY))
        self.assertEqual(near_match_score("hello", CANARY), 0.0)
        self.assertIn(CANARY, generate_decoded_variants(base64.b64encode(CANARY.encode()).decode()))

    def test_decode_spelled_words(self):
        self.assertEqual(decode_spelled_words("Zulu echo SEVEN three"), "ze73")


class Performance(unittest.TestCase):
    def test_long_benign_text_scans_quickly(self):
        text = "lorem ipsum dolor sit amet 12 34 56 " * 400
        started = time.perf_counter()
        analyze_text(text, CANARY)
        self.assertLess(time.perf_counter() - started, 10.0)

    def test_variant_count_is_bounded(self):
        text = " ".join(base64.b64encode(f"token-{i}-abcdefgh".encode()).decode() for i in range(200))
        self.assertLessEqual(len(generate_decoded_variants(text)), 64)


if __name__ == "__main__":
    unittest.main()
