import unittest
from ml.web_helpers import validate_url, risk_level


class AppHelperTests(unittest.TestCase):
    def test_validate_rejects_empty_and_bad_input(self):
        for bad in ("", "   ", "ftp://example.com", "http://nodot", "https://exa\x01mple.com", "http://example.com:99999", "a" * 3000):
            url, err = validate_url(bad)
            self.assertIsNone(url, bad[:30])
            self.assertTrue(err)

    def test_validate_accepts_schemeless_url(self):
        url, err = validate_url("example.com/path")
        self.assertIsNone(err)
        self.assertTrue(url.startswith("https://example.com"))

    def test_risk_level_boundaries(self):
        self.assertEqual(risk_level(74)[0], "MEDIUM")
        self.assertEqual(risk_level(75)[0], "HIGH")
        self.assertEqual(risk_level(29)[0], "LOW")
        self.assertEqual(risk_level(30)[0], "MEDIUM")


if __name__ == "__main__":
    unittest.main()
