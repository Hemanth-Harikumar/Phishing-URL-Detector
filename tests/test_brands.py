import unittest
from ml.brands import registrable_domain, is_allowlisted, brand_signals, ALLOWLIST


class BrandTests(unittest.TestCase):
    def test_registrable_domain(self):
        self.assertEqual(registrable_domain("login.microsoftonline.com"), "microsoftonline.com")
        self.assertEqual(registrable_domain("www.amazon.co.uk"), "amazon.co.uk")
        self.assertEqual(registrable_domain("a.b.example.com.au"), "example.com.au")

    def test_allowlist_exact_registrable_only(self):
        self.assertTrue(is_allowlisted("login.microsoftonline.com"))
        self.assertTrue(is_allowlisted("www.paypal.com"))
        self.assertFalse(is_allowlisted("paypal.com.evil.tk"))
        self.assertFalse(is_allowlisted("paypal-secure.com"))

    def test_user_content_hosts_not_allowlisted(self):
        self.assertFalse(is_allowlisted("sites.google.com"))
        self.assertFalse(is_allowlisted("docs.google.com"))
        self.assertFalse(is_allowlisted("tenant.sharepoint.com"))

    def test_real_brand_domains_have_no_impersonation_signals(self):
        for host in ("paypal.com", "www.google.com", "login.microsoftonline.com", "aws.amazon.com"):
            s = brand_signals(host)
            self.assertEqual((s["brand_in_subdomain"], s["brand_in_registrable"], s["brand_lookalike"]), (0.0, 0.0, 0.0), host)

    def test_synthetic_impersonation_patterns_are_flagged(self):
        self.assertEqual(brand_signals("paypal.com.secure-login.tk")["brand_in_subdomain"], 1.0)
        self.assertEqual(brand_signals("secure-chase-banking.com")["brand_in_registrable"], 1.0)
        self.assertEqual(brand_signals("paypa1-login.com")["brand_lookalike"], 1.0)
        self.assertEqual(brand_signals("amaz0n-verify.top")["brand_lookalike"], 1.0)
        self.assertEqual(brand_signals("micros0ft-support.click")["brand_lookalike"], 1.0)

    def test_unrelated_words_are_not_flagged(self):
        for host in ("pineapple.com", "stackoverflow.com", "wikipedia.org"):
            s = brand_signals(host)
            self.assertEqual(s["brand_in_registrable"] + s["brand_in_subdomain"] + s["brand_lookalike"], 0.0, host)

    def test_ip_and_garbage_hosts_do_not_crash(self):
        self.assertEqual(brand_signals("192.168.1.10")["brand_lookalike"], 0.0)
        self.assertEqual(brand_signals("")["brand_lookalike"], 0.0)

    def test_allowlist_is_not_empty(self):
        self.assertGreater(len(ALLOWLIST), 40)


if __name__ == "__main__":
    unittest.main()
