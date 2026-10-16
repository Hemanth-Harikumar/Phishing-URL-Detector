import unittest
from ml.url_features import FEATURE_NAMES, extract_url_features, feature_vector

class URLFeatureTests(unittest.TestCase):
    def test_feature_schema_is_stable(self):
        values = extract_url_features('https://example.com/path?a=1')
        self.assertEqual(list(values), FEATURE_NAMES)
        self.assertEqual(len(feature_vector('https://example.com')), len(FEATURE_NAMES))

    def test_ip_host_is_detected(self):
        self.assertEqual(extract_url_features('http://192.168.1.10/login')['hostname_is_ip'], 1.0)

    def test_punycode_is_detected(self):
        self.assertEqual(extract_url_features('https://xn--pple-43d.com')['punycode_hostname'], 1.0)

    def test_scheme_and_www_do_not_change_features(self):
        self.assertEqual(extract_url_features('https://www.github.com'), extract_url_features('http://github.com'))

    def test_benign_path_does_not_change_hostname_features(self):
        self.assertEqual(extract_url_features('https://github.com'), extract_url_features('https://github.com/anthropics'))

    def test_hostname_suspicious_words_detected(self):
        self.assertGreater(extract_url_features('https://secure-login-example.xyz/account')['suspicious_hostname_keyword_count'], 0)

    def test_empty_input_does_not_crash(self):
        self.assertEqual(len(extract_url_features('')), len(FEATURE_NAMES))

    def test_brand_features_in_schema(self):
        v = extract_url_features('https://paypal.com.secure-login.tk')
        self.assertEqual(v['brand_in_subdomain'], 1.0)
        self.assertEqual(extract_url_features('https://paypal.com')['brand_in_subdomain'], 0.0)

if __name__ == '__main__':
    unittest.main()


class SuspiciousHostWordRegressionTests(unittest.TestCase):
    def test_wallet_keyword_is_not_damaged_by_www_normalization(self):
        from ml.url_features import suspicious_host_words
        self.assertIn("wallet", suspicious_host_words("wallet.com"))
        self.assertIn("wallet", suspicious_host_words("www.wallet.com"))

    def test_only_exact_www_prefix_is_removed(self):
        from ml.url_features import suspicious_host_words
        self.assertIn("wallet", suspicious_host_words("www.wallet.com"))
        self.assertIn("login", suspicious_host_words("login-wallet.example"))

    def test_hostname_normalization_is_case_insensitive(self):
        from ml.url_features import suspicious_host_words
        self.assertIn("secure", suspicious_host_words("WWW.SECURE-EXAMPLE.COM."))
