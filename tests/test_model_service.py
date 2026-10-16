import unittest
from ml.model_service import PhishingModel, MODEL_PATH
from ml.url_features import FEATURE_NAMES


class ModelServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = PhishingModel()

    def test_bundled_model_exists(self):
        self.assertTrue(MODEL_PATH.exists(), "Train the model or restore the bundled model file.")

    def test_prediction_shape_and_probability(self):
        result = self.model.predict("https://www.google.com")
        self.assertGreaterEqual(result["phishing_probability"], 0.0)
        self.assertLessEqual(result["phishing_probability"], 1.0)
        self.assertEqual(len(result["features"]), len(FEATURE_NAMES))
        # decision_threshold may be overridden by the MODEL_THRESHOLD env var;
        # only assert against the stored value when no override is active.
        from ml.model_service import _THRESHOLD_OVERRIDE
        if _THRESHOLD_OVERRIDE is None:
            self.assertEqual(result["decision_threshold"], self.model.metadata["threshold"])
        else:
            self.assertEqual(result["decision_threshold"], _THRESHOLD_OVERRIDE)

    def test_allowlisted_domain_overrides_verdict(self):
        result = self.model.predict("https://login.microsoftonline.com/")
        self.assertTrue(result["known_domain"])
        self.assertFalse(result["is_phishing"])
        self.assertFalse(result["needs_review"])

    def test_user_content_host_is_not_overridden(self):
        self.assertFalse(self.model.predict("https://sites.google.com/view/x")["known_domain"])

    def test_obvious_impersonation_is_flagged(self):
        for url in ("https://paypal.com.secure-login.tk/", "http://paypal-secure-login.verify-account.xyz/signin"):
            self.assertTrue(self.model.predict(url)["is_phishing"], url)

    def test_scheme_and_www_do_not_change_probability(self):
        a = self.model.predict("https://www.example-shop.com/a")["phishing_probability"]
        b = self.model.predict("http://example-shop.com/b")["phishing_probability"]
        # The two URLs differ only in scheme and www prefix, which are normalised away
        # before feature extraction. The resulting probabilities should be identical or
        # differ only by sub-nanosecond IEEE-754 rounding — not a meaningful model delta.
        self.assertAlmostEqual(a, b, places=10)


if __name__ == "__main__":
    unittest.main()
