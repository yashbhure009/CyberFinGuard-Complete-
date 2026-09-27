import unittest

from backend.risk_estimation import estimate_asset


class RiskEstimationTests(unittest.TestCase):
    def setUp(self):
        self.asset = {"asset_id": "site-1", "asset_name": "Site", "asset_value": 1_000_000,
                      "criticality": 5, "business_unit": "Operations"}
        self.finding = {"source": "zap", "title": "Content Security Policy Header Not Set",
                        "severity": "medium", "epss_score": None, "cisa_kev": False,
                        "patching_status": "unknown"}

    def test_repeat_observation_does_not_inflate_loss(self):
        once, recommendations = estimate_asset(self.asset, [self.finding])
        repeated, _ = estimate_asset(self.asset, [self.finding, dict(self.finding)])
        self.assertEqual(once["ale"], repeated["ale"])
        self.assertEqual(once["modeled_issues"], 1)
        self.assertEqual(recommendations[0]["control_name"], "Harden web security headers")

    def test_missing_asset_value_stays_unestimated(self):
        summary, recommendations = estimate_asset({**self.asset, "asset_value": None}, [self.finding])
        self.assertIsNone(summary)
        self.assertEqual(recommendations, [])


if __name__ == "__main__":
    unittest.main()
