import unittest
from unittest.mock import patch

from backend.remote_risk_model import estimate_remote, features


class RemoteRiskModelTests(unittest.TestCase):
    def test_missing_scores_are_explicit_assumptions(self):
        payload, sources = features(
            {"severity": "high", "patching_status": "unknown", "cvss_score": None, "epss_score": None},
            {"asset_value": 50000000, "criticality": 4}, {}, {})
        self.assertEqual(payload["likelihood"]["cvss_score"], 8.0)
        self.assertEqual(payload["likelihood"]["epss_score"], .05)
        self.assertEqual(sources["cvss_score"], "assumed")
        self.assertEqual(sources["epss_score"], "assumed")
        self.assertEqual(payload["impact"]["data_type"], "Financial")

    @patch("backend.remote_risk_model.infer_many")
    def test_remote_eal_uses_one_score_per_issue_and_overlap(self, infer):
        infer.return_value = [
            {"likelihood": {"incident_probability": .2}, "impact": {"total_loss_inr": 1000}, "monte_carlo": {"eal_inr": 100, "var_95_inr": 300}},
            {"likelihood": {"incident_probability": .1}, "impact": {"total_loss_inr": 500}, "monte_carlo": {"eal_inr": 50, "var_95_inr": 100}},
        ]
        asset = {"asset_id": "a", "asset_value": 10000, "criticality": 4}
        rows = [{"source": "zap", "title": "A", "severity": "high"},
                {"source": "zap", "title": "A", "severity": "high"},
                {"source": "nmap", "title": "B", "severity": "low"}]
        result = estimate_remote(asset, rows, {}, {})
        self.assertEqual(len(infer.call_args.args[0]), 2)
        self.assertEqual(result["ale"], 117.5)
        self.assertEqual(result["estimatedValueAtRisk"], 335)


if __name__ == "__main__":
    unittest.main()
