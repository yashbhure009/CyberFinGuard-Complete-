import unittest
from unittest.mock import patch

from backend.assessment_pipeline import validate_controls, validate_impact, transform_stored_record, calculate_model_summary
from backend.pdf_report import pdf_from_lines


IMPACT = {"asset_value": 50000000, "customers_affected": 50, "records_affected": 100,
          "downtime_hours": 8, "recovery_time_hours": 12, "recovery_capability": .7,
          "business_continuity_score": .6, "revenue_per_hour": 250000,
          "data_sensitivity": "Confidential", "data_type": "Financial",
          "regulatory_jurisdiction": "DPDPA", "backup_availability": "Yes"}


class AssessmentPipelineTests(unittest.TestCase):
    def test_only_three_controls_are_writable(self):
        self.assertEqual(validate_controls({"mfa": "Yes", "waf": "No", "edr": "Yes"})["mfa"], "Yes")
        with self.assertRaises(ValueError):
            validate_controls({"mfa": "Yes", "waf": "No", "edr": "Yes", "cvss_score": 10})

    def test_impact_requires_exact_valid_fields(self):
        self.assertEqual(validate_impact(IMPACT)["records_affected"], 100)
        with self.assertRaises(ValueError):
            validate_impact({**IMPACT, "records_affected": -1})

    def test_stored_record_transforms_to_exact_model_shape(self):
        raw = {"asset": {"asset_id": "a", "asset_value": 50000000, "criticality": 4},
               "impact": IMPACT, "controls": {"mfa": "Yes", "waf": "No", "edr": "Yes"},
               "findings": [{"finding_id": "f", "source": "zap", "title": "Alert",
                             "severity": "high", "cvss_score": None, "epss_score": None,
                             "patching_status": "unknown", "mfa_enabled": False}]}
        item = transform_stored_record(raw)[0]
        self.assertEqual(set(item["payload"]), {"likelihood", "impact"})
        self.assertEqual(len(item["payload"]["likelihood"]), 11)
        self.assertEqual(len(item["payload"]["impact"]), 13)
        self.assertEqual(item["payload"]["likelihood"]["mfa"], "Yes")
        self.assertEqual(item["payload"]["impact"]["records_affected"], 100)

    def test_pdf_has_valid_header_and_summary_text(self):
        result = pdf_from_lines(["Risk summary", "ALE INR 100"])
        self.assertTrue(result.startswith(b"%PDF-1.4"))
        self.assertIn(b"Risk summary", result)
        self.assertIn(b"%%EOF", result)

    def test_pdf_endpoint_downloads_saved_assessment(self):
        from backend.live_api import app
        saved = {"assessment_id": 42, "status": "complete", "created_at": "2026-09-17",
                 "raw_input": {"asset": {"asset_id": "a", "asset_name": "Example", "asset_value": 1000},
                               "impact": IMPACT, "findings": []},
                 "model_result": {"ale": 100, "estimatedValueAtRisk": 200,
                                  "likelihood_score": .2, "impact_score": .3,
                                  "estimation_method": "hosted-ml-db-v1", "model_results": []}}
        with patch("backend.live_api.state", return_value={"website_asset_id": "a"}), \
             patch("backend.live_api.latest_assessment", return_value=saved), \
             patch("backend.live_api.estimate_asset", return_value=({}, [])):
            response = app.test_client().get("/api/assessment/summary.pdf")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/pdf")
        self.assertTrue(response.data.startswith(b"%PDF-1.4"))


if __name__ == "__main__":
    unittest.main()
