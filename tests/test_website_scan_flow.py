import unittest
from unittest.mock import patch

import main


class WebsiteScanFlowTests(unittest.TestCase):
    @patch("backend.live_api.mapped", return_value=[{"mappings": [{"framework": "ISO 27001"}]}])
    def test_scanner_reference_does_not_become_compliance_score(self, mapped):
        from backend.live_api import app
        result = app.test_client().get("/api/compliance/summary")
        self.assertEqual(result.status_code, 200)
        self.assertIsNone(result.json["frameworks"][0]["coverage_percent"])
        self.assertEqual(result.json["frameworks"][0]["assessment_status"], "not_assessed")

    @patch("backend.live_api.threading.Thread")
    @patch("backend.live_api.query")
    @patch("backend.live_api.distinct_findings", return_value=[{"finding_id": "scan-1"}])
    @patch("backend.live_api.assessment_context", return_value=({"asset_id": "site-a", "asset_name": "example.test"}, {"asset_value": 100}))
    @patch("backend.live_api.state", return_value={"website_asset_id": "site-a", "target_url": "https://example.test"})
    @patch("backend.live_api.completed_scan_available", return_value=True)
    def test_submit_returns_after_database_save_before_model_call(self, available, state, context,
                                                                 findings, query, thread):
        from backend.live_api import app
        query.side_effect = [[{"assessment_id": 42}], None]
        result = app.test_client().post("/api/assessment/submit", json={
            "controls": {"mfa": "Yes", "waf": "No", "edr": "Yes"}})
        self.assertEqual(result.status_code, 202)
        self.assertEqual(result.json["assessment_id"], 42)
        self.assertEqual(result.json["status"], "pending")
        thread.return_value.start.assert_called_once()

    def test_scan_time_matches_utc_database_clock(self):
        from backend.scan_time import database_scan_start

        self.assertEqual(database_scan_start("2026-09-17T04:34:01+05:30").isoformat(),
                         "2026-09-16T23:04:01")

    @patch("backend.live_api.query")
    @patch("backend.live_api.SCAN_STATUS")
    def test_old_assessment_cannot_populate_new_scan_dashboard(self, status, query):
        from backend.live_api import latest_assessment
        status.exists.return_value = True
        status.read_text.return_value = '{"status":"complete"}'
        self.assertIsNone(latest_assessment("site-a"))
        query.assert_not_called()

    @patch("backend.live_api.query", return_value=[])
    @patch("backend.live_api.state", return_value={"website_asset_id": "site-a"})
    @patch("backend.live_api.SCAN_STATUS")
    def test_dashboard_reads_only_current_scan_rows(self, status, state, query):
        from backend.live_api import findings
        status.exists.return_value = True
        status.read_text.return_value = '{"status":"running","asset_id":"site-a","started_at":"2026-09-17T04:00:00"}'
        self.assertEqual(findings(), [])
        sql, params = query.call_args.args
        self.assertIn("f.asset_id=%s AND f.created_at >= %s", sql)
        self.assertEqual(params[0], "site-a")

    @patch("main.update_scan_status")
    @patch("main.save_unified_output", return_value="latest.json")
    @patch("main.fetch_unified_findings", return_value=[])
    @patch("main.run_threat_intel_enricher", return_value={"source": "threat_intel", "enriched": 0})
    @patch("main.run_nuclei", return_value={"source": "nuclei", "findings_ingested": 0})
    @patch("main.run_zap_manual", return_value={"source": "zap", "findings_ingested": 0})
    @patch("main.load_user_config", return_value={})
    @patch("main.run_nmap")
    @patch("main.run_wazuh")
    @patch("main.run_prowler")
    @patch("main.run_keycloak")
    @patch("main.get_ip_from_hostname")
    def test_website_scan_needs_only_url(self, resolve, keycloak, prowler, wazuh, nmap,
                                         config, zap, nuclei, threat, output, save, status):
        main.main("https://example.test/path")
        self.assertEqual(zap.call_args.kwargs["target_url"], "https://example.test/path")
        self.assertEqual(nuclei.call_args.kwargs["target"], "https://example.test/path")
        for unrelated in (resolve, nmap, wazuh, prowler, keycloak):
            unrelated.assert_not_called()


if __name__ == "__main__":
    unittest.main()
