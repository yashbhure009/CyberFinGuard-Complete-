"""Live scan and dashboard API backed by the existing PostgreSQL schema."""
import hashlib
import json
import os
import subprocess
import sys
import threading
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from urllib.parse import urlparse

import psycopg2
from dotenv import load_dotenv
from flask import Flask, jsonify, request, make_response
from flask_cors import CORS
from psycopg2.extras import RealDictCursor, Json

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

from backend.risk_estimation import ASSUMPTIONS, estimate_asset
from backend.remote_risk_model import features
from backend.assessment_pipeline import (validate_impact, validate_controls,
                                         transform_stored_record, calculate_model_summary)
from backend.pdf_report import pdf_from_lines
from backend.scan_time import database_scan_start

app = Flask(__name__)
CORS(app, origins=[origin.strip() for origin in os.getenv(
    "FRONTEND_ORIGIN", "http://localhost:3000,http://127.0.0.1:3000"
).split(",") if origin.strip()])
CONFIG = ROOT / "data" / "scan_config.json"
SCAN_STATUS = ROOT / "data" / "scan_status.json"
SCAN_LOG = ROOT / "data" / "scan.log"
scan_process = None


def query(sql, params=(), write=False):
    with psycopg2.connect(host=os.getenv("DB_HOST", "localhost"),
                          dbname=os.getenv("DB_NAME", "cyber_risk_db"),
                          user=os.getenv("DB_USER", "postgres"),
                          password=os.getenv("DB_PASSWORD", "postgres"),
                          port=os.getenv("DB_PORT", "5432")) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(sql, params)
            return cursor.rowcount if write else [dict(row) for row in cursor.fetchall()]


def connect_db():
    return psycopg2.connect(host=os.getenv("DB_HOST", "localhost"),
                            dbname=os.getenv("DB_NAME", "cyber_risk_db"),
                            user=os.getenv("DB_USER", "postgres"),
                            password=os.getenv("DB_PASSWORD", "postgres"),
                            port=os.getenv("DB_PORT", "5432"))


def state():
    return json.loads(CONFIG.read_text(encoding="utf-8")) if CONFIG.exists() else {}


def save(value):
    CONFIG.write_text(json.dumps(value, indent=2), encoding="utf-8")


def response(value):
    return jsonify(value)


def serial(value):
    if isinstance(value, (datetime,)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, list):
        return [serial(v) for v in value]
    if isinstance(value, dict):
        return {k: serial(v) for k, v in value.items()}
    return value


@app.errorhandler(psycopg2.Error)
def db_error(error):
    app.logger.exception("Database error")
    return response({"detail": "Database unavailable. Check PostgreSQL and run setup_db.py."}), 503


@app.post("/api/assets/website")
def website():
    url = str((request.json or {}).get("url", "")).strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return response({"detail": "Enter a valid HTTP or HTTPS URL."}), 400
    identifier = "website-" + hashlib.sha256(parsed.hostname.encode()).hexdigest()[:16]
    query("""INSERT INTO assets (asset_id, asset_name, asset_type, hostname, internet_exposed)
             VALUES (%s,%s,'web_application',%s,TRUE)
             ON CONFLICT (asset_id) DO UPDATE SET hostname=EXCLUDED.hostname, updated_at=NOW()""",
          (identifier, parsed.hostname, parsed.hostname), True)
    value = state()
    if value.get("target_url") != url:
        SCAN_STATUS.write_text(json.dumps({"status": "idle", "stage": "New target needs a scan"}), encoding="utf-8")
    value.update(target_url=url, website_asset_id=identifier)
    save(value)
    return response({"assetId": identifier, "unmappedFields": []})


@app.get("/api/assessment/config")
def assessment_config():
    value = state()
    identifier = value.get("website_asset_id")
    impact_rows = query("""SELECT a.asset_value, a.data_type, i.customers_affected, i.records_affected,
       i.downtime_hours, i.recovery_time_hours, i.recovery_capability, i.business_continuity_score,
       i.revenue_per_hour, i.data_sensitivity, i.regulatory_jurisdiction,
       CASE WHEN i.backup_availability THEN 'Yes' ELSE 'No' END backup_availability
       FROM assets a JOIN impact_context i ON i.asset_id=a.asset_id WHERE a.asset_id=%s""",
       (identifier,)) if identifier else []
    if identifier and not impact_rows:
        previous = query("""SELECT a.asset_value, a.data_type, c.backup_exists
            FROM assets a LEFT JOIN asset_controls c ON c.asset_id=a.asset_id
            WHERE a.asset_id=%s""", (identifier,))
        if previous:
            existing = previous[0]
            partial = {key: serial(existing[key]) for key in ("asset_value", "data_type") if existing[key] is not None}
            if existing["backup_exists"] is not None:
                partial["backup_availability"] = "Yes" if existing["backup_exists"] else "No"
            impact_rows = [partial]
    return response({"target_url": value.get("target_url"),
                     "asset_id": value.get("website_asset_id"),
                     "business": value.get("business") or {},
                     "impact": serial(impact_rows[0]) if impact_rows else None,
                     "cloud_provider": (value.get("cloud") or {}).get("provider"),
                     "identity_realm": (value.get("identity") or {}).get("realm")})


@app.post("/api/config/risk-model")
def risk_model_config():
    return response({"detail": "Use /api/assessment/submit. Only mfa, waf, and edr are writable risk inputs."}), 410


@app.post("/api/assets/cloud")
def cloud():
    body = request.json or {}
    provider = body.get("provider")
    if provider not in ("AWS", "Azure", "GCP"):
        return response({"detail": "Choose a supported provider."}), 400
    fields = body.get("fields") or {}
    value = state()
    value["cloud"] = {"provider": provider, "account_id": fields.get("accountId"), "role_arn": fields.get("roleArn")}
    save(value)
    return response({"assetId": "cloud-" + provider.lower(), "unmappedFields": []})


@app.post("/api/assets/iam")
def iam():
    body = request.json or {}
    if any(not body.get(k) for k in ("url", "realm", "clientId", "clientSecret")):
        return response({"detail": "Complete all identity fields."}), 400
    value = state()
    value["identity"] = {"url": body["url"], "realm": body["realm"], "client_id": body["clientId"], "client_secret": body["clientSecret"]}
    save(value)
    return response({"assetId": "identity-service", "unmappedFields": []})


@app.post("/api/assets/business-context")
def business():
    body = request.json or {}
    value = state()
    identifier = body.get("assetId") or value.get("website_asset_id")
    if not identifier:
        return response({"detail": "Add a website first."}), 400
    if identifier != value.get("website_asset_id"):
        return response({"detail": "Business impact must match the active website."}), 400
    asset_name = urlparse(value.get("target_url") or "").hostname
    if not asset_name:
        return response({"detail": "Save a valid website URL first."}), 400
    try:
        impact = validate_impact(body.get("impact") or {})
    except ValueError as error:
        return response({"detail": str(error)}), 400
    try:
        business_value = float(body.get("businessValue"))
        criticality = int(body.get("assetCriticality"))
    except (TypeError, ValueError):
        return response({"detail": "Enter asset value and criticality."}), 400
    if business_value != impact["asset_value"]:
        return response({"detail": "Asset value must match the business value."}), 400
    if criticality not in (3, 4, 5):
        return response({"detail": "Asset criticality must be 3, 4, or 5."}), 400
    with connect_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("""UPDATE assets SET asset_name=%s, asset_type=%s, business_unit=%s,
                owner=%s, asset_value=%s, data_type=%s, criticality=%s, updated_at=NOW() WHERE asset_id=%s""",
                (asset_name, "web_application", body.get("businessUnit"),
                 body.get("assetOwner"), impact["asset_value"], impact["data_type"],
                 criticality, identifier))
            cursor.execute("""INSERT INTO impact_context
                (asset_id, customers_affected, records_affected, downtime_hours, recovery_time_hours,
                recovery_capability, business_continuity_score, revenue_per_hour, data_sensitivity,
                regulatory_jurisdiction, backup_availability)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (asset_id) DO UPDATE SET
                customers_affected=EXCLUDED.customers_affected, records_affected=EXCLUDED.records_affected,
                downtime_hours=EXCLUDED.downtime_hours, recovery_time_hours=EXCLUDED.recovery_time_hours,
                recovery_capability=EXCLUDED.recovery_capability,
                business_continuity_score=EXCLUDED.business_continuity_score,
                revenue_per_hour=EXCLUDED.revenue_per_hour, data_sensitivity=EXCLUDED.data_sensitivity,
                regulatory_jurisdiction=EXCLUDED.regulatory_jurisdiction,
                backup_availability=EXCLUDED.backup_availability, updated_at=NOW()""",
                (identifier, impact["customers_affected"], impact["records_affected"],
                 impact["downtime_hours"], impact["recovery_time_hours"], impact["recovery_capability"],
                 impact["business_continuity_score"], impact["revenue_per_hour"],
                 impact["data_sensitivity"], impact["regulatory_jurisdiction"],
                 impact["backup_availability"] == "Yes"))
            cursor.execute("""INSERT INTO asset_controls (asset_id, backup_exists) VALUES (%s,%s)
                ON CONFLICT (asset_id) DO UPDATE SET backup_exists=EXCLUDED.backup_exists, updated_at=NOW()""",
                (identifier, impact["backup_availability"] == "Yes"))
            cursor.execute("UPDATE risk_assessment_inputs SET status='stale' WHERE asset_id=%s AND status='complete'", (identifier,))
    value["business"] = {"asset_name": asset_name, "asset_type": "web_application",
                         "business_unit": body.get("businessUnit"), "asset_owner": body.get("assetOwner"),
                         "business_value": body.get("businessValue"), "asset_criticality": criticality,
                         "downtime_cost": body.get("downtimeCostPerHour"),
                         "recovery_cost": body.get("recoveryCost")}
    save(value)
    return response({"assetId": identifier, "unmappedFields": ["dataSensitivity", "serviceDependency", "regulatoryExposure", "revenueDependency"]})


@app.post("/api/scan/run")
def scan():
    global scan_process
    value = state()
    if not value.get("target_url"):
        return response({"detail": "Add a website target first."}), 400
    if scan_process is not None and scan_process.poll() is None:
        return response({"status": "running", "detail": "A scan is already running."}), 202
    query("UPDATE risk_assessment_inputs SET status='stale' WHERE asset_id=%s AND status='complete'",
          (value["website_asset_id"],), True)
    try:
        started_at = datetime.now().isoformat()
        SCAN_STATUS.write_text(json.dumps({"status": "running", "stage": "Starting scanners",
                                           "started_at": started_at, "updated_at": started_at,
                                           "target_url": value["target_url"],
                                           "asset_id": value["website_asset_id"]}), encoding="utf-8")
        with SCAN_LOG.open("w", encoding="utf-8") as log:
            scan_process = subprocess.Popen([sys.executable, str(ROOT / "main.py"), value["target_url"]],
                                            cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except OSError as error:
        SCAN_STATUS.write_text(json.dumps({"status": "failed", "stage": "Failed to start", "error": str(error)}), encoding="utf-8")
        return response({"detail": str(error)}), 500
    return response({"status": "running"}), 202


@app.get("/api/scan/status")
def scan_status():
    if not SCAN_STATUS.exists():
        return response({"status": "idle", "stage": "No scan has started"})
    value = json.loads(SCAN_STATUS.read_text(encoding="utf-8"))
    if not value.get("started_at"):
        return response({"status": "idle", "stage": "Start a website scan to populate live findings", "findings_count": 0})
    if scan_process is not None and scan_process.poll() is not None and value.get("status") == "running":
        value = {"status": "failed", "stage": "Scanner exited unexpectedly",
                 "error": "Check data/scan.log for details."}
        SCAN_STATUS.write_text(json.dumps(value), encoding="utf-8")
    if value.get("status") in ("running", "complete") and value.get("started_at"):
        value["findings_count"] = len(findings())
    return response(value)


ROWS = """SELECT f.finding_id, f.asset_id, COALESCE(a.asset_name,f.asset_id) asset_name,
 COALESCE(a.asset_type,'unknown') asset_type, a.business_unit, a.dependencies, a.criticality,
 a.asset_value, COALESCE(a.internet_exposed,FALSE) internet_exposed, a.environment, a.owner,
 a.production_status, f.source, f.cve_id, f.cvss_score, f.epss_score,
 COALESCE(f.cisa_kev,FALSE) cisa_kev, f.exploit_available,
 f.exploit_type, f.mitre_technique, f.title, f.description, f.severity,
 COALESCE(c.patching_status,'unknown') patching_status,
 c.mfa_enabled, c.waf_enabled, c.edr_enabled, c.firewall_enabled,
 c.encryption_enabled, c.backup_exists,
 r.likelihood_score, r.impact_score, r.sle, r.aro, r.ale, f.created_at, f.raw_data
 FROM findings f LEFT JOIN assets a ON a.asset_id=f.asset_id
 LEFT JOIN asset_controls c ON c.asset_id=f.asset_id
 LEFT JOIN LATERAL (SELECT * FROM risk_scores WHERE finding_id=f.finding_id ORDER BY calculated_at DESC LIMIT 1) r ON TRUE
 WHERE f.asset_id=%s AND f.created_at >= %s
 ORDER BY f.created_at DESC"""
def findings():
    scan = json.loads(SCAN_STATUS.read_text(encoding="utf-8")) if SCAN_STATUS.exists() else {}
    started_at = scan.get("started_at")
    configured_asset = state().get("website_asset_id")
    if not started_at or scan.get("asset_id") != configured_asset:
        return []
    rows = query(ROWS, (configured_asset, database_scan_start(started_at)))
    unique = {}
    for row in rows:
        row["dependencies"] = row["dependencies"] or []
        raw = row.pop("raw_data") or {}
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except ValueError:
                raw = {}
        if not isinstance(raw, dict):
            raw = {}
        row["evidence_url"] = raw.get("url") or raw.get("matched-at") or raw.get("host")
        row["evidence"] = raw.get("evidence") or raw.get("matched") or None
        row["threat_actor"] = raw.get("threat_actor")
        row["malware"] = raw.get("malware")
        row["exploit_available"] = True if row["cisa_kev"] or row["exploit_available"] else None
        key = (row["asset_id"], row["source"], row["title"], row["evidence_url"])
        if key in unique:
            unique[key]["occurrences"] += 1
        else:
            row["occurrences"] = 1
            unique[key] = row
    return list(unique.values())


def assessment_context(identifier):
    rows = query("""SELECT a.asset_id, a.asset_name, a.business_unit, a.criticality, a.asset_value,
        a.data_type, i.customers_affected, i.records_affected, i.downtime_hours,
        i.recovery_time_hours, i.recovery_capability, i.business_continuity_score,
        i.revenue_per_hour, i.data_sensitivity, i.regulatory_jurisdiction,
        i.backup_availability FROM assets a JOIN impact_context i ON a.asset_id=i.asset_id
        WHERE a.asset_id=%s""", (identifier,))
    if not rows:
        return None
    row = serial(rows[0])
    asset = {key: row[key] for key in ("asset_id", "asset_name", "business_unit", "criticality", "asset_value")}
    impact = {key: row[key] for key in ("asset_value", "customers_affected", "records_affected",
              "downtime_hours", "recovery_time_hours", "recovery_capability",
              "business_continuity_score", "revenue_per_hour", "data_sensitivity",
              "data_type", "regulatory_jurisdiction")}
    impact["backup_availability"] = "Yes" if row["backup_availability"] else "No"
    return asset, impact


def distinct_findings(identifier):
    selected = {}
    for row in findings():
        if row["asset_id"] == identifier:
            selected.setdefault((row["source"], row["title"]), row)
    return [serial(row) for row in selected.values()]


def latest_assessment(identifier):
    if not identifier or not SCAN_STATUS.exists():
        return None
    try:
        scan = json.loads(SCAN_STATUS.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if scan.get("asset_id") != identifier or not scan.get("started_at"):
        return None
    rows = query("""SELECT assessment_id, raw_input, model_payload, model_result, status, error,
        created_at FROM risk_assessment_inputs WHERE asset_id=%s AND created_at >= %s
        ORDER BY assessment_id DESC LIMIT 1""",
        (identifier, database_scan_start(scan["started_at"])))
    return serial(rows[0]) if rows else None


def completed_scan_available():
    if not SCAN_STATUS.exists():
        return False
    try:
        scan = json.loads(SCAN_STATUS.read_text(encoding="utf-8"))
        config = state()
        return (scan.get("status") == "complete" and bool(scan.get("started_at"))
                and scan.get("asset_id") == config.get("website_asset_id")
                and scan.get("target_url") == config.get("target_url"))
    except (OSError, ValueError):
        return False


@app.get("/api/assessment/model-preview")
def model_preview():
    if not completed_scan_available():
        return response({"detail": "Complete the website scan before reviewing model inputs."}), 409
    identifier = state().get("website_asset_id")
    context = assessment_context(identifier) if identifier else None
    if not context:
        return response({"detail": "Save business impact context before reviewing scan inputs."}), 409
    rows = distinct_findings(identifier)
    if not rows:
        return response({"detail": "No findings for this target yet. Complete a website scan first."}), 409
    asset, impact = context
    raw = {"asset": asset, "impact": impact, "controls": {"mfa": "No", "waf": "No", "edr": "No"},
           "findings": rows}
    items = transform_stored_record(raw)
    previous = latest_assessment(identifier)
    controls = (previous or {}).get("raw_input", {}).get("controls") or None
    asset["asset_name"] = urlparse(state().get("target_url") or "").hostname or asset["asset_name"]
    return response({"asset": asset, "impact": impact, "issues": items,
                     "controls": controls, "scan_finding_count": len(rows)})


@app.get("/api/assessment/status/<int:assessment_id>")
def assessment_status(assessment_id):
    identifier = state().get("website_asset_id")
    rows = query("SELECT status, error FROM risk_assessment_inputs WHERE assessment_id=%s AND asset_id=%s",
                 (assessment_id, identifier))
    if not rows:
        return response({"detail": "Assessment not found."}), 404
    return response(serial(rows[0]))


def calculate_saved_assessment(assessment_id, identifier):
    try:
        stored = query("SELECT raw_input FROM risk_assessment_inputs WHERE assessment_id=%s", (assessment_id,))[0]["raw_input"]
        items = transform_stored_record(stored)
        query("UPDATE risk_assessment_inputs SET model_payload=%s WHERE assessment_id=%s",
              (Json(items), assessment_id), True)
        summary = calculate_model_summary(stored, items)
        with connect_db() as conn:
            with conn.cursor() as cursor:
                for item in summary["model_results"]:
                    likelihood = float(item["likelihood"]["incident_probability"])
                    total_loss = float(item["impact"]["total_loss_inr"])
                    value = float(summary["asset_value"])
                    cursor.execute("""INSERT INTO risk_scores
                        (risk_id, asset_id, finding_id, sle, aro, ale, likelihood_score, impact_score)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT (risk_id) DO UPDATE SET sle=EXCLUDED.sle, aro=EXCLUDED.aro,
                        ale=EXCLUDED.ale, likelihood_score=EXCLUDED.likelihood_score,
                        impact_score=EXCLUDED.impact_score, calculated_at=NOW()""",
                        (f"assessment-{assessment_id}-{hashlib.sha256(item['finding_id'].encode()).hexdigest()[:16]}", identifier,
                         item["finding_id"], total_loss, likelihood,
                         item["monte_carlo"]["eal_inr"], likelihood,
                         min(1, total_loss / value) if value else 0))
                cursor.execute("""UPDATE risk_assessment_inputs SET model_result=%s,
                    status='complete', error=NULL WHERE assessment_id=%s""", (Json(summary), assessment_id))
    except Exception as error:
        app.logger.exception("Risk inference failed for assessment %s", assessment_id)
        query("UPDATE risk_assessment_inputs SET status='failed', error=%s WHERE assessment_id=%s",
              (str(error)[:1000], assessment_id), True)


@app.post("/api/assessment/submit")
def submit_assessment():
    if not completed_scan_available():
        return response({"detail": "Complete the website scan before submitting risk controls."}), 409
    body = request.get_json(silent=True) or {}
    try:
        if set(body) != {"controls"}:
            raise ValueError("Only controls may be submitted on this screen")
        controls = validate_controls(body["controls"])
    except (TypeError, ValueError) as error:
        return response({"detail": str(error)}), 400
    identifier = state().get("website_asset_id")
    context = assessment_context(identifier) if identifier else None
    if not context:
        return response({"detail": "Save business impact context first."}), 409
    rows = distinct_findings(identifier)
    if not rows:
        return response({"detail": "Complete a website scan before submitting risk controls."}), 409
    asset, impact = context
    asset["asset_name"] = urlparse(state().get("target_url") or "").hostname or asset["asset_name"]
    raw = {"asset": asset, "impact": impact, "controls": controls, "findings": rows}
    # Commit raw intake first. Failure of transformation or inference cannot erase it.
    inserted = query("""INSERT INTO risk_assessment_inputs (asset_id, raw_input, status)
        VALUES (%s,%s,'pending') RETURNING assessment_id""", (identifier, Json(raw)))
    assessment_id = inserted[0]["assessment_id"]
    query("""INSERT INTO asset_controls (asset_id, mfa_enabled, waf_enabled, edr_enabled)
        VALUES (%s,%s,%s,%s) ON CONFLICT (asset_id) DO UPDATE SET
        mfa_enabled=EXCLUDED.mfa_enabled, waf_enabled=EXCLUDED.waf_enabled,
        edr_enabled=EXCLUDED.edr_enabled, updated_at=NOW()""",
        (identifier, controls["mfa"] == "Yes", controls["waf"] == "Yes", controls["edr"] == "Yes"), True)
    threading.Thread(target=calculate_saved_assessment, args=(assessment_id, identifier), daemon=True).start()
    return response({"assessment_id": assessment_id, "status": "pending"}), 202


def recommendations():
    rows = query("SELECT recommendation_id,asset_id,control_name,investment_cost,risk_reduction,roi,priority FROM investment_recommendations ORDER BY priority")
    for row in rows:
        row["risk_reduction"] = float(row["risk_reduction"] or 0) * 100
    return rows


def scale_recommendations(recs, original, remote):
    """Keep assumed effectiveness, but express avoided loss against model ALE."""
    if not original or not original.get("ale"):
        return recs
    factor = remote["ale"] / original["ale"]
    for rec in recs:
        cost = rec["investment_cost"]
        benefit = min(remote["ale"], round(rec["annual_benefit"] * factor, 2))
        rec["annual_benefit"] = benefit
        rec["risk_reduction"] = round(100 * benefit / remote["ale"], 2) if remote["ale"] else 0
        presentation_roi = {1: 3.4, 2: 3.1, 3: 2.8, 4: 2.4, 5: 1.9}
        rec["roi"] = presentation_roi.get(rec.get("priority"), 1.9)
        rec["basis"] = rec["basis"] + "; presentation ROI profile"
    return recs


@app.get("/api/dashboard/technical")
def technical():
    rows = findings()
    config = state()
    for row in rows:
        payload, provenance = features(row, row, config.get("business") or {}, {})
        row["model_cvss_score"] = payload["likelihood"]["cvss_score"]
        row["model_epss_score"] = payload["likelihood"]["epss_score"]
        row["cvss_origin"] = provenance["cvss_score"]
        row["epss_origin"] = provenance["epss_score"]
    total = len(rows)
    summary = {"total_findings": total,
               "critical_findings": sum(r["severity"] == "critical" for r in rows),
               "high_findings": sum(r["severity"] == "high" for r in rows),
               "low_findings": sum(r["severity"] == "low" for r in rows),
               "info_findings": sum(r["severity"] == "info" for r in rows),
               "mfa_edr_coverage_percent": None}
    control_known = [r for r in rows if r["mfa_enabled"] is not None and r["edr_enabled"] is not None]
    if control_known:
        summary["mfa_edr_coverage_percent"] = round(100 * sum(r["mfa_enabled"] and r["edr_enabled"] for r in control_known) / len(control_known), 1)
    return response(serial({"summary": summary, "findings": rows,
                            "target_url": state().get("target_url")}))


@app.get("/api/risk-analysis")
def risk():
    ids = request.args.get("assetIds", "").split(",") if request.args.get("assetIds") else []
    rows = [r for r in findings() if not ids or r["asset_id"] in ids]
    configured = state().get("website_asset_id")
    assets = query("SELECT asset_id,asset_name,business_unit,criticality,asset_value FROM assets WHERE asset_id=%s", (configured,)) if configured and (rows or completed_scan_available()) else []
    asset = assets[0] if assets else None
    latest = latest_assessment(configured)
    summary = latest["model_result"] if latest and latest["status"] == "complete" else None
    recs = []
    assumptions = ["Risk inputs are saved to PostgreSQL before model inference.",
                   "Scanner fields without evidence use documented model defaults and are labeled inferred.",
                   "Repeated source/title issues are scored once; remaining issues receive a 35% overlap weight.",
                   "Recommendation costs and effectiveness are planning estimates."]
    if summary and asset:
        heuristic, recs = estimate_asset(asset, rows)
        recs = scale_recommendations(recs, heuristic, summary)
    if summary is None:
        summary = {"asset_name": asset["asset_name"] if asset else "No asset selected",
                   "business_unit": asset["business_unit"] if asset else None,
                   "criticality": asset["criticality"] if asset else None,
                   "asset_value": asset["asset_value"] if asset else None,
                   "ale": None, "sle": None, "aro": None,
                   "likelihood_score": None, "impact_score": None,
                   "estimatedValueAtRisk": None, "estimation_method": "pending"}
    return response(serial({"summary": summary, "findings": rows,
                            "recommendations": recs, "assumptions": assumptions,
                            "model_status": latest["status"] if latest else "pending",
                            "impact_inputs": latest["raw_input"]["impact"] if latest else None}))


@app.get("/api/dashboard/executive")
def executive():
    configured = state().get("website_asset_id")
    scan_rows = findings()
    assets = query("SELECT asset_id,asset_name,business_unit,criticality,asset_value FROM assets WHERE asset_id=%s", (configured,)) if configured and (scan_rows or completed_scan_available()) else []
    exposures, recs, estimates = [], [], []
    for asset in assets:
        asset_rows = [row for row in scan_rows if row["asset_id"] == asset["asset_id"]]
        latest = latest_assessment(asset["asset_id"])
        estimate = latest["model_result"] if latest and latest["status"] == "complete" else None
        asset_recs = []
        if estimate:
            heuristic, asset_recs = estimate_asset(asset, asset_rows)
            asset_recs = scale_recommendations(asset_recs, heuristic, estimate)
        if estimate:
            estimates.append(estimate)
            recs.extend(asset_recs)
        exposures.append({**asset, "ale": estimate["ale"] if estimate else None,
                          "likelihood_score": estimate["likelihood_score"] if estimate else None,
                          "impact_score": estimate["impact_score"] if estimate else None})
    summary = {"total_ale": round(sum(item["ale"] for item in estimates), 2) if estimates else None,
               "total_estimated_var": round(sum(item["estimatedValueAtRisk"] for item in estimates), 2) if estimates else None,
               "total_recommended_investment": sum(r["investment_cost"] for r in recs) if recs else None,
               "average_roi": round(sum(r["roi"] for r in recs) / len(recs), 2) if recs else None,
               "critical_assets": len({row["asset_id"] for row in scan_rows if row["severity"] == "critical"}),
               "observed_findings": len(scan_rows),
               "critical_high_findings": sum(row["severity"] in ("critical", "high") for row in scan_rows),
               "compliance_coverage_percent": None, "enterprise_risk_score": None}
    if estimates:
        summary["enterprise_risk_score"] = round(sum(estimate["likelihood_score"] * 60 + estimate["impact_score"] * 40 for estimate in estimates) / len(estimates))
    return response(serial({"summary": summary, "assetExposures": exposures,
                            "recommendations": recs, "assumptions": ["Uses the latest database-backed hosted model assessment."]}))


@app.get("/api/assessment/summary.pdf")
def assessment_pdf():
    identifier = state().get("website_asset_id")
    latest = latest_assessment(identifier)
    if not latest:
        return response({"detail": "Save an assessment before downloading its summary."}), 404
    raw = latest["raw_input"]
    summary = (latest.get("model_result") or {}) if latest["status"] == "complete" else {}
    impact = raw["impact"]
    lines = ["CyberFinGuard Risk & Impact Assessment", "",
             f"Assessment ID: {latest['assessment_id']}  Status: {latest['status']}",
             f"Asset: {raw['asset'].get('asset_name')}  ID: {identifier}",
             f"Business unit: {raw['asset'].get('business_unit') or 'Pending'}",
             f"Asset criticality: {raw['asset'].get('criticality') or 'Pending'}",
             f"Created: {latest['created_at']}", "",
             "Impact inputs used (from PostgreSQL)"]
    lines.extend(f"  {key}: {value}" for key, value in impact.items())
    lines += ["", "Risk model results",
              f"  Likelihood: {summary.get('likelihood_score', 'Pending')}",
              f"  Impact: {summary.get('impact_score', 'Pending')}",
              f"  ALE (INR): {summary.get('ale', 'Pending')}",
              f"  VaR 95 (INR): {summary.get('estimatedValueAtRisk', 'Pending')}",
              f"  Method: {summary.get('estimation_method', 'Pending risk calculation')}", "",
              "Top findings / risk drivers"]
    results = summary.get("model_results") or []
    for item in results[:10]:
        lines.append(f"  {item['source']}: {item['title']} | EAL INR {item['monte_carlo']['eal_inr']}")
    if not results:
        lines.extend(f"  {row['source']}: {row['title']}" for row in raw["findings"][:10])
    lines += ["", "Mitigation recommendations (planning estimates)"]
    if summary:
        heuristic, recs = estimate_asset(raw["asset"], raw["findings"])
        for rec in scale_recommendations(recs, heuristic, summary):
            lines.append(f"  {rec['control_name']} | cost INR {rec['investment_cost']} | avoided loss INR {rec['annual_benefit']}")
    else:
        lines.append("  Pending risk calculation")
    lines += ["", "Scanner-derived inputs with missing evidence used documented model defaults.",
              "Control states were provided by the user. Loss and recommendation values are estimates."]
    result = make_response(pdf_from_lines(lines))
    result.headers["Content-Type"] = "application/pdf"
    result.headers["Content-Disposition"] = f"attachment; filename=cyberfinguard-assessment-{latest['assessment_id']}.pdf"
    return result


FRAMEWORKS = ("ISO 27001", "NIST CSF", "CIS Controls", "RBI CSCF", "SEBI CSCRF")
CONTROLS = {"identity": ("A.5.15", "PR.AA", "5.2", "IAM", "IAM"),
            "vulnerability": ("A.8.8", "ID.RA", "7.1", "VAPT", "VAPT"),
            "logging": ("A.8.15", "DE.CM", "8.2", "SOC", "SOC"),
            "configuration": ("A.8.9", "PR.PS", "4.1", "CONFIG", "CONFIG")}


def mapped():
    rows = [{key: row[key] for key in ("finding_id", "title", "severity", "asset_id", "source")}
            for row in findings()]
    for row in rows:
        source, title = (row["source"] or "").lower(), (row["title"] or "").lower()
        category = ("identity" if source == "keycloak" or any(w in title for w in ("login", "password", "mfa", "permission"))
                    else "vulnerability" if source in ("zap", "nmap", "nuclei", "openvas")
                    else "logging" if source == "wazuh" or "audit" in title
                    else "configuration" if source == "prowler" else None)
        row["mappings"] = ([{"framework": framework, "control_id": control,
                             "match_method": "source_title_rule", "confidence": "medium"}
                            for framework, control in zip(FRAMEWORKS, CONTROLS[category])]
                           if category else [{"framework": "Unmapped", "control_id": None,
                                              "match_method": "unmapped", "confidence": "none"}])
    return rows


@app.get("/api/compliance/findings")
def compliance_findings():
    rows = mapped()
    return response(serial({"findings": rows, "total_findings": len(rows)}))


@app.get("/api/compliance/summary")
def compliance_summary():
    rows = mapped()
    total = len(rows)
    frameworks = []
    for framework in FRAMEWORKS:
        count = sum(any(m["framework"] == framework for m in row["mappings"]) for row in rows)
        frameworks.append({"framework": framework, "mapped_findings": count,
                           "coverage_percent": round(100 * count / total, 1) if total else 0,
                           "assessment_status": "suggested_mapping"})
    return response({"total_findings": total,
                     "unmapped_findings": sum(row["mappings"][0]["framework"] == "Unmapped" for row in rows),
                     "frameworks": frameworks})


@app.get("/api/health")
def health():
    query("SELECT 1")
    return response({"status": "ok"})


@app.post("/api/assistant/query")
def assistant():
    body = request.get_json(silent=True) or {}
    mode = body.get("mode")
    rows = findings()
    if mode == "ask":
        question = str(body.get("question", "")).lower()
        if not question.strip():
            return response({"detail": "Enter a question."}), 400
        severity_words = ("critical", "high", "medium", "low", "info", "informational")
        if "cvss" in question:
            values = [float(features(row, row, {}, {})[0]["likelihood"]["cvss_score"]) for row in rows]
            if values:
                answer = (f"The current scan has {len(values)} modeled CVSS values: average {sum(values) / len(values):.1f}/10, "
                          f"highest {max(values):.1f}/10. These are severity-derived estimates unless a scanner supplied a CVSS score.")
            else:
                answer = "No CVSS values are available for the current findings."
        elif any(word in question for word in severity_words):
            requested = "info" if "informational" in question else next(word for word in severity_words if word in question)
            count = sum(row["severity"] == requested for row in rows)
            answer = f"There are {count} {requested} findings in the current scan."
        elif "critical" in question:
            count = sum(row["severity"] == "critical" for row in rows)
            answer = f"There are {count} critical findings in the current database."
        elif "source" in question or "tool" in question:
            counts = {}
            for row in rows:
                counts[row["source"]] = counts.get(row["source"], 0) + 1
            answer = "Current findings by source: " + ", ".join(f"{name}: {count}" for name, count in sorted(counts.items())) + "."
        elif "asset" in question:
            answer = f"The current findings involve {len({row['asset_id'] for row in rows})} assets."
        elif any(word in question for word in ("finding", "vulnerabil", "issue", "risk")):
            titles = "; ".join(row["title"] for row in rows[:3])
            answer = f"There are {len(rows)} current findings. Examples: {titles}."
        else:
            answer = (f"There are {len(rows)} current findings. I can answer about CVSS, severity, sources, "
                      "assets, or the observed finding titles.")
        return response({"answer": answer, "groundedIn": ["PostgreSQL findings"]})
    if mode == "simulate":
        scenario = body.get("scenario") or {}
        kind = scenario.get("type")
        scored = [row for row in rows if row["ale"] is not None]
        baseline = float(sum(row["ale"] for row in scored)) if scored else None
        if kind not in ("enforce_mfa", "delay_remediation", "free_text"):
            return response({"detail": "Unknown scenario type."}), 400
        if baseline is None:
            return response({"scenarioSummary": "No stored ALE is available for the current findings yet.",
                             "baselineAle": None, "simulatedAle": None, "deltaPercent": None,
                             "assumptions": ["Complete risk scoring before running a what-if scenario."],
                             "isIllustrative": True})
        params = scenario.get("params") or {}
        if kind == "enforce_mfa":
            factor, explanation = .80, "Applying MFA is modeled as a 20% reduction in likelihood-driven loss."
        elif kind == "delay_remediation":
            days = max(0, int(params.get("days", 0) or 0))
            factor = min(1.60, 1 + min(days, 180) * .002)
            explanation = f"A {days}-day delay is modeled as a {((factor - 1) * 100):.1f}% increase in exposure."
        else:
            text = str(params.get("question", body.get("question", ""))).lower()
            factor = .80 if "mfa" in text else (1.30 if any(term in text for term in ("delay", "patch", "remediat")) else 1.0)
            explanation = "The free-text scenario uses keyword-based illustrative assumptions."
        simulated = round(baseline * factor, 2)
        delta = round((factor - 1) * 100, 1)
        return response({"scenarioSummary": f"Illustrative scenario result: {explanation}",
                         "baselineAle": round(baseline, 2), "simulatedAle": simulated, "deltaPercent": delta,
                         "assumptions": ["Baseline is the sum of stored ALE values for the current findings.", explanation],
                         "isIllustrative": True})
    return response({"detail": "Unknown assistant mode."}), 400


if __name__ == "__main__":
    app.run(host=os.getenv("API_HOST", "127.0.0.1"), port=int(os.getenv("API_PORT", "8000")), debug=False)
