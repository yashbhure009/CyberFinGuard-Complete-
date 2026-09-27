"""Adapter for the hosted CyberFinGuard /risk inference API.

Observed scanner values remain separate from explicit planning assumptions.
The remote service receives no credentials, only normalized risk features.
"""
import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / "data" / "risk_model_cache.json"
RISK_URL = os.getenv("RISK_MODEL_URL", "https://cyberfinguard-risk-api.onrender.com/risk")
OUTBOUND_PROXY = os.getenv("RISK_MODEL_PROXY", os.getenv("SCANNER_HTTP_PROXY"))
_configured_ca = os.getenv("ZAP_PROXY_CA_CERT", "data/zap_proxy_root.cer")
PROXY_CA_CERT = Path(_configured_ca)
if not PROXY_CA_CERT.is_absolute():
    PROXY_CA_CERT = ROOT / PROXY_CA_CERT

SEVERITY_CVSS = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.1, "info": 0.0}
SEVERITY_EPSS = {"critical": .10, "high": .05, "medium": .02, "low": .005, "info": 0.0}
SENSITIVITY = {"Public", "Internal", "Confidential"}
DATA_TYPES = {"Financial", "Credentials", "Intellectual_Property", "Operational"}
JURISDICTIONS = {"GDPR", "DPDPA", "RBI", "SEBI"}
EXPLOIT_TYPES = {"None", "PoC", "Weaponized", "Active_ITW"}
THREAT_ACTORS = {"Unknown", "Script_Kiddie", "Organized_Crime", "Nation_State"}


def valid_number(value, fallback, low=0, high=None):
    try:
        result = float(value)
        if low <= result and (high is None or result <= high):
            return result
    except (TypeError, ValueError):
        pass
    return fallback


def yes_no(value, default="No"):
    if value is True or value == "Yes":
        return "Yes"
    if value is False or value == "No":
        return "No"
    return default


def features(row, asset, business, inputs):
    severity = row.get("severity") or "info"
    cvss_observed = row.get("cvss_score") is not None
    epss_observed = row.get("epss_score") is not None
    cvss = valid_number(row.get("cvss_score"), None, 0, 10) if cvss_observed else None
    epss = valid_number(row.get("epss_score"), None, 0, 1) if epss_observed else None
    cvss = cvss if cvss is not None else valid_number(inputs.get("cvss_score"), SEVERITY_CVSS.get(severity, 0), 0, 10)
    epss = epss if epss is not None else valid_number(inputs.get("epss_score"), SEVERITY_EPSS.get(severity, 0), 0, 1)
    likelihood = {
        "cvss_score": cvss, "epss_score": epss,
        "exploit_available": yes_no(row.get("exploit_available"), yes_no(inputs.get("exploit_available"))),
        "exploit_type": row.get("exploit_type") if row.get("exploit_type") in EXPLOIT_TYPES else inputs.get("exploit_type", "None"),
        "threat_actor": row.get("threat_actor") if row.get("threat_actor") in THREAT_ACTORS else "Unknown",
        "malware": yes_no(row.get("malware")),
        "mitre_technique": row.get("mitre_technique") or inputs.get("mitre_technique", "T0000"),
        "patched": yes_no(row.get("patching_status") == "patched" if row.get("patching_status") != "unknown" else None, yes_no(inputs.get("patched"))),
        "mfa": yes_no(row.get("mfa_enabled"), yes_no(inputs.get("mfa"))),
        "waf": yes_no(row.get("waf_enabled"), yes_no(inputs.get("waf"))),
        "edr": yes_no(row.get("edr_enabled"), yes_no(inputs.get("edr"))),
    }
    if likelihood["exploit_type"] not in EXPLOIT_TYPES:
        likelihood["exploit_type"] = "None"
    if likelihood["threat_actor"] not in THREAT_ACTORS:
        likelihood["threat_actor"] = "Unknown"
    sensitivity = inputs.get("data_sensitivity", business.get("data_sensitivity", "Confidential"))
    if sensitivity not in SENSITIVITY:
        sensitivity = "Confidential"
    data_type = inputs.get("data_type", "Financial")
    if data_type not in DATA_TYPES:
        data_type = "Financial"
    jurisdiction = inputs.get("regulatory_jurisdiction", "DPDPA")
    if jurisdiction not in JURISDICTIONS:
        jurisdiction = "DPDPA"
    impact = {
        "asset_value": valid_number(asset.get("asset_value"), valid_number(business.get("business_value"), 0)),
        "asset_criticality": max(3, min(5, int(asset.get("criticality") or business.get("asset_criticality") or 3))),
        "records_affected": int(valid_number(inputs.get("records_affected"), 0)),
        "customers_affected": int(valid_number(inputs.get("customers_affected"), 0)),
        "downtime_hours": valid_number(inputs.get("downtime_hours"), 8),
        "recovery_time_hours": valid_number(inputs.get("recovery_time_hours"), 24),
        "recovery_capability": valid_number(inputs.get("recovery_capability"), .5, 0, 1),
        "business_continuity_score": valid_number(inputs.get("business_continuity_score"), .5, 0, 1),
        "revenue_per_hour": valid_number(inputs.get("revenue_per_hour"), valid_number(business.get("downtime_cost"), 0)),
        "data_sensitivity": sensitivity,
        "data_type": data_type,
        "regulatory_jurisdiction": jurisdiction,
        "backup_availability": yes_no(inputs.get("backup_availability")),
    }
    provenance = {
        "cvss_score": "scanner" if cvss_observed else "assumed",
        "epss_score": "threat_intel" if epss_observed else "assumed",
        "controls": "asset_controls" if any(row.get(name) is not None for name in ("mfa_enabled", "waf_enabled", "edr_enabled")) else "assumed",
        "impact": "assessment_with_assumptions",
        "exploit_available": "scanner" if row.get("exploit_available") is not None else "inferred",
        "exploit_type": "scanner" if row.get("exploit_type") in EXPLOIT_TYPES else "inferred",
        "threat_actor": "scanner" if row.get("threat_actor") in THREAT_ACTORS else "inferred",
        "malware": "scanner" if row.get("malware") in (True, False, "Yes", "No") else "inferred",
        "mitre_technique": "scanner" if row.get("mitre_technique") else "inferred",
        "patched": "asset_controls" if row.get("patching_status") in ("patched", "unpatched", "partial") else "inferred",
    }
    return {"likelihood": likelihood, "impact": impact}, provenance


def key_for(payload):
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def infer_many(items):
    """Return results in input order; cache by exact normalized input payload."""
    try:
        cache = json.loads(CACHE.read_text(encoding="utf-8")) if CACHE.exists() else {}
    except (OSError, ValueError):
        cache = {}
    keys = [key_for(payload) for payload in items]
    missing = {key: payload for key, payload in zip(keys, items) if key not in cache}

    def send(item):
        key, payload = item
        request_options = {"timeout": 75}
        if OUTBOUND_PROXY:
            request_options["proxies"] = {"http": OUTBOUND_PROXY, "https": OUTBOUND_PROXY}
            if PROXY_CA_CERT.is_file():
                request_options["verify"] = str(PROXY_CA_CERT)
        result = requests.post(RISK_URL, json=payload, **request_options)
        result.raise_for_status()
        data = result.json()
        if not all(part in data for part in ("likelihood", "impact", "monte_carlo")):
            raise ValueError("Risk API response is missing model sections")
        return key, data

    if missing:
        with ThreadPoolExecutor(max_workers=4) as pool:
            for key, result in pool.map(send, missing.items()):
                cache[key] = result
        temporary = CACHE.with_suffix(".tmp")
        temporary.write_text(json.dumps(cache), encoding="utf-8")
        temporary.replace(CACHE)
    return [cache[key] for key in keys]


def estimate_remote(asset, findings, business, inputs):
    if not asset or not asset.get("asset_value") or not findings:
        return None
    # Each source/title issue is evaluated once; repeated endpoints remain visible in the register.
    unique = {}
    for row in findings:
        unique.setdefault((row.get("source"), row.get("title")), row)
    selected = list(unique.values())
    payloads = [features(row, asset, business, inputs)[0] for row in selected]
    results = infer_many(payloads)
    parts = sorted(zip(selected, results), key=lambda item: item[1]["monte_carlo"]["eal_inr"], reverse=True)
    overlap = .35
    ale = parts[0][1]["monte_carlo"]["eal_inr"] + overlap * sum(item[1]["monte_carlo"]["eal_inr"] for item in parts[1:])
    var95 = parts[0][1]["monte_carlo"]["var_95_inr"] + overlap * sum(item[1]["monte_carlo"]["var_95_inr"] for item in parts[1:])
    probability = 1
    for _, result in parts:
        probability *= 1 - float(result["likelihood"]["incident_probability"])
    probability = 1 - probability
    max_impact = max(float(result["impact"]["total_loss_inr"]) for _, result in parts)
    value = float(asset["asset_value"])
    return {
        "asset_name": asset.get("asset_name") or asset["asset_id"],
        "business_unit": asset.get("business_unit"),
        "criticality": asset.get("criticality"), "asset_value": value,
        "likelihood_score": round(probability, 4),
        "impact_score": round(min(1, max_impact / value), 4) if value else None,
        "sle": round(max_impact, 2), "aro": round(probability, 4),
        "ale": round(ale, 2), "estimatedValueAtRisk": round(var95, 2),
        "estimation_method": "hosted-ml-with-overlap-v1",
        "modeled_issues": len(parts),
        "model_results": [{"source": row.get("source"), "title": row.get("title"),
                           "incident_probability": result["likelihood"]["incident_probability"],
                           "eal_inr": result["monte_carlo"]["eal_inr"],
                           "var_95_inr": result["monte_carlo"]["var_95_inr"]} for row, result in parts],
    }
