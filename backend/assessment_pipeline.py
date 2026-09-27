"""Database-backed intake and exact hosted /risk payload transformation."""
from backend.remote_risk_model import features, infer_many


IMPACT_NUMBERS = {
    "asset_value": (0, None), "customers_affected": (0, None),
    "records_affected": (0, None), "downtime_hours": (0, None),
    "recovery_time_hours": (0, None), "recovery_capability": (0, 1),
    "business_continuity_score": (0, 1), "revenue_per_hour": (0, None),
}
IMPACT_CHOICES = {
    "data_sensitivity": {"Public", "Internal", "Confidential"},
    "data_type": {"Financial", "Credentials", "Intellectual_Property", "Operational"},
    "regulatory_jurisdiction": {"GDPR", "DPDPA", "RBI", "SEBI"},
    "backup_availability": {"Yes", "No"},
}
CONTROL_KEYS = {"mfa", "waf", "edr"}


def validate_impact(data):
    clean = {}
    expected = set(IMPACT_NUMBERS) | set(IMPACT_CHOICES)
    if set(data) != expected:
        raise ValueError("Impact context requires exactly: " + ", ".join(sorted(expected)))
    for key, (low, high) in IMPACT_NUMBERS.items():
        try:
            number = float(data[key])
        except (TypeError, ValueError):
            raise ValueError(f"{key} must be numeric") from None
        if not (number >= low and (high is None or number <= high)):
            raise ValueError(f"{key} is outside its allowed range")
        if key in ("customers_affected", "records_affected") and not number.is_integer():
            raise ValueError(f"{key} must be a whole number")
        clean[key] = int(number) if key in ("customers_affected", "records_affected") else number
    for key, choices in IMPACT_CHOICES.items():
        if data[key] not in choices:
            raise ValueError(f"Invalid {key}")
        clean[key] = data[key]
    return clean


def validate_controls(data):
    if set(data) != CONTROL_KEYS or any(value not in ("Yes", "No") for value in data.values()):
        raise ValueError("Only mfa, waf, and edr may be submitted, each as Yes or No")
    return dict(data)


def transform_stored_record(raw):
    """Transform the raw JSONB record read back from PostgreSQL.

    Each issue gets the exact {likelihood: 11 fields, impact: 13 fields}
    request shape accepted by the deployed /risk API.
    """
    asset = raw["asset"]
    impact = raw["impact"]
    controls = raw["controls"]
    items = []
    for row in raw["findings"]:
        scanner_row = {**row, "mfa_enabled": None, "waf_enabled": None, "edr_enabled": None}
        payload, provenance = features(scanner_row, asset, {}, {**impact, **controls})
        provenance["controls"] = "user_assessment"
        # The intake values are authoritative for the impact model.
        payload["impact"].update({key: impact[key] for key in IMPACT_NUMBERS if key != "asset_value"})
        payload["impact"].update({key: impact[key] for key in IMPACT_CHOICES})
        payload["impact"]["asset_value"] = impact["asset_value"]
        items.append({"finding_id": row["finding_id"], "source": row["source"],
                      "title": row["title"], "payload": payload, "provenance": provenance})
    return items


def calculate_model_summary(raw, items):
    """Invoke the hosted model with payloads derived only from the stored row."""
    if not items:
        return None
    results = infer_many([item["payload"] for item in items])
    ranked = sorted(zip(items, results), key=lambda pair: pair[1]["monte_carlo"]["eal_inr"], reverse=True)
    top = ranked[0][1]
    ale = float(top["monte_carlo"]["eal_inr"]) + .35 * sum(float(result["monte_carlo"]["eal_inr"]) for _, result in ranked[1:])
    var95 = float(top["monte_carlo"]["var_95_inr"]) + .35 * sum(float(result["monte_carlo"]["var_95_inr"]) for _, result in ranked[1:])
    complement = 1.0
    for _, result in ranked:
        complement *= 1 - float(result["likelihood"]["incident_probability"])
    probability = 1 - complement
    max_impact = max(float(result["impact"]["total_loss_inr"]) for _, result in ranked)
    asset = raw["asset"]
    value = float(raw["impact"]["asset_value"])
    return {"asset_name": asset.get("asset_name") or asset["asset_id"],
            "business_unit": asset.get("business_unit"), "criticality": asset.get("criticality"),
            "asset_value": value, "likelihood_score": round(probability, 4),
            "impact_score": round(min(1, max_impact / value), 4) if value else None,
            "sle": round(max_impact, 2), "aro": round(probability, 4),
            "ale": round(ale, 2), "estimatedValueAtRisk": round(var95, 2),
            "estimation_method": "hosted-ml-db-v1", "modeled_issues": len(items),
            "model_results": [{"finding_id": item["finding_id"], "source": item["source"],
                               "title": item["title"], "provenance": item["provenance"],
                               "likelihood": result["likelihood"], "impact": result["impact"],
                               "monte_carlo": result["monte_carlo"]} for item, result in ranked]}
