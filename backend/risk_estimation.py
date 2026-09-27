"""Transparent planning estimates derived from observed findings and user asset values.

These assumptions are scenario inputs, not measured incident frequencies or quotes.
No scanner finding is treated as proof that a control is absent.
"""
from hashlib import sha256
from random import Random

ANNUAL_PROBABILITY = {"critical": .15, "high": .08, "medium": .03, "low": .01, "info": .002}
LOSS_FRACTION = {"critical": .25, "high": .15, "medium": .07, "low": .03, "info": .01}
OVERLAP_FACTOR = .35


def category(row):
    title = (row.get("title") or "").lower()
    source = (row.get("source") or "").lower()
    if row.get("cve_id") or "vulnerab" in title:
        return "patch"
    if "csrf" in title or "cross-site scripting" in title or "injection" in title:
        return "application"
    if source == "nmap" or "open port" in title:
        return "network"
    if any(word in title for word in ("header", "content security policy", "clickjack", "cache-control", "sub resource integrity")):
        return "headers"
    if source == "keycloak" or "mfa" in title or "authentication" in title:
        return "identity"
    return "monitoring"


CONTROLS = {
    "patch": ("Patch vulnerable components", .005, .70),
    "application": ("Harden request validation and CSRF protection", .004, .60),
    "network": ("Restrict exposed network services", .003, .65),
    "headers": ("Harden web security headers", .002, .55),
    "identity": ("Enforce MFA and review access", .003, .60),
    "monitoring": ("Improve detection and review", .002, .25),
}


def estimate_asset(asset, findings):
    value = float(asset.get("asset_value") or 0)
    if value <= 0 or not findings:
        return None, []
    criticality = max(1, min(5, int(asset.get("criticality") or 3))) / 5
    # Repeated alerts and endpoints for the same issue contribute once to the estimate.
    issues = {}
    for row in findings:
        key = ((row.get("source") or "").lower(), (row.get("title") or "").lower())
        severity = row.get("severity") or "info"
        if key not in issues or ANNUAL_PROBABILITY.get(severity, 0) > ANNUAL_PROBABILITY.get(issues[key].get("severity"), 0):
            issues[key] = row
    modeled = []
    for row in issues.values():
        severity = row.get("severity") or "info"
        probability = ANNUAL_PROBABILITY.get(severity, .002)
        epss = row.get("epss_score")
        if epss is not None:
            probability *= 1 + min(1, max(0, float(epss)))
        if row.get("cisa_kev"):
            probability = max(probability, .30)
        if row.get("patching_status") == "patched":
            probability *= .5
        probability = min(.6, probability)
        impact = value * LOSS_FRACTION.get(severity, .01) * criticality
        modeled.append((row, probability, impact, probability * impact))
    modeled.sort(key=lambda item: item[3], reverse=True)
    if not modeled:
        return None, []
    annual_loss = min(value, modeled[0][3] + OVERLAP_FACTOR * sum(item[3] for item in modeled[1:]))
    likelihood = 1
    for _, probability, _, _ in modeled:
        likelihood *= 1 - probability
    likelihood = 1 - likelihood
    rng = Random(int(sha256(str(asset["asset_id"]).encode()).hexdigest()[:12], 16))
    trials = []
    for _ in range(10000):
        realized = sorted((impact for _, probability, impact, _ in modeled if rng.random() < probability), reverse=True)
        trials.append(min(value, realized[0] + OVERLAP_FACTOR * sum(realized[1:])) if realized else 0)
    trials.sort()
    p95 = trials[9499]
    summary = {
        "asset_name": asset.get("asset_name") or asset["asset_id"],
        "business_unit": asset.get("business_unit"),
        "criticality": asset.get("criticality"),
        "asset_value": value,
        "likelihood_score": round(likelihood, 4),
        "impact_score": round(max(impact for _, _, impact, _ in modeled) / value, 4),
        "sle": round(max(impact for _, _, impact, _ in modeled), 2),
        "aro": round(likelihood, 4),
        "ale": round(annual_loss, 2),
        "estimatedValueAtRisk": round(p95, 2),
        "estimation_method": "heuristic-v1",
        "modeled_issues": len(modeled),
    }
    category_loss = {}
    for index, (row, _, _, expected) in enumerate(modeled):
        group = category(row)
        category_loss[group] = category_loss.get(group, 0) + expected * (1 if index == 0 else OVERLAP_FACTOR)
    recommendations = []
    for group, loss in category_loss.items():
        name, cost_fraction, effectiveness = CONTROLS[group]
        cost = round(max(25000, value * cost_fraction), 2)
        avoided = min(annual_loss, loss * effectiveness)
        recommendations.append({
            "recommendation_id": f"estimated-{asset['asset_id']}-{group}",
            "asset_id": asset["asset_id"],
            "control_name": name,
            "investment_cost": cost,
            "annual_benefit": round(avoided, 2),
            "risk_reduction": round(100 * avoided / annual_loss, 2) if annual_loss else 0,
            "roi": round((avoided - cost) / cost, 2),
            "priority": 0,
            "estimated": True,
            "basis": f"{group} findings; assumed {effectiveness:.0%} effectiveness",
        })
    recommendations.sort(key=lambda item: item["annual_benefit"] / item["investment_cost"], reverse=True)
    for index, item in enumerate(recommendations):
        item["priority"] = min(5, index + 1)
    return summary, recommendations


ASSUMPTIONS = [
    "Observed issues are grouped by source and title so repeat scans do not multiply risk.",
    "Annual event probabilities are planning assumptions by severity: critical 15%, high 8%, medium 3%, low 1%, info 0.2%.",
    "A single event loss uses 25%, 15%, 7%, 3%, or 1% of entered asset value by severity, scaled by criticality.",
    "EPSS and KEV increase likelihood where present; missing control telemetry is treated as unknown.",
    "Additional issue losses receive a 35% overlap weight. The 95th-percentile loss uses 10,000 seeded simulations.",
    "Control costs are planning allowances of 0.2%–0.5% of asset value, minimum ₹25,000; effectiveness is assumed, not measured.",
]
