"""
CyberFinGuard â€” Unified Ingestion Runner
Outputs unified findings JSON for downstream models
With Nexora website integration (full pipeline)
"""

import os
import sys
import json
import logging
import socket
from datetime import datetime

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ============================================================
# PATH SETUP
# ============================================================
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(ROOT_DIR, 'backend')
sys.path.insert(0, ROOT_DIR)
sys.path.insert(0, BACKEND_DIR)

from dotenv import load_dotenv
from backend.scan_time import database_scan_start
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Output directory
OUTPUT_DIR = os.getenv('UNIFIED_OUTPUT_DIR', 'data/unified_findings')
os.makedirs(OUTPUT_DIR, exist_ok=True)

# User config file
SCAN_CONFIG_PATH = os.path.join(ROOT_DIR, 'data', 'scan_config.json')
SCAN_STATUS_PATH = os.path.join(ROOT_DIR, 'data', 'scan_status.json')


def update_scan_status(status, stage, error=None, scanner_results=None):
    """Persist a small progress record without waiting for the final export."""
    os.makedirs(os.path.dirname(SCAN_STATUS_PATH), exist_ok=True)
    try:
        with open(SCAN_STATUS_PATH, 'r', encoding='utf-8') as stream:
            previous = json.load(stream)
    except (OSError, ValueError):
        previous = {}
    payload = {key: previous[key] for key in ('started_at', 'target_url', 'asset_id') if key in previous}
    payload.update(status=status, stage=stage, updated_at=datetime.now().isoformat())
    if error:
        payload['error'] = str(error)
    if scanner_results is not None:
        payload['scanner_results'] = scanner_results
    temporary = SCAN_STATUS_PATH + '.tmp'
    with open(temporary, 'w', encoding='utf-8') as stream:
        json.dump(payload, stream)
    os.replace(temporary, SCAN_STATUS_PATH)

# Nexora target (default)

# Hardcoded IPv4 (DNS multiple IPs de raha hai)


# ============================================================
# USER CONFIG LOADER
# ============================================================

def load_user_config():
    """Load user config from scan_config.json if it exists."""
    if not os.path.exists(SCAN_CONFIG_PATH):
        logger.info("No scan_config.json found â€” using defaults")
        return {}
    try:
        with open(SCAN_CONFIG_PATH, 'r', encoding='utf-8') as fp:
            cfg = json.load(fp)
        logger.info(f"âœ… Loaded user config from {SCAN_CONFIG_PATH}")
        return cfg
    except Exception as e:
        logger.warning(f"Failed to load user config: {e}")
        return {}


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def _safe_float(value, default=0.0):
    if value is None or value == "" or str(value).lower() in ("unknown", "n/a", "null"):
        return default
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def _safe_string(value, default="None"):
    if value is None or value == "" or str(value).lower() in ("unknown", "n/a", "null"):
        return default
    return str(value)


def parse_raw_data(raw):
    if not raw:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"raw": raw}
    return {}


def get_ip_from_hostname(hostname):
    """Hostname se IPv4 nikalo"""
    try:
        return socket.gethostbyname(hostname)
    except OSError as exc:
        raise ValueError(f"Could not resolve target hostname {hostname}: {exc}") from exc


# ============================================================
# INGESTOR RUNNERS
# ============================================================

def run_zap_manual(target_url=None, asset_id=None):
    """ZAP Manual scan â€” 92 findings (Nexora)"""
    try:
        logger.info("=" * 60)
        logger.info("ðŸ•·ï¸ Running ZAP MANUAL scan...")
        from backend.ingestion.zap_manual_scan import ZAPManualScan
        
        scanner = ZAPManualScan()
        if asset_id:
            scanner.asset_id = asset_id
        if not target_url:
            raise ValueError('Website URL is required')
        result = scanner.run(target_url)
        logger.info(f"âœ… ZAP Manual: {result}")
        return result
    except Exception as e:
        logger.error(f"âŒ ZAP Manual failed: {e}")
        return {"source": "zap", "error": str(e)}


def run_nmap(target=None, asset_id=None):
    """Nmap scan â€” Nexora IP"""
    try:
        if not target:
            raise ValueError('Nmap target is required')
        logger.info("=" * 60)
        logger.info(f"ðŸ” Running Nmap on {target}...")
        from backend.ingestion.nmap_ingestor import NmapIngestor
        ingestor = NmapIngestor()
        if asset_id:
            ingestor.asset_id = asset_id
        result = ingestor.run(target=target)
        logger.info(f"âœ… Nmap: {result}")
        return result
    except Exception as e:
        logger.error(f"âŒ Nmap failed: {e}")
        return {"source": "nmap", "error": str(e)}


def run_nuclei(target=None, severity='low,medium,high,critical', asset_id=None):
    """Nuclei scan â€” httpbin.org test target"""
    try:
        if not target:
            raise ValueError('Website URL is required')
        logger.info(f"ðŸŽ¯ Running Nuclei on {target}")
        logger.info(f"   Severity: {severity}")

        from backend.ingestion.nuclei_ingestor import NucleiIngestor
        ingestor = NucleiIngestor()
        if asset_id:
            ingestor.asset_id = asset_id
        result = ingestor.run(target=target, severity=severity)
        logger.info(f"âœ… Nuclei: {result}")
        return result
    except Exception as e:
        logger.error(f"âŒ Nuclei failed: {e}")
        return {"source": "nuclei", "error": str(e)}


def run_wazuh():
    """Wazuh â€” Local Docker"""
    try:
        logger.info("=" * 60)
        logger.info("ðŸ“Š Running Wazuh Ingestor...")
        from backend.ingestion.wazuh_ingestor import WazuhIngestor
        ingestor = WazuhIngestor()
        result = ingestor.run()
        logger.info(f"âœ… Wazuh: {result}")
        return result
    except Exception as e:
        logger.error(f"âŒ Wazuh failed: {e}")
        return {"source": "wazuh", "error": str(e)}


def run_prowler():
    """Prowler â€” AWS scan"""
    try:
        logger.info("=" * 60)
        logger.info("â˜ï¸ Running Prowler Ingestor...")
        from backend.ingestion.prowler_ingestor import ProwlerIngestor
        ingestor = ProwlerIngestor()
        result = ingestor.run()
        logger.info(f"âœ… Prowler: {result}")
        return {"source": "prowler", "output": result}
    except Exception as e:
        logger.error(f"âŒ Prowler failed: {e}")
        return {"source": "prowler", "error": str(e)}


def run_keycloak(identity=None):
    """Keycloak â€” Local Docker (8090)"""
    try:
        logger.info("=" * 60)
        logger.info("ðŸ” Running Keycloak Ingestor...")
        from backend.ingestion.keycloak_ingestor import KeycloakIngestor, KeycloakConfig
        identity = identity or {}
        cfg = KeycloakConfig()
        cfg.keycloak_url = identity.get('url') or cfg.keycloak_url
        cfg.keycloak_realm = identity.get('realm') or cfg.keycloak_realm
        cfg.client_id = identity.get('client_id') or ''
        cfg.client_secret = identity.get('client_secret') or ''
        ingestor = KeycloakIngestor(cfg)
        data = ingestor.collect()
        from backend.database import db
        db.execute_query("""INSERT INTO assets (asset_id,asset_name,asset_type)
            VALUES ('identity-service','Keycloak identity service','identity')
            ON CONFLICT (asset_id) DO NOTHING""")
        for user in data.get('users', []):
            if not user.get('id'):
                continue
            db.execute_query("""INSERT INTO iam_users
                (user_id,username,first_name,last_name,email,email_verified,enabled,mfa_enabled)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (user_id) DO UPDATE SET email=EXCLUDED.email,
                enabled=EXCLUDED.enabled,mfa_enabled=EXCLUDED.mfa_enabled,updated_at=NOW()""",
                (user['id'], user.get('username') or user['id'], user.get('first_name'),
                 user.get('last_name'), user.get('email'), user.get('email_verified', False),
                 user.get('enabled', False), user.get('mfa_enabled', False)))
            if user.get('enabled') and not user.get('mfa_enabled'):
                db.execute_query("""INSERT INTO findings
                    (finding_id,asset_id,source,title,description,severity)
                    VALUES (%s,'identity-service','keycloak',%s,%s,'medium')
                    ON CONFLICT (finding_id) DO UPDATE SET updated_at=NOW()""",
                    ('iam-' + user['id'][:44], 'MFA disabled for ' + (user.get('username') or user['id']),
                     'Enabled identity does not have TOTP configured.'))
        logger.info(f"âœ… Keycloak: {len(data.get('users', []))} users collected")
        return {"source": "keycloak", "users": len(data.get('users', []))}
    except Exception as e:
        logger.error(f"âŒ Keycloak failed: {e}")
        return {"source": "keycloak", "error": str(e)}


def run_threat_intel_enricher(asset_id=None, started_at=None):
    """Threat Intel â€” CVSS/EPSS/KEV enrichment"""
    try:
        logger.info("=" * 60)
        logger.info("ðŸ›¡ï¸ Running Threat Intel Enricher...")
        from backend.Enrichment.threat_intel import ThreatIntelEnricher
        enricher = ThreatIntelEnricher()
        count = enricher.enrich_database_findings(asset_id=asset_id,
                                                 started_at=database_scan_start(started_at))
        logger.info(f"âœ… Threat Intel: {count} findings enriched")
        return {"source": "threat_intel", "enriched": count}
    except Exception as e:
        logger.error(f"âŒ Threat Intel failed: {e}")
        return {"source": "threat_intel", "error": str(e)}


# ============================================================
# UNIFIED OUTPUT GENERATOR
# ============================================================

def fetch_unified_findings(business_context=None, asset_id=None, started_at=None):
    started_at = database_scan_start(started_at)
    """Fetch all findings in unified format with likelihood/impact/metadata"""
    from backend.database import db
    business_context = business_context or {}

    query = """
        SELECT 
            f.finding_id,
            f.asset_id,
            f.source,
            f.severity,
            f.title,
            f.description,
            f.cve_id,
            f.cvss_score,
            f.epss_score,
            f.cisa_kev,
            f.exploit_available,
            f.exploit_type,
            f.mitre_technique,
            f.raw_data,
            f.created_at,
            a.asset_name,
            a.asset_type,
            a.ip_address,
            a.hostname,
            a.environment,
            a.production_status,
            a.criticality,
            a.asset_value,
            a.business_unit,
            a.owner,
            a.internet_exposed,
            c.mfa_enabled,
            c.patching_status,
            c.waf_enabled,
            c.edr_enabled
        FROM findings f
        LEFT JOIN assets a ON f.asset_id = a.asset_id
        LEFT JOIN asset_controls c ON c.asset_id = f.asset_id
        WHERE (%s IS NULL OR f.asset_id = %s)
          AND (%s IS NULL OR f.created_at >= %s)
        ORDER BY 
            CASE f.severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            f.created_at DESC
    """

    findings = db.execute_query(query, (asset_id, asset_id, started_at, started_at))
    unified = []

    for f in findings:
        raw = parse_raw_data(f.get('raw_data'))

        # LIKELIHOOD
        likelihood = {
            "cvss_score": _safe_float(f.get('cvss_score'), default=None),
            "epss_score": _safe_float(f.get('epss_score'), default=None),
            "exploit_available": "Yes" if f.get('cisa_kev') or f.get('exploit_available') else None,
            "exploit_type": f.get('exploit_type') or raw.get('exploit_type'),
            "threat_actor": raw.get("threat_actor"),
            "malware": raw.get("malware"),
            "mitre_technique": f.get('mitre_technique'),
            "patched": f.get('patching_status'),
            "mfa": f.get('mfa_enabled'),
            "waf": f.get('waf_enabled'),
            "edr": f.get('edr_enabled'),
        }

        # IMPACT
        impact = {
            "asset_name": f.get('asset_name') or business_context.get("asset_name"),
            "asset_type": f.get('asset_type') or business_context.get("asset_type"),
            "business_unit": f.get('business_unit') or business_context.get("business_unit"),
            "asset_owner": f.get('owner') or business_context.get("asset_owner"),
            "asset_value": _safe_float(f.get('asset_value'), default=None),
            "downtime_cost_per_hour": _safe_float(business_context.get("downtime_cost"), default=None),
            "recovery_cost": _safe_float(business_context.get("recovery_cost"), default=None),
            "criticality": int(f['criticality']) if f.get('criticality') is not None else None,
            "environment": f.get('environment'),
            "production_status": f.get('production_status'),
            "ip_address": f.get('ip_address'),
            "hostname": f.get('hostname'),
        }

        # METADATA
        created_at = f.get('created_at')
        age_days = None
        if created_at:
            try:
                age_days = (datetime.now() - created_at).days
            except Exception:
                age_days = None

        metadata = {
            "discovered_at": _safe_string(
                raw.get("@timestamp") or (created_at.isoformat() if created_at else None),
                default=datetime.now().isoformat()
            ),
            "source_tool": _safe_string(f.get('source'), default="unknown"),
            "finding_age_days": int(age_days) if age_days is not None else 0,
        }

        # FINAL FINDING
        finding = {
            "finding_id": f['finding_id'],
            "asset_id": f['asset_id'],
            "source": f['source'],
            "severity": _safe_string(f.get('severity'), default="info").lower(),
            "title": _safe_string(f.get('title'), default="Untitled Finding"),
            "description": _safe_string(f.get('description'), default="No description available"),
            "likelihood": likelihood,
            "impact": impact,
            "metadata": metadata,
            "detail": raw,
            "framework_tags": [],
            "remediation_cost": None,
            "risk_reduction": None,
            "risk_score": None,
            "sle": None,
            "aro": None,
            "ale": None,
        }
        unified.append(finding)

    return unified


def save_unified_output(findings, user_config=None, target_ip=None, final=True):
    """Save unified findings to JSON file"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    user_config = user_config or {}

    output = {
        "generated_at": datetime.now().isoformat(),
        "scan_config": {
            "target_url": user_config.get("target_url"),
            "target_ip": target_ip,
            "business": user_config.get("business", {}),
        },
        "total_findings": len(findings),
        "findings": findings,
        "summary": {
            "by_source": {},
            "by_severity": {},
            "kev_count": 0,
            "cve_count": 0,
        }
    }

    for f in findings:
        src = f['source']
        sev = f['severity']

        output['summary']['by_source'][src] = output['summary']['by_source'].get(src, 0) + 1
        output['summary']['by_severity'][sev] = output['summary']['by_severity'].get(sev, 0) + 1

        if f['likelihood'].get('exploit_available') == "Yes":
            output['summary']['kev_count'] += 1
        if f['detail'].get('cve_id'):
            output['summary']['cve_count'] += 1

    latest_file = os.path.join(OUTPUT_DIR, 'latest.json')
    temporary_file = latest_file + '.tmp'
    with open(temporary_file, 'w', encoding='utf-8') as fp:
        json.dump(output, fp, indent=2, default=str)
    os.replace(temporary_file, latest_file)

    if final:
        timestamped_file = os.path.join(OUTPUT_DIR, f'findings_{timestamp}.json')
        with open(timestamped_file, 'w', encoding='utf-8') as fp:
            json.dump(output, fp, indent=2, default=str)

    logger.info(f"âœ… Saved: {latest_file}")
    if final:
        logger.info(f"Saved final scan file: {timestamped_file}")

    return latest_file


# ============================================================
# MAIN PIPELINE
# ============================================================

def main(target_url=None):
    """Run all ingestors and generate unified output"""
    print("\n" + "=" * 60)
    print("ðŸš€ CyberFinGuard â€” Unified Ingestion Pipeline")
    print(f"â° Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60 + "\n")

    # ============================================================
    # LOAD USER CONFIG
    # ============================================================
    user_config = load_user_config()

    # Priority: CLI target, then the saved website URL.
    if not target_url:
        target_url = user_config.get('target_url')
    if not target_url:
        raise ValueError('Save a website URL before starting a scan')

    business_context = user_config.get('business', {})
    website_asset_id = user_config.get('website_asset_id')
    try:
        with open(SCAN_STATUS_PATH, 'r', encoding='utf-8') as stream:
            started_at = json.load(stream).get('started_at')
    except (OSError, ValueError):
        started_at = None

    def publish_current_findings():
        current = fetch_unified_findings(business_context=business_context,
                                         asset_id=website_asset_id, started_at=started_at)
        save_unified_output(current, user_config=user_config, final=False)

    save_unified_output([], user_config=user_config, final=False)

    # ============================================================
    # EXTRACT HOSTNAME/IP
    # ============================================================
    hostname = target_url.replace("https://", "").replace("http://", "").split("/")[0]
    target_ip = None
    if website_asset_id:
        from backend.database import db
        db.execute_query("""INSERT INTO assets (asset_id, asset_name, asset_type, hostname, ip_address, business_unit, owner, asset_value, criticality, internet_exposed)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,TRUE)
            ON CONFLICT (asset_id) DO UPDATE SET ip_address=EXCLUDED.ip_address, updated_at=NOW()""",
            (website_asset_id, business_context.get('asset_name') or hostname,
             business_context.get('asset_type') or 'web_application', hostname, target_ip,
             business_context.get('business_unit'), business_context.get('asset_owner'),
             business_context.get('business_value'), business_context.get('asset_criticality')))

    print(f"ðŸŽ¯ Target URL: {target_url}")
    print(f"ðŸŒ Target IP:  {target_ip}")
    print("Business: " + str(business_context.get("asset_name") or "Not provided"))
    print("Unit: " + str(business_context.get("business_unit") or "Not provided"))
    print("Value: " + str(business_context.get("business_value") or "Not provided"))
    print()

    # ============================================================
    # RUN ALL INGESTORS
    # ============================================================
    results = {}
    update_scan_status('running', 'Starting ZAP')

    # 1. ZAP â€” Manual scan (Nexora website)
    results['zap'] = run_zap_manual(target_url=target_url, asset_id=website_asset_id)
    publish_current_findings()

    # 2. Nmap â€” submitted website hostname
    update_scan_status('running', 'Running Nmap')
    results['nmap'] = run_nmap(target=hostname, asset_id=website_asset_id)
    publish_current_findings()

    update_scan_status('running', 'Running Nuclei')

    # 3. Nuclei â€” Nexora website (all severities)
    results['nuclei'] = run_nuclei(
        target=target_url,
        severity='info,low,medium,high,critical', asset_id=website_asset_id
    )
    publish_current_findings()

    # 4. Wazuh â€” Local Docker
    # Host telemetry is separate from this website scan.

    # 5. Prowler â€” AWS
    # Cloud posture is separate from this website scan.

    # 6. Keycloak â€” Local Docker (8090)
    # Identity posture is separate from this website scan.
    update_scan_status('running', 'Enriching threat intelligence')

    # 7. Threat Intel â€” Enrich CVEs
    results['threat_intel'] = run_threat_intel_enricher(asset_id=website_asset_id,
                                                       started_at=started_at)

    scan_sources = ('zap', 'nmap', 'nuclei')
    successful = [name for name in scan_sources if isinstance(results.get(name), dict)
                  and not results[name].get('error')
                  ]
    if not successful:
        raise RuntimeError('No scanner completed successfully. Check the scanner services and credentials.')

    # ============================================================
    # SUMMARY
    # ============================================================
    print("\n" + "=" * 60)
    print("ðŸ“Š INGESTION SUMMARY")
    print("=" * 60)

    for source, result in results.items():
        print(f"\nðŸ”¹ {source.upper()}:")
        if isinstance(result, dict):
            for key, value in result.items():
                print(f"   {key}: {value}")

    # ============================================================
    # UNIFIED OUTPUT
    # ============================================================
    print("\n" + "=" * 60)
    print("ðŸ“‹ GENERATING UNIFIED OUTPUT")
    print("=" * 60)

    findings = fetch_unified_findings(business_context=business_context,
                                      asset_id=website_asset_id, started_at=started_at)
    update_scan_status('running', 'Writing unified findings')
    output_file = save_unified_output(findings, user_config=user_config, target_ip=target_ip)
    failed_sources = [name for name in scan_sources if results[name].get('error')]
    final_stage = ('Complete with scanner errors: ' + ', '.join(failed_sources)) if failed_sources else 'Complete'
    update_scan_status('complete', final_stage, scanner_results=results)

    print(f"\nâœ… Total findings: {len(findings)}")
    print(f"âœ… Output file: {output_file}")
    print(f"\nðŸ“¤ This file will be consumed by:")
    print(f"   1. Risk Quantification Model (SLE/ARO/ALE)")
    print(f"   2. Investment Optimization Model (Knapsack)")
    print(f"   3. CISO/CFO Dashboards")
    print(f"   4. AI Decision Layer (Chatbot/What-if)")

    print("\n" + "=" * 60)
    print(f"â° Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60 + "\n")

    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    try:
        main(target_url=target)
    except Exception as error:
        update_scan_status('failed', 'Failed', error)
        raise

