"""
Nuclei Data Ingestor
Runs Nuclei scan and stores findings in database
"""

import subprocess
import json
import logging
import uuid
import os
import sys
import time
from datetime import datetime
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database import db

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Nuclei path from .env
NUCLEI_PATH = os.getenv('NUCLEI_PATH', 'nuclei')


def _positive_int(name, default):
    """Read a positive integer scanner setting without failing on bad config."""
    try:
        value = int(os.getenv(name, str(default)))
        return value if value > 0 else default
    except ValueError:
        logger.warning("Invalid %s value; using %s", name, default)
        return default


class NucleiIngestor:
    def __init__(self):
        self.asset_id = 'web_target'

    def run_scan(self, target, severity='low,medium,high,critical'):
        """Run Nuclei scan and save JSON output"""
        self.host_unresponsive = False
        rate_limit = _positive_int('NUCLEI_RATE_LIMIT', 40)
        concurrency = _positive_int('NUCLEI_CONCURRENCY', 15)
        request_timeout = _positive_int('NUCLEI_REQUEST_TIMEOUT', 8)
        scan_timeout = _positive_int('NUCLEI_SCAN_TIMEOUT', 600)
        max_host_error = _positive_int('NUCLEI_MAX_HOST_ERROR', 10)
        output_file = f'nuclei_{target.replace("://", "_").replace("/", "_").replace(".", "_")}.json'

        # Sanity check: templates installed?
        templates_dir = os.path.expanduser(r'~\nuclei-templates')
        if not os.path.isdir(templates_dir):
            logger.error(f"❌ Nuclei templates not found at {templates_dir}")
            logger.error("   Fix: run  nuclei -update-templates")
            return None

        cmd = [
            NUCLEI_PATH,
            '-u', target,
            '-severity', severity,
            '-jsonl',
            '-o', output_file,
            '-rate-limit', str(rate_limit),
            '-timeout', str(request_timeout),
            '-retries', '0',
            '-c', str(concurrency),
            '-max-host-error', str(max_host_error),
            '-stats',
            '-stats-interval', '15',
            '-no-interactsh',          # skip OOB server if not needed (much faster)
        ]
        proxy = os.getenv('SCANNER_HTTP_PROXY')
        if proxy:
            cmd.extend(['-proxy', proxy])

        logger.info(f"🚀 Running Nuclei scan on {target}...")
        logger.info(f"   Severity: {severity}")

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            start = time.time()
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    logger.info(f"   [nuclei] {line}")
                    if 'unresponsive permanently' in line:
                        self.host_unresponsive = True
                if time.time() - start > scan_timeout:
                    proc.kill()
                    logger.error("Scan timeout (%s sec)", scan_timeout)
                    return None

            proc.wait(timeout=30)

            if self.host_unresponsive:
                logger.error("Nuclei could not complete: target became unresponsive")
                return None

            if proc.returncode != 0:
                logger.error(f"❌ Scan failed (exit {proc.returncode})")
                return None

            # ✅ Real success check
            if not os.path.exists(output_file):
                logger.warning("⚠️ Nuclei exited 0 but produced no output file")
                return None

            size = os.path.getsize(output_file)
            if size == 0:
                logger.warning("⚠️ Nuclei produced an empty file — 0 findings (target may be clean)")
            else:
                logger.info(f"✅ Scan complete: {output_file} ({size} bytes)")

            return output_file

        except Exception as e:
            logger.error(f"❌ Scan error: {e}")
            return None


    def parse_json(self, json_file):
        """Parse Nuclei JSON output"""
        if not os.path.exists(json_file):
            logger.error(f"❌ File not found: {json_file}")
            return []
        
        findings = []
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        finding = json.loads(line)
                        findings.append(finding)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            logger.error(f"❌ JSON parse error: {e}")
        
        return findings

    def normalize_finding(self, finding):
        """Convert Nuclei finding to unified schema"""
        info = finding.get('info', {})
        severity = info.get('severity', 'low')
        
        severity_map = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'info': 'info',
            'unknown': 'info'
        }
        
        # Extract CVE from classification
        classification = info.get('classification', {})
        cve_ids = classification.get('cve-id', [])
        cve_id = cve_ids[0] if cve_ids else None
        
        return {
            'finding_id': f"nuclei_{uuid.uuid4().hex[:8]}",
            'asset_id': self.asset_id,
            'source': 'nuclei',
            'cve_id': cve_id,
            'title': info.get('name', 'Nuclei Finding'),
            'description': info.get('description', '') or f"Matched at: {finding.get('matched-at', 'unknown')}",
            'severity': severity_map.get(severity, 'info'),
            'raw_data': json.dumps(finding)
        }

    def ingest(self, json_file):
        """Parse JSON and store findings in DB"""
        findings = self.parse_json(json_file)
        logger.info(f"📊 Found {len(findings)} Nuclei findings")
        
        count = 0
        for finding in findings:
            try:
                norm = self.normalize_finding(finding)
                
                query = """
                    INSERT INTO findings (finding_id, asset_id, source, cve_id, title, description, severity, raw_data)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (finding_id) DO NOTHING
                """
                db.execute_query(query, (
                    norm['finding_id'], norm['asset_id'], norm['source'],
                    norm['cve_id'], norm['title'], norm['description'],
                    norm['severity'], norm['raw_data']
                ))
                count += 1
                logger.info(f"✅ Ingested: {norm['title'][:60]}")
            except Exception as e:
                logger.error(f"❌ Failed: {e}")
        
        return {'source': 'nuclei', 'findings_ingested': count}

    def run(self, target=None, severity='low,medium,high,critical'):
        """Full pipeline: scan → parse → ingest"""
        if not target:
            target = os.getenv('NUCLEI_TARGET_URL', 'https://httpbin.org')

        logger.info(f"🎯 Nuclei target: {target}")
        logger.info(f"   Severity: {severity}")

        json_file = self.run_scan(target, severity=severity)
        if not json_file:
            return {'source': 'nuclei', 'error': 'target_unresponsive' if self.host_unresponsive else 'scan_failed', 'findings_ingested': 0}

        result = self.ingest(json_file)

        if result.get('findings_ingested', 0) == 0:
            result['note'] = 'scan_completed_no_findings'
            logger.info("ℹ️  Scan completed with 0 findings")

        return result


if __name__ == "__main__":
    ingestor = NucleiIngestor()
    
    # Target select karo
    target = input("Enter target URL (default: https://httpbin.org): ").strip()
    if not target:
        target = 'https://httpbin.org'
    
    result = ingestor.run(target)
    print(result)
