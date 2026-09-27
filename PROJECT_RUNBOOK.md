# CyberFinGuard Project Runbook

This document explains how to install, configure, start, use, and troubleshoot CyberFinGuard.

## 1. Overview

CyberFinGuard combines website-security findings with business-impact data and produces technical, executive, risk, and compliance views.

Main workflow:

1. Enter an authorized website URL in the assessment page.
2. The Flask API saves it as an asset in PostgreSQL.
3. The API starts main.py in the background.
4. OWASP ZAP and Nuclei scan the target.
5. Findings are normalized into PostgreSQL and data/unified_findings/latest.json.
6. Threat intelligence can add CVSS, EPSS, and CISA KEV context.
7. Business impact and MFA/WAF/EDR controls are entered.
8. Risk-analysis and dashboard pages display the result.

Technology:

- Next.js, React, and TypeScript frontend.
- Flask API in backend/live_api.py.
- PostgreSQL database.
- Python ingestion modules in backend/ingestion/.
- OWASP ZAP and Nuclei for website scanning.
- Optional Nmap, Wazuh, Prowler/AWS, and Keycloak integrations.
- CISA KEV, EPSS, and NVD enrichment services.

## 2. Services

Required for the basic website assessment:

| Service | Default address | Purpose |
| --- | --- | --- |
| PostgreSQL | localhost:5432 | Persistent data |
| Flask API | 127.0.0.1:8000 | Backend and scan control |
| Next.js | localhost:3000 | Browser interface |
| OWASP ZAP | localhost:8080 | Dynamic website scanning |
| Nuclei | Local executable | Template-based scanning |

Wazuh, Keycloak, Prowler/AWS, and Nmap are optional for the basic website flow.

## 3. Prerequisites

- Windows 10/11, Linux, or macOS.
- Python 3.10 or newer.
- Node.js and npm compatible with frontend/package.json.
- PostgreSQL 15 or newer.
- Git.
- Docker Desktop if using containerized PostgreSQL.

Optional: OWASP ZAP, Nuclei, Nmap, Wazuh, Keycloak, and Prowler.

## 4. Install on Windows

Run PowerShell from the repository root:

~~~powershell
cd D:\PROJECT\CyberFinGuard\CyberFinGuard
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
cd frontend
npm install
cd ..
~~~

If the virtual environment already exists, skip creation. If activation is blocked, use .\venv\Scripts\python.exe directly.

## 5. PostgreSQL setup

### Docker

Run this once:

~~~powershell
docker run -d --name postgres-risk -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=cyber_risk_db -p 5432:5432 postgres:15
~~~

Later starts:

~~~powershell
docker start postgres-risk
docker ps
~~~

### Existing PostgreSQL

Set the correct values in the root .env:

~~~dotenv
DB_HOST=localhost
DB_NAME=cyber_risk_db
DB_USER=postgres
DB_PASSWORD=your-postgres-password
DB_PORT=5432
~~~

Initialize the schema:

~~~powershell
.\venv\Scripts\python.exe setup_db.py
~~~

For demo data only:

~~~powershell
.\venv\Scripts\python.exe setup_db.py --sample
~~~

Do not use --sample for a clean live assessment database.

## 6. Environment file

Create the file:

~~~powershell
Copy-Item .env.example .env
~~~

Never commit .env. It may contain passwords, cloud credentials, scanner credentials, or provider keys.

### Required database values

~~~dotenv
DB_HOST=localhost
DB_NAME=cyber_risk_db
DB_USER=postgres
DB_PASSWORD=your-password
DB_PORT=5432
~~~

### OWASP ZAP

Required for website scans:

~~~dotenv
ZAP_API_URL=http://localhost:8080
ZAP_API_KEY=
ZAP_TARGET_URL=https://httpbin.org
~~~

Start ZAP before scanning and configure its API on localhost port 8080. Set ZAP_API_KEY if API-key protection is enabled.

Optional proxy settings:

~~~dotenv
SCANNER_HTTP_PROXY=http://127.0.0.1:8080
ZAP_PROXY_CA_CERT=data\zap_proxy_root.cer
~~~

Only set SCANNER_HTTP_PROXY when ZAP is accepting proxy traffic.

### Nuclei

~~~dotenv
NUCLEI_PATH=D:\Tools\Nuclei\nuclei.exe
NUCLEI_TARGET_URL=https://httpbin.org
NUCLEI_RATE_LIMIT=40
NUCLEI_CONCURRENCY=15
NUCLEI_REQUEST_TIMEOUT=8
NUCLEI_SCAN_TIMEOUT=600
NUCLEI_MAX_HOST_ERROR=10
~~~

Set NUCLEI_PATH to the real executable. Lower rate and concurrency for fragile targets.

### Optional Nmap

~~~dotenv
NMAP_PATH=C:\Program Files (x86)\Nmap\nmap.exe
~~~

### Optional Wazuh

~~~dotenv
WAZUH_API_URL=https://localhost:55000
WAZUH_USERNAME=wazuh-wui
WAZUH_PASSWORD=your-wazuh-password
WAZUH_INDEXER_URL=https://localhost:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASSWORD=your-indexer-password
WAZUH_MANAGER_IP=localhost
~~~

### Optional Keycloak

~~~dotenv
KEYCLOAK_URL=http://127.0.0.1:8090
KEYCLOAK_ADMIN=admin
KEYCLOAK_PASSWORD=your-keycloak-password
KEYCLOAK_REALM=master
~~~

### Optional Prowler and AWS

~~~dotenv
PROWLER_PATH=C:\Users\your-username\.local\bin\prowler.exe
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_DEFAULT_REGION=ap-south-1
~~~

Use least-privilege or short-lived AWS credentials.

### Threat intelligence

~~~dotenv
CISA_KEV_URL=https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
EPSS_API_URL=https://api.first.org/data/v1/epss
NVD_API_URL=https://services.nvd.nist.gov/rest/json/cves/2.0
NVD_API_KEY=
~~~

NVD_API_KEY is optional.

### Runtime and outputs

~~~dotenv
POLL_INTERVAL_SECONDS=300
INGESTION_BATCH_SIZE=100
UNIFIED_OUTPUT_DIR=data/unified_findings
ANALYTICS_OUTPUT_DIR=data/analytics
PYTHONUTF8=1
PYTHONIOENCODING=utf-8
~~~

### API and frontend networking

~~~dotenv
API_HOST=127.0.0.1
API_PORT=8000
FRONTEND_ORIGIN=http://localhost:3000,http://127.0.0.1:3000
~~~

frontend/next.config.ts proxies /api requests to port 8000. Normally no frontend API variable is needed locally. If the API has a separate browser-accessible origin, create frontend/.env.local:

~~~dotenv
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
~~~

Restart Next.js after changing frontend environment variables or next.config.ts.

### Optional AI/provider values

~~~dotenv
OPENROUTER_API_KEY=your-key
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
OPENROUTER_MODEL=openai/gpt-4o-mini
OPENROUTER_APP_TITLE=CyberFinGuard
~~~

## 7. Start the application

Use three PowerShell windows.

### Window 1: PostgreSQL

~~~powershell
docker start postgres-risk
~~~

Skip this when PostgreSQL is a Windows service.

### Window 2: Flask API

~~~powershell
cd D:\PROJECT\CyberFinGuard\CyberFinGuard
.\venv\Scripts\python.exe -m backend.live_api
~~~

The API listens on http://127.0.0.1:8000.

The compatibility command also starts the same live API:

~~~powershell
.\venv\Scripts\python.exe backend\api.py
~~~

Run only one API process.

Health check:

~~~powershell
Invoke-WebRequest http://127.0.0.1:8000/api/health
~~~

### Window 3: frontend

~~~powershell
cd D:\PROJECT\CyberFinGuard\CyberFinGuard\frontend
npm run dev
~~~

Open http://localhost:3000/assessment.

## 8. Website assessment

1. Enter an authorized URL starting with http:// or https://.
2. Click Save website and start scan.
3. Keep the API, ZAP, and Nuclei available.
4. Enter business impact values.
5. Wait for scan status to become complete.
6. Review scanner-derived fields.
7. Enter MFA, WAF, and EDR status.
8. Submit the assessment.
9. Review technical, executive, risk, and compliance dashboards.

Runtime files:

- data/scan_config.json: saved target and configuration.
- data/scan_status.json: scan progress.
- data/scan.log: scanner output.
- data/unified_findings/latest.json: latest normalized findings.

## 9. API endpoints

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | /api/health | Health check |
| POST | /api/assets/website | Save website asset |
| GET | /api/assessment/config | Load assessment configuration |
| POST | /api/scan/run | Start website scan |
| GET | /api/scan/status | Read scan progress |
| POST | /api/assets/business-context | Save business impact |
| GET | /api/assessment/model-preview | Preview risk inputs |
| POST | /api/assessment/submit | Submit controls and start risk assessment |
| GET | /api/assessment/status/id | Read assessment status |
| GET | /api/dashboard/technical | Technical dashboard |
| GET | /api/dashboard/executive | Executive dashboard |
| GET | /api/risk-analysis | Risk-analysis workspace |
| GET | /api/compliance/summary | Compliance summary |
| GET | /api/compliance/findings | Compliance mappings |
| POST | /api/assistant/query | Assistant request |
| GET | /api/assessment/summary.pdf | PDF report |

## 10. Standalone ingestion

The live API normally starts scans automatically. Direct execution is also possible:

~~~powershell
.\venv\Scripts\python.exe main.py https://httpbin.org/
~~~

Without a target argument, main.py uses the target saved in data/scan_config.json when available.

Only scan systems for which you have explicit authorization.

## 11. Project structure

~~~text
CyberFinGuard/
├── backend/
│   ├── live_api.py                 # Current Flask API
│   ├── api.py                      # Compatibility launcher
│   ├── ingestion/                  # Scanner ingestors
│   ├── enrichment/                 # Threat intelligence
│   ├── assessment_pipeline.py      # Risk input transformation
│   ├── remote_risk_model.py        # Hosted risk integration
│   ├── risk_estimation.py          # Local risk estimation
│   └── pdf_report.py               # PDF generation
├── frontend/
│   ├── src/app/                    # Next.js pages
│   ├── src/components/             # UI components
│   ├── src/lib/api.ts              # API client
│   └── next.config.ts              # API proxy
├── data/                           # Runtime configuration and outputs
├── risk_engine/
├── main.py
├── setup_db.py
├── requirements.txt
├── .env.example
└── PROJECT_RUNBOOK.md
~~~

## 12. Troubleshooting

### Frontend shows Request failed (404)

This normally means a stale or incorrect process is running on port 8000. Start the canonical API:

~~~powershell
.\venv\Scripts\python.exe -m backend.live_api
Invoke-WebRequest http://127.0.0.1:8000/api/health
~~~

Restart npm run dev if next.config.ts changed.

### Backend is not reachable

Check that the API listens on port 8000 and the frontend listens on port 3000. The proxy is configured in frontend/next.config.ts.

### Database unavailable

~~~powershell
docker ps
docker logs postgres-risk
.\venv\Scripts\python.exe setup_db.py
~~~

Verify all DB_* values in .env.

### Website scan fails

Check that ZAP is running, ZAP_API_KEY is correct, NUCLEI_PATH points to an executable, the target is reachable, and data/scan.log has no errors.

### Scan is slow or remains running

~~~powershell
Get-Content data\scan.log -Wait
Get-Content data\scan_status.json
~~~

For fragile targets, reduce load:

~~~dotenv
NUCLEI_RATE_LIMIT=10
NUCLEI_CONCURRENCY=3
NUCLEI_REQUEST_TIMEOUT=15
~~~

### Target responds with HTTP 404

An immediate Request failed (404) is an API route/proxy problem. A 404 reported by ZAP or Nuclei is a response from the target website and is a scanner observation.

### No findings appear

Zero findings can be valid. Confirm the scan completed, the target is reachable, PostgreSQL is available, and data/scan.log has no ingestion errors.

### Risk submission stays pending

The risk model may be unavailable, may reject input, or may be missing required values. Check the assessment status endpoint and backend logs. Raw input is retained instead of fabricating a result.

## 13. Security guidance

- Rotate credentials or keys exposed in a shared file, screenshot, terminal, or chat.
- Keep .env, data/scan_config.json, scanner certificates, and logs out of source control.
- Keep the API bound to localhost unless authentication is configured.
- Do not expose PostgreSQL, ZAP, Wazuh, Keycloak, or Flask directly to the internet.
- Use least-privilege AWS and scanner accounts.
- Scan only authorized systems.
- Treat scanner logs as sensitive.
- Back up PostgreSQL before destructive changes.
- Do not use setup_db.py --sample for live data.

## 14. Validation commands

~~~powershell
.\venv\Scripts\python.exe -m pip show Flask flask-cors psycopg2-binary python-dotenv requests pandas numpy matplotlib
Invoke-WebRequest http://127.0.0.1:8000/api/health
cd frontend
npm run build
Test-Path 'C:\Program Files (x86)\Nmap\nmap.exe'
Test-Path 'D:\Tools\Nuclei\nuclei.exe'
~~~

## 15. First-run checklist

- [ ] Python environment and dependencies installed.
- [ ] Node dependencies installed.
- [ ] PostgreSQL running on port 5432.
- [ ] .env created with database values.
- [ ] setup_db.py completed successfully.
- [ ] ZAP running on port 8080.
- [ ] Nuclei path is correct.
- [ ] API health check succeeds.
- [ ] Frontend opens at localhost:3000/assessment.
- [ ] An authorized test URL is entered.
- [ ] data/scan.log is monitored during the first scan.

