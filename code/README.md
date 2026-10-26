# AI-Based Adaptive Penetration Testing Assistant for Intelligent Vulnerability Assessment and Risk Prioritization

A safety-first final-year project that registers authorized targets, runs offline mock assessments, normalizes findings, combines explainable and ML risk scores, recommends non-destructive next actions, records audit events, and generates PDF, CSV, and JSON reports.

## Safety boundary

- Mock mode is the default and never contacts a target.
- A valid authorization record and date window are required before every scan.
- Viewer accounts cannot scan; only administrators can authorize.
- Live mode is disabled by default and scanner arguments are never accepted from the web UI.
- The system does not exploit vulnerabilities, execute arbitrary commands, steal credentials, persist, or run destructive payloads.
- Every synthetic record is labelled DEMO / MOCK.

## Architecture

React/Vite dashboard to FastAPI REST API to SQLAlchemy database. Results pass through normalized vulnerability records, enrichment, rule scoring, ML scoring, hybrid prioritization, recommendations, reports, and audits. Scanner availability is shown at /health.

## Local setup

Python 3.11 or later and Node 20 or later are required.

1. Run: py -m venv .venv
2. Run: .venv\Scripts\Activate.ps1
3. Run: pip install -r requirements.txt
4. Copy .env.example to .env
5. Run: python scripts/seed_demo.py
6. Run: uvicorn app.main:app --reload
7. In frontend, run: npm install
8. In frontend, run: npm run dev

Open http://localhost:5173. API documentation is at http://localhost:8000/docs.

Development credentials are admin / Admin123! and analyst / Analyst123!. Replace them and SECRET_KEY before deployment.

## Demo workflow

The seed script creates a target with time-bounded DEMO-AUTH-001 authorization. Sign in, open Scans, and run a mock vulnerability scan. Refresh to see assets, findings, hybrid scores, and recommendations. Reports are exposed at /reports/{scan_id}?format=pdf, csv, or json with bearer authentication.

New targets are deliberately not self-authorizable in the UI. An administrator calls POST /targets/{id}/authorize so approval remains explicit and privileged.

## Risk and ML methodology

Rule risk uses CVSS, known exploitation, and exposure. Final risk is 0.4 times the rule score plus 0.6 times the ML score. Both component scores and confidence remain visible. Bands are Low 0-25, Medium 26-50, High 51-75, and Critical 76-100.

The target is not a copy of CVSS. It incorporates KEV membership, exploitability, service and asset exposure, impact, port, and vulnerability age. The bundled dataset is synthetic and for development only.

Dataset and model commands:

1. python scripts/download_nvd.py 2025
2. python scripts/download_kev.py
3. python scripts/process_nvd.py
4. python scripts/merge_security_data.py
5. python -m ml.train
6. python -m ml.evaluate

Training creates models/risk_model.joblib, models/preprocessor.joblib, reports/model_evaluation.json, and reports/confusion_matrix.png. Evaluation uses balanced class weights, macro F1, per-class precision and recall, accuracy, and a confusion matrix.

## Testing, frontend build, and Docker

- Backend tests: pytest -q
- Frontend build: cd frontend, then npm run build
- Containers: docker compose up --build

## Integrated engineering tools

- SHAP: `GET /risk-assessments/{id}/explanation` returns the strongest local model factors.
- MLflow: training runs, metrics, datasets, and model artifacts are recorded at http://localhost:5000.
- Celery and Redis: Docker scan requests run on a bounded background worker queue.
- PostgreSQL and Alembic: PostgreSQL is the container database; create future migrations with `alembic revision --autogenerate -m "description"`.
- Trivy: run `docker compose --profile tools run --rm trivy`, then import the generated JSON through `POST /integrations/trivy/import/{target_id}` for an authorized target.
- DefectDojo: `GET /integrations/defectdojo/export/{scan_id}` produces Generic Findings Import data.
- Prometheus: http://localhost:9090 scrapes API request count and latency from `/metrics`.
- Grafana: http://localhost:3000 (development default `admin` / `admin`) includes a provisioned operations dashboard. Change `GRAFANA_PASSWORD` outside local demonstrations.

The default remains non-destructive: live scanning is disabled, the Trivy service only reads the mounted workspace, and imports still require an authorized target.

SQLite is the development default. Set DATABASE_URL to PostgreSQL in production and install the matching SQLAlchemy driver. All environment variables are documented in .env.example.

## API coverage

Implemented groups include authentication/current user, target CRUD and authorization, scans, assets, normalized vulnerabilities, risks, recommendations, NVD and KEV refresh hooks, dashboard summaries, reports, and admin-only audit logs. List endpoints are bounded and common filters are indexed.

## Scanner integration

The API reports Nmap and Nuclei availability and fails clearly if a requested tool is absent. Live jobs remain safely blocked until a controlled lab adapter is configured. Production adapters should construct only allowlisted commands, parse Nmap XML, Nuclei JSONL, or ZAP JSON, apply timeouts, and revalidate stored authorization immediately before execution.

## Known limitations and future work

- Add Alembic migrations, Redis/Celery workers, refresh tokens, rate limits, multi-tenancy, and secrets management for production.
- Implement controlled-lab live adapters and cached NVD enrichment after the environment is approved.
- The sample dataset is too small for meaningful academic claims; use multi-year NVD plus CISA KEV.
- Compare Random Forest with gradient boosting and logistic regression, calibrate probabilities, and monitor model and data drift.
