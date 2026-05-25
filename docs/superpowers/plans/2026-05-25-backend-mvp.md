# Backend MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete a backend-first MVP that scans a repo, retrieves vulnerability data, ranks remediation tasks, persists results, and reports quality metrics.

**Architecture:** Keep `ScanService` as the single scanner engine. CLI and FastAPI call the service, persistence stores scan results, evals verify behavior, and traces record execution evidence.

**Tech Stack:** Python 3.11+, FastAPI, SQLAlchemy, Alembic, Postgres, pgvector, unittest/pytest-compatible tests, OSV API.

---

## File Structure Map

- `backend/app/services/scan_service.py`: scanner orchestration and safe public output.
- `backend/app/services/persistence.py`: DB writes for scan results.
- `backend/app/api/routes_repos.py`: scan/read endpoints.
- `backend/app/cli.py`: local CLI scan and report output.
- `backend/app/eval/run_eval.py`: fixture eval runner.
- `backend/app/eval/metrics.py`: deterministic eval metrics.
- `backend/app/services/trace_service.py`: local trace recording fallback.
- `backend/tests/`: unit and integration-style tests using fakes unless explicitly marked live.
- `docs/superpowers/specs/2026-05-25-backend-mvp-design.md`: stable product/architecture reference.

## Task 1: Verify Runtime And DB Baseline

**Files:**

- Modify: `README.md`
- Test: no tracked test file required

- [ ] **Step 1: Install backend deps in Python 3.11+ environment**

Run:

```bash
cd backend
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Expected:

```text
Successfully installed ...
```

- [ ] **Step 2: Start Postgres/pgvector**

Run:

```bash
cd ..
docker compose up -d postgres
docker compose ps
```

Expected:

```text
vulnsage-postgres ... healthy
```

- [ ] **Step 3: Run migration**

Run:

```bash
cd backend
source .venv/bin/activate
alembic upgrade head
```

Expected:

```text
Running upgrade  -> 0001_initial_schema
```

- [ ] **Step 4: Run API smoke test**

Run:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
curl http://127.0.0.1:8000/health
```

Expected:

```json
{"status":"ok","service":"vulnsage-ai-backend","version":"0.1.0"}
```

- [ ] **Step 5: Update README setup notes**

Add exact commands that worked on this machine, including any Python or Docker version caveats.

- [ ] **Step 6: Commit**

```bash
git add README.md
git commit -m "Document backend runtime setup"
```

## Task 2: Persist Scan Results End-To-End

**Files:**

- Modify: `backend/app/services/persistence.py`
- Modify: `backend/app/api/routes_repos.py`
- Test: `backend/tests/test_persistence.py`

- [ ] **Step 1: Write failing persistence test**

Create `backend/tests/test_persistence.py` with a SQLite-backed SQLAlchemy session for unit-level persistence behavior. Test that persisting a fake `ScanResult` creates one repo, one scan, packages, vulnerabilities, aliases, package-vulnerability links, reachability, and remediation tasks.

Run:

```bash
cd backend
PYTHONPATH=. python3 -m unittest tests.test_persistence
```

Expected:

```text
FAILED
```

Failure should be about missing/incorrect persistence behavior, not import errors.

- [ ] **Step 2: Implement minimal persistence fixes**

Update `persist_scan_result` so it:

- upserts repo by `full_name`
- creates a new scan per scan call
- stores all parsed packages
- stores canonical vulnerabilities and aliases
- stores remediation task rows matching public task output
- commits only once per scan

- [ ] **Step 3: Verify persistence test passes**

Run:

```bash
PYTHONPATH=. python3 -m unittest tests.test_persistence
```

Expected:

```text
OK
```

- [ ] **Step 4: Add API persistence behavior test**

Add a route test if FastAPI dependencies are installed. If not installed, keep this as a documented blocked check in README and verify after Task 1.

- [ ] **Step 5: Run full tests**

```bash
PYTHONPATH=. python3 -m unittest discover tests
```

Expected:

```text
OK
```

- [ ] **Step 6: Commit**

```bash
git add backend/app/services/persistence.py backend/app/api/routes_repos.py backend/tests/test_persistence.py
git commit -m "Persist scan results"
```

## Task 3: Improve CLI Report

**Files:**

- Modify: `backend/app/cli.py`
- Test: `backend/tests/test_cli.py`

- [ ] **Step 1: Write failing CLI report test**

Test human-readable output from `vulnsage scan --offline` and a fake scan path. Assert output includes:

- repo name
- package count
- remediation task count
- top package
- priority
- fixed version

Also assert it does not include `raw`, `details`, `PoC`, or `payload`.

- [ ] **Step 2: Implement report formatter**

Add a small formatter function in `backend/app/cli.py`:

```python
def format_scan_summary(result: ScanResult) -> str:
    ...
```

It should print top 5 remediation tasks with:

```text
P0_RELEASE_BLOCKER lodash 4.17.20 -> 4.17.21 CVE-...
Reason: production + possibly_reachable + fix available
Evidence: src/upload/receiptParser.ts
```

- [ ] **Step 3: Verify CLI tests**

```bash
PYTHONPATH=. python3 -m unittest tests.test_cli
```

Expected:

```text
OK
```

- [ ] **Step 4: Live CLI smoke**

```bash
PYTHONPATH=. python3 -m app.cli scan ../demo-repos/payments-api
```

Expected:

```text
Scan complete: payments-api
Release blockers: 2
```

- [ ] **Step 5: Commit**

```bash
git add backend/app/cli.py backend/tests/test_cli.py
git commit -m "Improve scan CLI report"
```

## Task 4: Add Eval Harness V1

**Files:**

- Create: `backend/app/eval/metrics.py`
- Create: `backend/app/eval/run_eval.py`
- Create: `backend/app/eval/cases/backend_mvp.jsonl`
- Test: `backend/tests/test_eval_metrics.py`

- [ ] **Step 1: Write failing metric tests**

Test exact-match accuracy for:

- vulnerability affected
- fixed version
- dependency scope
- reachability
- priority
- evidence present

- [ ] **Step 2: Implement metrics**

Implement pure functions:

```python
def exact_match_accuracy(rows: list[dict], key: str) -> float: ...
def score_case(expected: dict, actual: dict) -> dict: ...
def summarize_scores(scores: list[dict]) -> dict: ...
```

- [ ] **Step 3: Add 10 eval cases**

Cases must cover:

- direct production high issue
- critical dev-only issue
- transitive high issue
- no fixed version
- unknown reachability
- alias dedupe
- package reference dedupe guard
- unsafe details redaction
- owner inference
- route evidence present

- [ ] **Step 4: Implement eval runner**

`python -m app.eval.run_eval` should load JSONL, run deterministic checks against fixture outputs, and print metric JSON.

- [ ] **Step 5: Verify**

```bash
PYTHONPATH=. python3 -m unittest tests.test_eval_metrics
PYTHONPATH=. python3 -m app.eval.run_eval
```

Expected:

```text
vulnerability_match_accuracy >= 0.85
fixed_version_accuracy >= 0.85
citation_precision >= 0.80
```

- [ ] **Step 6: Commit**

```bash
git add backend/app/eval backend/tests/test_eval_metrics.py
git commit -m "Add backend MVP eval harness"
```

## Task 5: Add Local Trace Fallback

**Files:**

- Create: `backend/app/services/trace_service.py`
- Modify: `backend/app/services/scan_service.py`
- Modify: `backend/app/models/core.py` only if model change is required
- Test: `backend/tests/test_trace_service.py`

- [ ] **Step 1: Write failing trace tests**

Test trace events can be created for:

- scan start
- OSV package query
- normalization result
- risk score
- scan complete

Assert no event stores raw advisory details or secret-like values.

- [ ] **Step 2: Implement in-memory trace collector**

Add a lightweight collector that can later be backed by DB:

```python
class TraceCollector:
    def record(self, agent_name: str, input_json: dict, output_json: dict) -> None: ...
```

- [ ] **Step 3: Wire optional trace collector into ScanService**

Keep constructor backward compatible:

```python
ScanService(osv_client=client, trace_collector=collector)
```

- [ ] **Step 4: Verify**

```bash
PYTHONPATH=. python3 -m unittest tests.test_trace_service tests.test_scan_service
```

Expected:

```text
OK
```

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/trace_service.py backend/app/services/scan_service.py backend/tests/test_trace_service.py backend/tests/test_scan_service.py
git commit -m "Add local scan tracing"
```

## Task 6: Final MVP Demo Path

**Files:**

- Modify: `README.md`
- Create: `docs/demo-script.md`
- Test: no new test file required

- [ ] **Step 1: Write demo script**

Include exact commands:

```bash
docker compose up -d postgres
cd backend
alembic upgrade head
uvicorn app.main:app --reload
PYTHONPATH=. python -m app.cli scan ../demo-repos/payments-api
PYTHONPATH=. python -m app.eval.run_eval
```

- [ ] **Step 2: Include expected demo claims**

The script must show:

- local scan works
- live OSV data works
- high production issue can outrank critical dev-only issue
- public output is safe
- eval metrics run
- traces exist

- [ ] **Step 3: Run final verification**

```bash
cd backend
PYTHONPATH=. python3 -m unittest discover tests
PYTHONPATH=. python3 -m app.cli scan ../demo-repos/payments-api --offline
```

If deps/DB are installed:

```bash
alembic upgrade head
curl http://127.0.0.1:8000/health
curl -X POST http://127.0.0.1:8000/repos/scan-local \
  -H "Content-Type: application/json" \
  -d '{"path":"../demo-repos/payments-api"}'
```

- [ ] **Step 4: Karen-style final audit**

Dispatch or manually run review against:

- MVP acceptance criteria
- test coverage
- unsafe output
- persistence correctness
- README/demo accuracy

- [ ] **Step 5: Commit and push**

```bash
git add README.md docs/demo-script.md
git commit -m "Document backend MVP demo"
git push
```

## Acceptance Checklist

- [ ] CLI scan works offline and live.
- [ ] API health works.
- [ ] API scan endpoint works.
- [ ] DB migration runs.
- [ ] Scan endpoint persists rows.
- [ ] Read endpoints return persisted scan data.
- [ ] Public output excludes raw advisory bodies and unsafe PoC/payload references.
- [ ] Eval runner reports deterministic metrics.
- [ ] Trace fallback records scan events.
- [ ] README/demo docs let another agent reproduce MVP.

