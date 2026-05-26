# Coffee-First Backend MVP Implementation Plan

> Future agents: this plan intentionally narrows the MVP. Do not spend this week on frontend, GitHub App install flow, PR generation, full LangGraph, or full RAG unless the user explicitly changes the goal. The product's coffee is high-quality vulnerability findings.

**Goal:** make Sage-AI excellent at one thing first: scan a repo and produce trustworthy dependency vulnerability priorities with evidence, safe wording, and measurable quality.

**Core engine:** `ScanService` remains the single scanner path. CLI, FastAPI, future VS Code extension, and future GitHub integrations should call this same service.

---

## Current State

Done:

- local repo scan
- Node `package.json` and `package-lock.json` parser
- OSV client
- vulnerability normalization and alias dedupe
- safe public output that redacts raw advisory details
- reachability signals from imports/routes/CODEOWNERS
- deterministic risk scoring
- patch/test/rollback plan scaffold
- CLI and FastAPI skeleton
- DB models/migration scaffold
- demo repo
- unit tests for parser, OSV client, normalizer, risk scoring, and scan flow
- deterministic eval harness with 10 scanner-executed fixture cases
- verifier/nemesis report checks for missing findings, false positives, evidence, priority, fixed version, unsupported claims, and unsafe output
- scanner hardening for incomplete OSV failures, malformed OSV payloads, mismatched advisories, exact-version-only OSV queries, and unsafe public strings

Known blockers:

- Docker and FastAPI dependencies were not available in this shell, so DB/API smoke checks are not verified here

---

## Coffee vs Matcha

Coffee:

- find vulnerable dependencies
- avoid duplicate or over-merged alerts
- identify direct/transitive and prod/dev context
- connect package usage to source evidence
- rank high production risk above critical dev-only noise
- produce safe structured output
- prove quality with evals and verifier checks

Coffee machine:

- fixture eval cases
- deterministic verifier
- focused tests
- Karen audit gate
- clear docs for future agents

Matcha for later:

- frontend dashboard
- GitHub App
- automatic PR creation
- Jira/Slack
- full RAG/pgvector retrieval
- LangGraph multi-agent orchestration
- executive reports

---

## Task 1: Add Eval And Verifier Harness

Files:

- Create: `backend/app/eval/metrics.py`
- Create: `backend/app/eval/verifier.py`
- Create: `backend/app/eval/run_eval.py`
- Create: `backend/app/eval/cases/backend_mvp.jsonl`
- Test: `backend/tests/test_eval_metrics.py`
- Test: `backend/tests/test_report_verifier.py`

- [x] Write tests for exact-match metrics, evidence coverage, unsafe output detection, unsupported claim detection, missing expected task, wrong priority, and wrong fixed version.
- [x] Implement pure metric functions with no network dependency.
- [x] Implement verifier output with `passed`, `scores`, `findings`, and `summary`.
- [x] Add at least 10 fixture cases.
- [x] Make `python -m app.eval.run_eval` print JSON metrics.
- [x] Run targeted eval tests.
- [x] Run full unit suite.

Success:

```text
vulnerability_match_accuracy >= 0.85
fixed_version_accuracy >= 0.85
citation_precision >= 0.80
unsupported_claim_rate <= 0.10
```

---

## Task 2: Improve Finding Quality Based On Eval Failures

Files likely touched:

- `backend/app/services/reachability.py`
- `backend/app/services/risk_scoring.py`
- `backend/app/services/vulnerability_normalizer.py`
- `backend/app/services/patch_planner.py`
- `backend/app/services/scan_service.py`

- [x] Run eval harness.
- [x] Fix only MVP-blocking failures found in the scanner.
- [x] Prioritize false positives, false negatives, unsafe output, wrong priority, wrong fixed version, and weak evidence.
- [x] Keep changes deterministic.
- [x] Add or update tests for each fix.

---

## Task 3: CLI Demo Report

Files:

- Modify: `backend/app/cli.py`
- Test: `backend/tests/test_cli.py`

- [ ] Add a small human-readable report formatter.
- [ ] Show repo, package count, task count, top priorities, fixed version, and evidence source.
- [ ] Assert report does not include raw details, PoC text, exploit links, or payload language.

---

## Task 4: Persistence And API Smoke

Files:

- Modify: `backend/app/services/persistence.py`
- Modify: `backend/app/api/routes_repos.py`
- Test: `backend/tests/test_persistence.py`

- [ ] Unit-test persistence with SQLite where possible.
- [ ] Verify Postgres/pgvector only when Docker is available.
- [ ] Keep DB work scoped to storing scanner outputs.
- [ ] Do not start frontend work.

---

## Task 5: Local Trace Fallback

Files:

- Create: `backend/app/services/trace_service.py`
- Modify: `backend/app/services/scan_service.py`
- Test: `backend/tests/test_trace_service.py`

- [ ] Record scan start, OSV query, normalization, risk score, and scan complete.
- [ ] Redact unsafe details and secret-like values.
- [ ] Keep trace format simple enough to move into Postgres later.

---

## Verification Gate

Before each commit:

```bash
cd backend
PYTHONPATH=. python3 -m unittest discover tests
PYTHONPATH=. python3 -m app.eval.run_eval
```

When network is allowed:

```bash
cd backend
PYTHONPATH=. python3 -m app.cli scan ../demo-repos/payments-api --json
```

When Docker and deps are available:

```bash
docker compose up -d postgres
cd backend
alembic upgrade head
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Manager/Karen gate:

- verifier findings reviewed
- only MVP blockers fixed now
- matcha moved to backlog

---

## Acceptance For This Slice

- [x] Plan reflects coffee-first MVP.
- [x] Eval/verifier harness exists.
- [x] At least 10 deterministic cases exist.
- [x] Tests pass.
- [x] Eval runner prints metric JSON.
- [x] Karen auditor findings are reviewed.
- [ ] Commit is pushed.
