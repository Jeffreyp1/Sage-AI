# Backend MVP Design

## Goal

Build Sage-AI into a backend-first dependency vulnerability triage MVP that can scan a repository, identify vulnerable dependencies, rank the issues by repo-specific risk, persist results, and produce a safe remediation report through CLI and API.

## Current State

Already implemented:

- Local repo scan path through `ScanService`.
- Node.js dependency parsing for `package.json` and `package-lock.json`.
- OSV client using the Python standard library.
- Vulnerability normalization, alias dedupe, fixed-version extraction, and public-safe serialization.
- Basic reachability from imports/routes plus CODEOWNERS owner inference.
- Deterministic risk scoring and remediation task output.
- CLI entrypoint and FastAPI route skeleton.
- SQLAlchemy models and Alembic initial migration.
- Demo repo at `demo-repos/payments-api`.
- Unit tests for parser, OSV client, normalization, risk scoring, and scan flow.

Known gaps:

- FastAPI dependencies are not installed in the local environment yet.
- Docker is not available in the current shell, so Postgres/pgvector has not been smoke-tested here.
- Persistence adapter exists but has not been verified against a live DB.
- Eval and trace packages exist only as placeholders.
- CLI output is useful for JSON, but human-readable reporting is still thin.

## Architecture

Sage-AI remains backend-first and UI-light for this milestone.

```text
CLI / FastAPI
  -> ScanService
  -> Repo profile + dependency parser
  -> OSV lookup
  -> Normalizer + deduper
  -> Reachability analyzer
  -> Risk scorer
  -> Patch-plan builder
  -> Persistence adapter
  -> JSON/report/API responses
```

The scanner is the core engine. FastAPI, CLI, future VS Code extension, and future GitHub integration should all call the same service layer instead of duplicating scan logic.

## Public Interfaces

CLI:

```bash
python -m app.cli scan ../demo-repos/payments-api
python -m app.cli scan ../demo-repos/payments-api --json
python -m app.cli scan ../demo-repos/payments-api --offline
```

API:

```http
GET /health
POST /repos/scan-local
GET /repos
GET /repos/{repo_id}
GET /repos/{repo_id}/scans
GET /repos/{repo_id}/packages
GET /repos/{repo_id}/remediation-tasks
GET /dashboard/summary
```

Near-term additions:

```bash
python -m app.eval.run_eval
```

```http
GET /remediation-tasks/{task_id}
GET /repos/{repo_id}/traces
```

## Data And Persistence

Postgres stores durable product state:

- repos and scans
- parsed packages
- canonical vulnerabilities and aliases
- package-vulnerability links
- reachability assessments
- remediation tasks
- eval cases and eval runs
- local LLM/tool traces

pgvector is reserved for RAG-ready evidence search. It will store embeddings later for advisory text, repo files, changelogs, and prior remediation decisions. It is not required for the first scanner path, but the schema is included so the MVP can grow into RAG without a database rewrite.

## Safety Rules

Public scan output must not expose raw advisory bodies, exploit payloads, or PoC links. It may expose:

- advisory IDs and aliases
- severity
- package/version
- fixed versions
- non-offensive references
- repo evidence
- deterministic risk rationale
- safe patch/test/rollback plan

The system must not:

- generate exploit payloads
- provide offensive exploitation steps
- auto-merge code
- auto-close vulnerabilities
- accept risk without human approval
- mark release block/unblock as final without human review

## MVP Completion Definition

MVP is complete when:

- Demo repo can be scanned from CLI and API.
- Live OSV scan returns prioritized remediation tasks.
- Results persist in Postgres.
- Read endpoints return persisted repos, packages, scans, and remediation tasks.
- Public outputs are safe and structured.
- At least one task includes repo evidence and owner inference.
- At least one task includes a patch/test/rollback plan.
- Eval runner reports metrics from at least 10 fixture cases.
- Local trace fallback records scan/tool/risk events.
- README explains setup and demo flow.

## Quality Process

Every meaningful implementation slice follows:

1. Write failing test.
2. Run test and verify expected failure.
3. Implement smallest code change.
4. Run targeted test.
5. Run full unit suite.
6. Run live smoke test when network/DB behavior changes.
7. Run Karen-style audit for safety, correctness, and missing tests.
8. Fix audit findings.
9. Commit explicitly named files.

## Immediate Priority

Next slice: FastAPI + Postgres persistence verification.

Reason:

- Core scanner already works.
- MVP needs durable state to be more than a script.
- Persistence unlocks dashboard, evals, traces, historical trends, and GitHub/IDE integrations.

