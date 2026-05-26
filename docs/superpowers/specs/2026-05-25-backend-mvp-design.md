# Coffee-First Backend MVP Design

## Goal

Build Sage-AI into a backend-first dependency vulnerability triage MVP that can scan a repository, identify vulnerable dependencies, rank the issues by repo-specific risk, and produce a safe, evidence-backed remediation report.

For this milestone, the product's "coffee" is not UI, PR automation, or a full agent system. The coffee is:

- finding vulnerable dependencies in a real repo
- explaining which findings matter most
- proving the priority with repo evidence
- avoiding unsafe or unsupported claims
- measuring report quality with deterministic evals

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
- CLI output is useful for JSON, but report quality is not yet scored.

## Architecture

Sage-AI remains backend-first and UI-light for this milestone.

```text
CLI / FastAPI / future IDE extension
  -> ScanService
  -> Repo profile + dependency parser
  -> OSV lookup
  -> Normalizer + deduper
  -> Reachability analyzer
  -> Risk scorer
  -> Patch-plan builder
  -> Safe JSON report
  -> Eval + verifier harness
  -> Persistence adapter later in the MVP
```

The scanner is the core engine. FastAPI, CLI, future VS Code extension, and future GitHub integration should all call the same service layer instead of duplicating scan logic.

## Coffee vs Matcha

Coffee for this MVP:

- deterministic dependency parsing
- OSV advisory matching
- alias dedupe without over-merging
- repo-specific reachability signals
- risk scoring that can rank a high production issue above a critical dev-only issue
- safe public output
- eval/verifier harness with adversarial checks
- CLI demo path

Good coffee machine:

- focused tests
- fixture-based eval cases
- verifier findings with severities
- Karen-style final gate
- clear docs for future agents

Matcha for later:

- frontend dashboard
- GitHub App install flow
- automated PR creation
- Jira/Slack integrations
- full LangGraph agent workflow
- full RAG with pgvector
- executive reporting

These are useful, but they do not matter until the scanner can produce trustworthy findings.

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

Postgres and pgvector stay in the architecture, but they are not the next quality bottleneck. pgvector is reserved for RAG-ready evidence search later. The immediate MVP can prove quality through deterministic reports and evals before persistence is fully smoke-tested.

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

- Demo repo can be scanned from CLI.
- Live OSV or deterministic fixture scan returns prioritized remediation tasks.
- Public outputs are safe and structured.
- At least one task includes repo evidence and owner inference.
- At least one task includes a patch/test/rollback plan.
- Eval runner reports metrics from at least 10 fixture cases.
- Verifier flags false positives, false negatives, weak evidence, unsafe output, and priority mismatches.
- Full unit suite passes.
- API and DB persistence are working or clearly documented as the next milestone if local tooling blocks verification.
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

## Developer / Verifier / Manager Loop

Developer:

- implements scanner, evals, fixes, docs
- keeps scope narrow
- does not add UI/RAG/PR automation early

Verifier:

- attacks report quality
- looks for false positives and false negatives
- checks missing evidence and unsupported claims
- rejects unsafe security output
- reports findings with severity and file references

Manager:

- used only at gates
- decides which verifier findings block MVP
- prevents scope creep

## Immediate Priority

Next slice: deterministic eval and verifier harness.

Reason:

- Core scanner already works.
- The user wants the best possible findings before UI or automation.
- Eval/verifier work directly improves trust in the output.
- DB/API polish is valuable after the report quality bar exists.
