# AI Agent Waves Design

## Purpose

This document defines the next waves for VulnSage AI after the backend MVP quality sprint.

It is written for future coding agents, verifier agents, and Karen reviewers. Use it as the reference for what each wave is trying to accomplish, which tasks can run in parallel, what must not be touched, and how completion should be judged.

The goal is to move from a deterministic vulnerability triage backend into an AI-assisted AppSec workflow without weakening the quality of the findings.

## Simple Mental Model

VulnSage is a security detective for code projects.

- The scanner finds clues.
- The database remembers clues.
- RAG helps AI find the right clues later.
- AI explains the clues in human language.
- LangGraph coordinates specialist AI workers.
- Karen reviewers verify the work is actually good.
- Humans approve risky actions.

## Current State

Already completed or mostly working:

- Local repository scanning.
- Node dependency parsing from `package.json` and `package-lock.json`.
- OSV vulnerability lookup.
- Vulnerability normalization and deduplication.
- Deterministic risk scoring.
- Basic reachability checks.
- Patch planning that avoids downgrades.
- Report validator.
- Eval harness with fixture cases.
- Open-source validation against OWASP NodeGoat replay data.
- Karen manager and final diff review workflow.

Important current constraint:

- Runtime AI is not part of the product yet. AI has been used for development and review, but the product itself is still mostly deterministic.

## Guiding Principle

Do not make AI the judge too early.

The product should follow this order:

```text
Scanner decides.
Validator judges.
Database remembers.
RAG finds evidence.
AI explains.
LangGraph coordinates.
Human approves.
```

This protects the "coffee": high-quality vulnerability findings.

## Parallel Work Rule

Work can run in parallel inside a wave when agents own separate files or separate modules.

Work should usually not skip ahead across waves unless it is an isolated prototype branch that does not change the scanner core or public report schema.

Safe parallel work:

- CI agent owns workflow files.
- Demo/report agent owns CLI/report export files.
- Persistence agent owns database models and persistence service.
- RAG agent owns chunking, embeddings, and retrieval services.
- AI summary agent owns AI explanation services and prompts.
- Karen agents own tests, audits, validators, and review reports.

Risky parallel work:

- Multiple agents editing `scan_service.py`.
- Multiple agents changing public report schema.
- RAG and persistence agents changing embedding table shape at the same time.
- AI agents changing deterministic risk scoring.
- Any agent bypassing report validation.

If a wave needs schema changes, one agent owns the schema and publishes the contract before dependent agents edit code.

## Shared Contracts

These contracts must remain stable unless the manager explicitly approves a change:

- Public scan report JSON.
- Remediation task shape.
- Evidence item shape.
- Patch plan shape.
- Risk priority names.
- Report validator expectations.
- Safety constraints.

Future agents must treat these as product APIs, not internal scratch data.

## Wave 1: Trust And Demo Foundation

### Goal

Make the current scanner easy to run, prove, and judge.

### Why This Comes First

Before VulnSage adds more AI, it needs a repeatable way to prove the existing report is good. This wave makes quality automatic.

If this wave is skipped, later AI work can produce nicer-looking output while hiding broken scanner behavior.

### Tasks

- Add GitHub Actions CI.
- Run backend unit tests in CI.
- Run eval harness in CI.
- Run report validator in CI.
- Add a repeatable demo scan command.
- Add JSON report export path.
- Add a NodeGoat/demo replay script that produces a stable report.
- Add more adversarial eval/report cases.

### Deliverables

- `.github/workflows/backend-ci.yml`.
- A command that writes a scan report to a JSON file.
- A reproducible demo report command.
- CI logs showing tests, evals, and report validation pass.
- Expanded eval/report validator cases.

### Parallel Agents

- CI agent: workflow files and command wiring.
- Demo/report agent: CLI report export and replay script.
- Karen evaluator: adversarial eval cases and report validator checks.

### Karen Gate

Karen must verify:

- Unit tests pass.
- Eval harness passes.
- Report validator passes.
- Demo command is reproducible.
- No unsafe security text is exposed.
- No duplicate findings pass validation.
- No non-review task lacks a patch target.

### Done Means

A new developer can run one command, produce a report, and trust that CI checks the same quality gates.

## Wave 2: Data And Ingestion Foundation

### Goal

Turn VulnSage from a smart scanner into a backend system that remembers scans and can ingest repos cleanly.

### Why This Comes Second

RAG, AI summaries, dashboards, and traces all need stored data. Without persistence, everything is temporary and hard to audit.

### Tasks

- Persist repositories.
- Persist scans.
- Persist packages.
- Persist vulnerabilities and aliases.
- Persist remediation tasks.
- Persist reachability evidence.
- Add scan history endpoints.
- Add GitHub URL ingestion by cloning or fetching an allowed repo.
- Add OSV caching and batching.
- Add database smoke tests where possible.

### Deliverables

- Working persistence path for scanner output.
- API endpoints for stored repos, scans, packages, and tasks.
- OSV cache service.
- GitHub URL ingestion path.
- Tests proving CLI and API use the same scanner output.

### Parallel Agents

- Persistence agent: models, migrations, persistence service.
- Ingestion agent: GitHub URL/local clone ingestion.
- OSV cache agent: batching and cache logic.
- Karen DB/API auditor: data correctness and schema safety.

### Karen Gate

Karen must verify:

- No duplicate DB records for the same package/advisory/task.
- Public API does not expose raw unsafe advisory details.
- Stored output matches scanner output.
- API and CLI do not fork into separate logic.
- Network failures fail clearly.

### Done Means

VulnSage can scan a repo, save the result, and retrieve scan history without losing evidence or changing priorities.

## Wave 3: Observability And AI Contracts

### Goal

Prepare for AI safely by defining what AI receives, what AI returns, and how every AI action is traced.

### Why This Comes Third

AI should not be added as a black box. Before real AI output ships, VulnSage needs logs, schemas, and safety boundaries.

### Tasks

- Add local trace service or trace table.
- Define AI provider interface.
- Define prompt input schemas.
- Define AI output schemas.
- Add mock AI provider for tests.
- Add trace redaction rules.
- Trace scan steps, future retrieval steps, and future AI calls.
- Store validation outcome with each AI output.

### Deliverables

- `trace_service`.
- AI request/response models.
- Mock provider.
- Tests for trace creation and redaction.
- Documentation for AI contracts.

### Parallel Agents

- Observability agent: trace service and persistence.
- AI contract agent: schemas and provider interface.
- Karen privacy/safety auditor: redaction and trace safety.

### Karen Gate

Karen must verify:

- Secrets are redacted.
- Unsafe advisory details are not logged into public traces.
- Unit tests do not require real AI calls.
- Every AI output has a validation status.
- Trace records explain what evidence was used.

### Done Means

The project can record what an AI would see and say, even before real AI is enabled.

## Wave 4: RAG Evidence Layer

### Goal

Give AI a trustworthy way to find evidence before it writes explanations.

### Why This Comes Fourth

RAG should retrieve real clues from stored repo files, advisories, and reports. This depends on persistence and AI-ready evidence contracts.

### Tasks

- Chunk repository source files.
- Chunk `package.json`, lockfiles, Dockerfiles, CI files, README files, and CODEOWNERS.
- Chunk vulnerability advisory summaries.
- Store chunks with metadata.
- Add embedding provider interface.
- Store embeddings in pgvector.
- Add vector retrieval with metadata filters.
- Add retrieval eval cases.

### Deliverables

- Chunking service.
- Embedding service interface.
- pgvector-backed storage.
- Retrieval service.
- Retrieval API or internal service call.
- Precision@K eval cases.

### Parallel Agents

- Chunking agent: chunk rules and metadata.
- Embeddings/pgvector agent: embedding storage and search.
- Retrieval eval agent: retrieval quality tests.
- Karen citation auditor: verifies citations point to real sources.

### Karen Gate

Karen must verify:

- Retrieved chunks include source metadata.
- Citations point to real files/advisories.
- Top retrieval results are relevant.
- Test fixtures measure bad retrieval, not only happy paths.
- RAG does not expose raw unsafe exploit content.

### Done Means

Given a remediation task, VulnSage can retrieve the most relevant evidence chunks from the repo and advisory data.

## Wave 5: AI Summaries And Citation Verification

### Goal

Add the first runtime AI feature: human-readable finding summaries backed by citations.

### Why This Comes Fifth

At this point, VulnSage has trustworthy scanner output, stored evidence, traces, and retrieval. AI can now explain instead of guessing.

### Tasks

- Generate finding summaries from structured report data and retrieved evidence.
- Generate "why this matters" explanations.
- Generate remediation explanation text.
- Generate test and rollback wording.
- Add citation verifier.
- Add unsupported-claim detector.
- Add AI-output eval cases.

### Deliverables

- AI summary service.
- Summary endpoint or CLI option.
- Citation verification result.
- Unsupported-claim score.
- Tests using mock AI output.
- Optional live AI smoke test behind environment flag.

### Parallel Agents

- AI summary agent: prompt templates and structured output.
- Citation verifier agent: claim-to-evidence checks.
- AI eval agent: quality cases and scoring.
- Karen adversarial reviewer: tries to make AI overclaim.

### Karen Gate

Karen must verify:

- AI cannot change risk score or priority.
- Every concrete claim has evidence.
- No exploit instructions are generated.
- Unknowns are labeled as unknown.
- Unsupported claims are blocked or flagged.
- Real AI calls are optional in tests.

### Done Means

VulnSage can produce a readable, cited explanation for a finding while the deterministic backend still controls the decision.

## Wave 6: LangGraph Agent Orchestration

### Goal

Turn individual AI helpers into a controlled multi-agent workflow.

### Why This Comes Sixth

LangGraph should orchestrate proven components. It should not be used to invent the foundation.

### Tasks

- Define LangGraph state model.
- Add repo profiler node.
- Add vulnerability triage explanation node.
- Add reachability explanation node.
- Add patch explanation node.
- Add citation verifier node.
- Add human approval node.
- Add retry/failure paths when validation fails.
- Trace each graph node.

### Deliverables

- LangGraph workflow.
- Structured node outputs.
- Agent prompts.
- Agent tests with mock model responses.
- Trace output per node.
- Human approval gate in workflow.

### Parallel Agents

- Graph workflow agent: state model and graph wiring.
- Agent prompt/schema agent: node schemas and prompt contracts.
- Human approval agent: approval state transitions.
- Karen orchestration reviewer: failure paths and safety gates.

### Karen Gate

Karen must verify:

- Failed citation verification blocks final output.
- Human approval is required for risky actions.
- No node auto-merges code, closes vulnerabilities, or accepts risk.
- Every node has structured input and output.
- Graph retries do not hide failures.

### Done Means

The AI workflow behaves like a controlled checklist instead of a single chatbot response.

## Wave 7: Product Workflow Polish

### Goal

Make VulnSage useful as an AppSec workflow, not only a report generator.

### Why This Comes Last

Workflow polish matters after findings, evidence, AI explanations, and approvals are trustworthy.

### Tasks

- Add remediation task status lifecycle.
- Add accepted-risk workflow.
- Add human approval records.
- Add PR/ticket draft generation without auto-submit.
- Add richer README and demo script.
- Add minimal dashboard only if backend workflow is stable.

### Deliverables

- Task lifecycle API.
- Approval API.
- Draft PR/ticket text.
- Demo script.
- Portfolio-ready README/docs.
- Optional minimal dashboard.

### Parallel Agents

- Workflow agent: task status and approvals.
- Draft generation agent: PR/ticket draft text.
- Docs/demo agent: README and demo flow.
- Karen product auditor: end-to-end review.

### Karen Gate

Karen must verify:

- No automatic risky actions.
- Human approval is recorded.
- Audit trail exists.
- Generated drafts are safe and evidence-backed.
- Demo commands match real behavior.

### Done Means

VulnSage can take a finding from scan to evidence-backed remediation workflow with human approval.

## Multi-Agent Implementation Pattern

Every wave follows the same loop:

```text
1. Manager confirms wave scope.
2. Orchestrator creates isolated worktrees.
3. Agents receive disjoint ownership.
4. Each agent writes failing tests first.
5. Each agent implements the smallest passing change.
6. Each agent runs targeted tests.
7. Karen audits each slice.
8. Fixer loops until Karen passes.
9. Manager verifies integration.
10. Final Karen reviews diff.
11. Orchestrator pushes only after all gates pass.
```

## TDD Requirements

Each implementation task should include:

- Failing test or explicit baseline proof.
- Focused implementation.
- Targeted tests.
- Full backend test suite when integrated.
- Eval/report validator when output quality changes.
- Clear commit message.

No agent should claim completion based only on manual inspection.

## Karen Army Responsibilities

Karen-the-auditor:

- Reads code and reports risks.
- Does not edit.
- Looks for missing tests, weak evidence, silent failures, unsafe output, and hidden complexity.

Karen-the-fixer:

- Fixes one verified problem at a time.
- Writes or updates tests first.
- Commits the fix.

Karen-the-manager:

- Checks whether the whole task is actually complete.
- Runs integration checks.
- Decides whether residual risks are acceptable.

Final Karen:

- Reviews final diff before push.
- Blocks if crash risk, safety risk, silent failure, or missing tests remain.

## Worktree Strategy

Use worktrees for parallel implementation:

```text
/private/tmp/vulnsage-worktrees/wave-N-ci
/private/tmp/vulnsage-worktrees/wave-N-demo
/private/tmp/vulnsage-worktrees/wave-N-rag
```

Each worktree should use a task-specific branch:

```text
codex/wave-N-ci
codex/wave-N-demo-report
codex/wave-N-rag-chunking
```

Merge only after:

- focused tests pass
- Karen slice review passes
- no overlapping files conflict with other active agents

## Things Not To Do Yet

Do not:

- Build a polished frontend before the backend workflow is trustworthy.
- Let AI decide priority.
- Let AI modify scanner output.
- Let AI mark risk accepted.
- Let AI auto-create PRs or tickets.
- Add LangGraph before the AI contracts and RAG evidence layer exist.
- Add RAG without retrieval evals.
- Change the report schema casually.

## Full Project Completion Markers

The full project is closer to complete when:

- A repo can be scanned from local path or GitHub URL.
- Findings are saved and retrievable.
- Reports are validated automatically.
- RAG retrieves evidence with measured quality.
- AI summaries are citation-backed.
- LangGraph orchestrates specialist agents.
- Human approval gates risky actions.
- Traces explain why the system said what it said.
- Demo script is reproducible.
- Karen gates run before every meaningful merge.

## Next Recommended Move

Start Wave 1.

Reason:

- It protects the current scanner.
- It gives future agents a stable quality gate.
- It makes every later wave easier to verify.
- It creates the fastest visible improvement without adding fragile AI behavior too early.

