# Simplified Files Watchlist

This file tracks files that were simplified during the AI-upgrades work. If any
file in this list is touched later, rerun the code-simplifier pass only on the
touched file or files, then run the focused tests listed below.

The goal is to preserve the simplification benefits without repeatedly
refactoring the whole codebase.

## Current Simplified Set

| File | Why It Is Watched | Focused Verification |
| --- | --- | --- |
| `backend/app/cli.py` | Split from a large command-and-implementation file into a thin parser/dispatcher. | `cd backend && .venv312/bin/python -m pytest tests/test_cli.py -q` |
| `backend/app/cli_commands.py` | Holds CLI command handlers separated from parser setup. | `cd backend && .venv312/bin/python -m pytest tests/test_cli.py -q` |
| `backend/app/cli_support.py` | Holds shared CLI JSON, schema, safety, and formatting helpers. | `cd backend && .venv312/bin/python -m pytest tests/test_cli.py -q` |
| `backend/app/cli_evidence.py` | Holds CLI evidence chunk helpers separated from command handling. | `cd backend && .venv312/bin/python -m pytest tests/test_cli.py -q` |
| `backend/app/cli_ai_demo.py` | Holds AI demo artifact generation separated from command handling. | `cd backend && .venv312/bin/python -m pytest tests/test_cli.py -q` |
| `backend/app/services/ai_context_bundle.py` | Client-AI bundle and validation logic was tightened and split around safety boundaries. | `cd backend && .venv312/bin/python -m pytest tests/test_ai_context_bundle.py -q` |
| `backend/app/services/ai_output_safety.py` | Extracted AI output safety scanning into a focused helper module. | `cd backend && .venv312/bin/python -m pytest tests/test_ai_context_bundle.py -q tests/test_ai_orchestration_eval.py -q` |
| `backend/tests/test_ai_context_bundle.py` | Expanded regression coverage for AI validation and safety behavior. | `cd backend && .venv312/bin/python -m pytest tests/test_ai_context_bundle.py -q` |
| `backend/tests/test_cli.py` | Updated to cover the split CLI helpers and public-output safety behavior. | `cd backend && .venv312/bin/python -m pytest tests/test_cli.py -q` |

## Rerun Rule

When a watched file changes:

1. Run code-simplifier only on the watched file or files that changed.
2. Preserve behavior, schemas, safety checks, and public output.
3. Run `git diff --check`.
4. Run the focused verification command from the table.
5. If the change touches shared CLI or AI validation behavior, also run:

```bash
cd backend
.venv312/bin/python -m ruff check app tests
.venv312/bin/python -m pytest
```
