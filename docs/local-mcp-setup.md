# Local MCP Setup

This guide shows how to run Sage AI as a local MCP server so Claude Desktop,
Claude Code, Cursor, or Codex can call Sage tools from your existing AI client.

Sage AI does not provide the model in this mode. Your AI client provides the
model, and Sage AI provides local security-analysis tools.

## When To Use This

Use local MCP when you want to:

- Ask an AI client to scan a local repo with Sage AI.
- Let the AI inspect Sage findings without pasting JSON manually.
- Validate the AI explanation with Sage AI's claim auditor before showing a
  final report.

Use the CLI when you only need a normal terminal scan.

## Install Locally

From this repo:

```bash
cd /Users/korilogic/Documents/VulnSageAI/backend
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

Confirm the MCP command exists:

```bash
/Users/korilogic/Documents/VulnSageAI/backend/.venv/bin/vulnsage-mcp --help
```

## Claude Desktop

Claude Desktop reads local MCP servers from its config JSON. Add `mcpServers`
as a top-level key, next to `preferences`.

Example:

```json
{
  "preferences": {
    "sidebarMode": "chat"
  },
  "mcpServers": {
    "sage-ai": {
      "command": "/Users/korilogic/Documents/VulnSageAI/backend/.venv/bin/vulnsage-mcp",
      "args": [
        "--workspace-root",
        "/Users/korilogic/Documents/trading/paper-trading"
      ]
    }
  }
}
```

Fully quit and reopen Claude Desktop after editing the config.

## Choosing The Workspace Root

`--workspace-root` is the folder Sage AI is allowed to scan.

For one repo:

```json
"args": ["--workspace-root", "/Users/korilogic/Documents/trading/paper-trading"]
```

For several local repos under one parent folder:

```json
"args": ["--workspace-root", "/Users/korilogic/Documents"]
```

If you use a broad workspace root, ask Sage AI to scan the specific repo path.

## Demo Prompt

Use this prompt in Claude Desktop:

```text
Use the sage-ai MCP tools to scan my paper trading app at:

/Users/korilogic/Documents/trading/paper-trading

Run the scan with OSV vulnerability lookup enabled. Then show me:

1. Total findings by priority/severity
2. The top 5 findings
3. Why each finding matters in this repo
4. Evidence Sage AI found for the top issue
5. A conservative remediation suggestion
6. Run Sage AI's validator on your explanation before showing the final report

If Sage AI's validator blocks any claim, clearly say:
"Sage AI's claim auditor blocked this claim because it was not supported by the evidence."
```

## Tool Behavior

The most common MCP tools are:

- `scan_current_repo`: scans the configured `--workspace-root`.
- `scan_repo`: scans a specific repo path under `--workspace-root`.
- `list_findings`: lists findings from the latest scan report.
- `get_finding_evidence`: returns evidence for a finding.
- `get_ai_context_bundle`: creates focused context for the AI client.
- `validate_ai_output`: checks whether the AI explanation is supported.

`scan_current_repo` uses OSV lookup by default. Set `offline: true` only when
you want a local-only scan with no external vulnerability lookup.

## Troubleshooting

If Claude says no repo is present, the configured `--workspace-root` likely
points at the wrong folder. Point it directly at the repo, or use `scan_repo`
with an absolute path under the configured workspace root.

If OSV lookup does not run, make sure the scan is not using `offline: true`.

If validation fails, that usually means the AI explanation made a claim Sage AI
could not verify from the evidence bundle. The scan can still be valid while the
AI explanation is blocked.

## Privacy Notes

Local MCP keeps Sage AI running on your machine. OSV lookup sends dependency
package names and versions to OSV unless the scan is run with `offline: true`.
Your AI client may still see the context it requests through MCP, so only point
the workspace root at repos you are comfortable analyzing with that client.
