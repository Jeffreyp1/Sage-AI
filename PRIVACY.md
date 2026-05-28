# Privacy

Sage AI is designed as a local-first repository analysis tool.

## Local-First Behavior

By default, Sage AI analyzes repository files on the machine where it runs and
stores local reports under the configured workspace or storage directory.

## Data Sage AI May Read

When pointed at a repository, Sage AI may read:

- Dependency manifests and lockfiles
- Source files used for reachability evidence
- README and documentation files
- Dockerfiles, CI files, and ownership metadata
- Previously generated local scan reports

## Network Access

Sage AI may query public vulnerability services such as OSV when online scanning
is enabled. Offline demo flows do not require public network access.

## AI Client Data Handling

Sage AI can produce focused context bundles for AI clients such as Claude Code,
Cursor, or Codex. Those clients are separate products with their own privacy,
logging, retention, and data-handling behavior. Review your AI client's settings
before sending repository context to it.

## Sensitive Data

Sage AI includes guardrails intended to reduce accidental disclosure of local
paths, secrets, private metadata, and unsafe report content. These guardrails are
not a guarantee. Do not run Sage AI on repositories containing secrets or private
data unless you understand and accept the risk.

## Public Display

If this repository is made public for portfolio review, viewers should treat it
as source-available demonstration software unless and until it is separately
published as an official package or MCP registry entry.
