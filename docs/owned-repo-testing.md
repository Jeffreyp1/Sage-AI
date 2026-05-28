# Owned Repository Testing

Sage AI live/manual testing should use only repositories owned by the project
maintainer or repositories the maintainer is explicitly authorized to assess.

## Approved Local Test Targets

- Sage AI itself
- The maintainer's paper-trading application
- Synthetic demo repositories committed to this project, such as
  `demo-repos/payments-api`

Do not use random public repositories for live scan demos or quality checks
unless the maintainer explicitly approves that target.

## Network Use

Offline scans are preferred when validating parsing, report shape, MCP behavior,
and privacy guardrails. Online OSV scans may be used for owned repositories when
real vulnerability intelligence is needed. Online OSV lookup sends package name,
version, and ecosystem metadata to OSV; it should not send source code.

## Output Handling

Do not commit scan outputs from private or personal repositories unless they have
been reviewed and sanitized. Public demo artifacts should avoid absolute local
paths, secrets, private package names, raw advisory exploit details, and private
repository metadata.

## Current Known Gap

Sage AI currently parses Node `package.json` and `package-lock.json` well. It
does not yet produce useful dependency results for Sage AI's own Python backend
because `pyproject.toml` dependency parsing is not implemented yet.
