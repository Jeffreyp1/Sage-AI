# Security Policy

Sage AI is defensive security tooling for analyzing repositories that a user
owns or is authorized to assess.

## Supported Versions

This project is in an early portfolio/MVP stage. Security reports are accepted
for the current default development branch and the current public submission
branch.

## Reporting a Vulnerability

Please report suspected security issues privately through GitHub's private
vulnerability reporting feature if it is enabled on the repository. If that is
not available, open a minimal GitHub issue that says you have a security report
to share, without posting exploit steps, secrets, private repository data, or
working payloads.

Reports should include:

- A short description of the issue
- The affected command, API route, MCP tool, or file
- The expected safe behavior
- The observed unsafe behavior
- Minimal reproduction steps that do not include exploit payloads or private
  data

## Scope

In scope:

- Accidental disclosure of local paths, secrets, repository content, or private
  metadata
- MCP tools reading outside the configured workspace
- Unsafe report generation, unsafe AI output validation, or unsupported security
  claims
- Dependency, packaging, or configuration issues that affect local defensive use

Out of scope:

- Requests to generate exploit payloads or offensive instructions
- Reports requiring unauthorized access to third-party systems
- Vulnerabilities in repositories that the reporter does not own or have
  permission to test
- Social engineering, denial-of-service against public services, or spam

## Safe Harbor

Good-faith research that follows this policy, avoids privacy violations, and
does not disrupt systems is welcome. Do not access, modify, delete, or exfiltrate
data that is not yours.

## Response Expectations

This is a portfolio project, not a commercial security service. Reports will be
reviewed on a best-effort basis.
