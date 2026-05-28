# Acceptable Use Policy

Sage AI is intended only for defensive repository security work.

## Allowed Uses

You may use Sage AI to:

- Analyze repositories you own or are authorized to assess
- Parse dependency manifests and lockfiles
- Query public vulnerability intelligence for dependency risk context
- Generate evidence-backed vulnerability triage reports
- Build AI context bundles for local AI coding clients
- Validate AI-generated remediation explanations against cited evidence
- Draft safe remediation plans, test plans, and rollback notes

## Prohibited Uses

You may not use Sage AI to:

- Generate exploit payloads, malware, credential theft flows, or offensive
  instructions
- Scan, attack, probe, or enumerate third-party systems without permission
- Bypass authentication, authorization, rate limits, or access controls
- Exfiltrate secrets, private source code, private repository metadata, or user
  data
- Auto-merge code, auto-close vulnerabilities, accept risk, or block/unblock a
  release without human approval
- Present AI-generated findings as verified facts unless they are backed by
  Sage AI evidence or trusted sources
- Use the project in a way that violates applicable law, contracts, platform
  rules, or repository owner policies

## User Responsibility

You are responsible for how you run the tool, which repositories you analyze,
which AI clients you connect, and which data you allow those clients to access.
Sage AI is local-first by design, but a connected AI client may have its own
privacy and data-handling behavior.

## Defensive-Only Design

Sage AI intentionally exposes tools for repository analysis, finding evidence,
building context, and validating reports. It does not expose tools for exploiting
targets, attacking services, generating payloads, or scanning arbitrary networks.
