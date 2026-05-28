"""Command line interface for Sage AI."""

import argparse
import sys

from app.cli_commands import COMMAND_HANDLERS


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vulnsage")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a local repository.")
    scan_parser.add_argument("path", help="Path to a local repository.")
    scan_parser.add_argument("--json", action="store_true", help="Print structured JSON output.")
    scan_parser.add_argument(
        "--offline",
        action="store_true",
        help="Parse the repository without querying OSV.",
    )
    scan_parser.add_argument(
        "--output",
        help="Write structured JSON output to this file.",
    )
    scan_parser.add_argument(
        "--workspace-root",
        help="Restrict the scan path to this workspace root.",
    )
    summary_parser = subparsers.add_parser(
        "summarize-report",
        help="Generate a deterministic AI summary for one remediation task.",
    )
    summary_parser.add_argument("report_json", help="Path to a scan report JSON file.")
    summary_parser.add_argument(
        "--output",
        required=True,
        help="Write structured summary JSON output to this file.",
    )
    summary_parser.add_argument(
        "--task-id",
        help="Summarize the remediation task with this task_id. Defaults to the first task.",
    )
    context_parser = subparsers.add_parser(
        "ai-context-bundle",
        help="Write a focused client-AI context bundle for one remediation task.",
    )
    context_parser.add_argument("report_json", help="Path to a scan report JSON file.")
    context_parser.add_argument(
        "--output",
        required=True,
        help="Write structured AI context bundle JSON output to this file.",
    )
    context_parser.add_argument(
        "--task-id",
        help="Build context for this remediation task. Defaults to the first task.",
    )
    context_parser.add_argument(
        "--include-rag",
        action="store_true",
        help="Include retrieved report evidence chunks in the AI context bundle.",
    )
    context_parser.add_argument(
        "--top-k",
        type=int,
        default=5,
        help="Maximum number of retrieved evidence chunks to include.",
    )
    validate_ai_parser = subparsers.add_parser(
        "validate-ai-output",
        help="Validate a client AI JSON response against one remediation task.",
    )
    validate_ai_parser.add_argument("report_json", help="Path to a scan report JSON file.")
    validate_ai_parser.add_argument("ai_output_json", help="Path to a client AI output JSON file.")
    validate_ai_parser.add_argument(
        "--task-id",
        help="Validate against this remediation task. Defaults to the first task.",
    )
    validate_ai_parser.add_argument(
        "--json",
        action="store_true",
        help="Print structured validator output.",
    )
    validate_ai_parser.add_argument(
        "--include-rag",
        action="store_true",
        help="Validate against retrieved report evidence chunks too.",
    )
    validate_ai_parser.add_argument(
        "--top-k",
        type=int,
        default=5,
        help="Maximum number of retrieved evidence chunks to include.",
    )
    ai_demo_parser = subparsers.add_parser(
        "ai-demo",
        help="Run the no-key AI MVP demo and write all proof artifacts.",
    )
    ai_demo_parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory where demo artifacts should be written.",
    )
    ai_upgrade_demo_parser = subparsers.add_parser(
        "ai-upgrade-demo",
        help="Run the RAG-backed client-AI orchestration demo and write proof artifacts.",
    )
    ai_upgrade_demo_parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory where demo artifacts should be written.",
    )
    validate_parser = subparsers.add_parser(
        "validate-report",
        help="Validate a public scan report JSON file.",
    )
    validate_parser.add_argument("report_json", help="Path to a scan report JSON file.")
    validate_parser.add_argument(
        "--json",
        action="store_true",
        help="Print structured validator output.",
    )
    findings_parser = subparsers.add_parser(
        "findings",
        help="List compact findings from a scan report JSON file.",
    )
    findings_parser.add_argument("report_json", help="Path to a scan report JSON file.")
    findings_parser.add_argument(
        "--limit",
        type=int,
        help="Limit the number of findings printed.",
    )
    findings_parser.add_argument(
        "--priority",
        help="Only include findings with this priority.",
    )
    findings_parser.add_argument(
        "--json",
        action="store_true",
        help="Print structured JSON output.",
    )

    args = parser.parse_args(argv)
    handler = COMMAND_HANDLERS.get(args.command)
    if handler is None:
        parser.print_help()
        return 1
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
