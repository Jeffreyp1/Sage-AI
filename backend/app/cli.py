"""Command line interface for VulnSage AI."""

import argparse
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Optional

from app.ai.contracts import MockAIProvider
from app.services.ai_summary_service import AISummaryService
from app.services.rag_types import EvidenceChunk
from app.services.scan_service import ScanService


class OfflineOsvClient:
    def query(self, package_name: str, version: Optional[str], ecosystem: str):
        return []


def main(argv: Optional[list] = None) -> int:
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

    args = parser.parse_args(argv)
    if args.command == "scan":
        client = OfflineOsvClient() if args.offline else None
        result = ScanService(osv_client=client).scan_local(args.path)
        if args.output:
            output_path = Path(args.output)
            try:
                write_json_output(output_path, result.to_dict())
            except OSError as error:
                print(
                    "Error: unable to write output file: %s: %s"
                    % (output_path, error.strerror or error),
                    file=sys.stderr,
                )
                return 1
            return 0
        if args.json:
            print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        else:
            print("Scan complete: %s" % result.repo_profile.repo_name)
            print("Packages: %s" % result.summary["packages"])
            print("Raw alerts: %s" % result.summary["raw_alerts"])
            print("Deduped remediation tasks: %s" % result.summary["deduped_remediation_tasks"])
            print("Release blockers: %s" % result.summary["release_blockers"])
            if result.errors:
                print("Errors:")
                for error in result.errors:
                    print("- %s" % error)
        return 0
    if args.command == "summarize-report":
        try:
            report = read_report_json(Path(args.report_json))
            task = select_remediation_task(report, args.task_id)
            chunks = evidence_chunks_from_task(task)
            result = AISummaryService(provider=MockAIProvider()).summarize_remediation_task(
                task,
                chunks,
            )
            write_json_output(Path(args.output), result.to_dict())
        except CliError as error:
            print("Error: %s" % error, file=sys.stderr)
            return 1
        except OSError as error:
            print(
                "Error: unable to write output file: %s: %s"
                % (Path(args.output), error.strerror or error),
                file=sys.stderr,
            )
            return 1
        except ValueError as error:
            print("Error: unable to summarize report: %s" % error, file=sys.stderr)
            return 1
        return 0

    parser.print_help()
    return 1


class CliError(RuntimeError):
    pass


def read_report_json(path: Path) -> dict[str, object]:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError as error:
        raise CliError("report file not found: %s" % path) from error
    except OSError as error:
        raise CliError(
            "unable to read report file: %s: %s" % (path, error.strerror or error)
        ) from error

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as error:
        raise CliError(
            "report file is not valid JSON: %s:%s: %s"
            % (path, error.lineno, error.msg)
        ) from error

    if not isinstance(data, dict):
        raise CliError("report JSON must be an object")
    return data


def select_remediation_task(
    report: Mapping[str, object],
    task_id: str | None,
) -> Mapping[str, object]:
    tasks = report.get("remediation_tasks")
    if not isinstance(tasks, list) or len(tasks) == 0:
        raise CliError("report contains no remediation tasks")

    if task_id is None:
        first_task = tasks[0]
        if not isinstance(first_task, Mapping):
            raise CliError("first remediation task must be an object")
        return first_task

    for task in tasks:
        if not isinstance(task, Mapping):
            continue
        if task.get("task_id") == task_id:
            return task
    raise CliError("remediation task not found: %s" % task_id)


def evidence_chunks_from_task(task: Mapping[str, object]) -> list[EvidenceChunk]:
    chunks: list[EvidenceChunk] = []
    package_name = string_from_mapping(task.get("package"), "name")
    repo_id = string_value(task.get("repo_id")) or string_value(task.get("repo"))

    vulnerability = mapping_value(task.get("vulnerability"))
    advisory_text = advisory_content(vulnerability)
    if advisory_text is not None:
        chunks.append(
            EvidenceChunk(
                chunk_id="cli-advisory",
                source_type="advisory",
                content=advisory_text,
                metadata=chunk_metadata(
                    repo_id=repo_id,
                    package_name=package_name,
                    source="vulnerability",
                ),
            )
        )

    risk_text = risk_content(mapping_value(task.get("risk")))
    if risk_text is not None:
        chunks.append(
            EvidenceChunk(
                chunk_id="cli-risk",
                source_type="risk",
                content=risk_text,
                metadata=chunk_metadata(
                    repo_id=repo_id,
                    package_name=package_name,
                    source="risk",
                ),
            )
        )

    evidence = task.get("evidence")
    if isinstance(evidence, list):
        for index, item in enumerate(evidence):
            if not isinstance(item, Mapping):
                continue
            claim = string_value(item.get("claim"))
            if claim is None or claim.strip() == "":
                continue
            chunks.append(
                EvidenceChunk(
                    chunk_id="cli-evidence-%s" % (index + 1),
                    source_type=string_value(item.get("type")) or "task_evidence",
                    content=claim,
                    metadata=chunk_metadata(
                        repo_id=repo_id,
                        package_name=package_name,
                        source=string_value(item.get("source")) or "remediation_task",
                    ),
                )
            )
    return chunks


def advisory_content(vulnerability: Mapping[str, object]) -> str | None:
    fields = [
        ("Vulnerability", vulnerability.get("canonical_id") or vulnerability.get("source_id")),
        ("Severity", vulnerability.get("severity")),
        ("Summary", vulnerability.get("summary")),
        ("Fixed versions", vulnerability.get("fixed_versions")),
    ]
    return content_from_fields(fields)


def risk_content(risk: Mapping[str, object]) -> str | None:
    fields = [
        ("Priority", risk.get("priority")),
        ("Risk score", risk.get("risk_score")),
        ("Reachability", risk.get("reachability")),
        ("Runtime scope", risk.get("runtime_scope")),
        ("Confidence", risk.get("confidence")),
        ("Rationale", risk.get("rationale")),
    ]
    return content_from_fields(fields)


def content_from_fields(fields: list[tuple[str, object]]) -> str | None:
    lines: list[str] = []
    for label, value in fields:
        text = field_text(value)
        if text is None:
            continue
        lines.append("%s: %s" % (label, text))
    if len(lines) == 0:
        return None
    return "\n".join(lines)


def field_text(value: object) -> str | None:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped if stripped != "" else None
    if isinstance(value, int | float) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, list):
        items: list[str] = []
        for item in value:
            text = field_text(item)
            if text is not None:
                items.append(text)
        if len(items) == 0:
            return None
        return ", ".join(items)
    return None


def chunk_metadata(
    repo_id: str | None,
    package_name: str | None,
    source: str,
) -> dict[str, object]:
    metadata: dict[str, object] = {"source": source}
    if repo_id is not None:
        metadata["repo_id"] = repo_id
    if package_name is not None:
        metadata["package"] = package_name
    return metadata


def mapping_value(value: object) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return value
    return {}


def string_from_mapping(value: object, key: str) -> str | None:
    return string_value(mapping_value(value).get(key))


def string_value(value: object) -> str | None:
    if isinstance(value, str) and value.strip() != "":
        return value
    return None


def write_json_output(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
