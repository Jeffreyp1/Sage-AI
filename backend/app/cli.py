"""Command line interface for VulnSage AI."""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

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

    parser.print_help()
    return 1


def write_json_output(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
