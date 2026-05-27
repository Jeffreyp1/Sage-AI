"""File-backed report storage for SDK-free MCP tool handlers."""

from __future__ import annotations

import json
import re
from pathlib import Path

from pydantic import ValidationError

from app.schemas.report import ScanReport
from app.services.path_policy import PathPolicyError, ensure_inside_workspace
from app.services.public_safety import safe_display_name


SCAN_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")


class ReportStoreError(ValueError):
    """Raised when a stored scan report cannot be safely read or written."""


class FileReportStore:
    """Persist public scan reports under one configured directory."""

    def __init__(self, storage_dir: str | Path, *, allowed_root: Path | None = None) -> None:
        root = Path(storage_dir)
        try:
            if allowed_root is not None:
                ensure_inside_workspace(root.resolve(strict=False), allowed_root)
            root.mkdir(parents=True, exist_ok=True)
            self.root = root.resolve(strict=True)
        except PathPolicyError as error:
            raise ReportStoreError(str(error)) from error
        except OSError as error:
            raise ReportStoreError("Unable to initialize report store") from error

        if not self.root.is_dir():
            raise ReportStoreError("Unable to initialize report store: path is not a directory")

        if allowed_root is not None:
            try:
                ensure_inside_workspace(self.root, allowed_root)
            except PathPolicyError as error:
                raise ReportStoreError(str(error)) from error

    def save(self, report: ScanReport) -> Path:
        path = self.path_for_scan_id(report.scan_id)
        payload = report.model_dump(mode="json")
        try:
            if path.is_symlink():
                raise OSError("refusing to write through report symlink")
            path.write_text(
                json.dumps(payload, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        except OSError as error:
            raise ReportStoreError("Unable to write scan report") from error
        return path

    def load(self, scan_id: str) -> ScanReport:
        path = self.path_for_scan_id(scan_id)
        try:
            path = path.resolve(strict=True)
        except FileNotFoundError as error:
            raise ReportStoreError("Scan report not found") from error

        try:
            path.relative_to(self.root)
        except ValueError as error:
            raise ReportStoreError("Report path is outside the report store") from error

        if not path.is_file():
            raise ReportStoreError("Scan report path is not a file")
        return self.load_resolved_path(path)

    def load_path(self, report_path: str | Path) -> ScanReport:
        path = self.resolve_report_path(report_path)
        return self.load_resolved_path(path)

    def load_resolved_path(self, path: Path) -> ScanReport:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise ReportStoreError(
                "Scan report is not valid JSON: %s" % public_report_name(path)
            ) from error
        except UnicodeDecodeError as error:
            raise ReportStoreError(
                "Scan report is not valid JSON: %s" % public_report_name(path)
            ) from error
        except OSError as error:
            raise ReportStoreError("Unable to read scan report") from error

        try:
            return ScanReport.model_validate(payload)
        except ValidationError as error:
            raise ReportStoreError(
                "Stored scan report is invalid: %s" % public_report_name(path)
            ) from error

    def load_json_object(self, report_path: str | Path) -> object:
        path = self.resolve_report_path(report_path)
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise ReportStoreError(
                "Scan report is not valid JSON: %s" % public_report_name(path)
            ) from error
        except UnicodeDecodeError as error:
            raise ReportStoreError(
                "Scan report is not valid JSON: %s" % public_report_name(path)
            ) from error
        except OSError as error:
            raise ReportStoreError("Unable to read scan report") from error

    def path_for_scan_id(self, scan_id: str) -> Path:
        safe_scan_id = safe_report_stem(scan_id)
        return self.root / ("%s.json" % safe_scan_id)

    def resolve_report_path(self, report_path: str | Path) -> Path:
        raw_path = Path(report_path)
        if raw_path.is_absolute():
            raise ReportStoreError("Report path must be store-relative")
        candidate = self.root / raw_path
        try:
            path = candidate.resolve(strict=True)
        except FileNotFoundError as error:
            raise ReportStoreError("Scan report not found") from error

        try:
            path.relative_to(self.root)
        except ValueError as error:
            raise ReportStoreError("Report path is outside the report store") from error

        if not path.is_file():
            raise ReportStoreError("Scan report path is not a file")
        return path


def safe_report_stem(scan_id: str) -> str:
    if not SCAN_ID_PATTERN.fullmatch(scan_id):
        raise ReportStoreError("Scan id is not safe for local report storage")
    if scan_id in {".", ".."} or scan_id.startswith(".") or scan_id.endswith("."):
        raise ReportStoreError("Scan id is not safe for local report storage")
    if ".." in scan_id:
        raise ReportStoreError("Scan id is not safe for local report storage")
    return scan_id


def public_report_name(path: Path) -> str:
    return safe_display_name(path.name, fallback="report file")
