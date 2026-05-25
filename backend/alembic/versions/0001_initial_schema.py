"""Initial VulnSage AI schema.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-05-24
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def timestamps() -> list:
    return [
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
    ]


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("email", sa.String(length=255), nullable=False, unique=True),
        sa.Column("name", sa.String(length=255), nullable=True),
        *timestamps(),
    )
    op.create_table(
        "organizations",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False, unique=True),
        *timestamps(),
    )
    op.create_table(
        "repos",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("org_id", sa.String(length=36), sa.ForeignKey("organizations.id"), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=512), nullable=False),
        sa.Column("provider", sa.String(length=50), nullable=False, server_default="local"),
        sa.Column("remote_url", sa.Text(), nullable=True),
        sa.Column("default_branch", sa.String(length=255), nullable=True),
        sa.Column("language", sa.String(length=255), nullable=True),
        sa.Column("service_type", sa.String(length=255), nullable=True),
        *timestamps(),
    )
    op.create_table(
        "scans",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("repo_id", sa.String(length=36), sa.ForeignKey("repos.id"), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("commit_sha", sa.String(length=64), nullable=True),
        sa.Column("summary_json", sa.JSON(), nullable=False),
        *timestamps(),
    )
    op.create_table(
        "packages",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("repo_id", sa.String(length=36), sa.ForeignKey("repos.id"), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("ecosystem", sa.String(length=50), nullable=False),
        sa.Column("current_version", sa.String(length=255), nullable=True),
        sa.Column("dependency_type", sa.String(length=50), nullable=False),
        sa.Column("is_direct", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("parent_package", sa.String(length=255), nullable=True),
        sa.Column("manifest_path", sa.Text(), nullable=True),
        sa.Column("lockfile_path", sa.Text(), nullable=True),
        *timestamps(),
    )
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("canonical_id", sa.String(length=255), nullable=False, unique=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("details", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=50), nullable=False, server_default="UNKNOWN"),
        sa.Column("published_at", sa.DateTime(), nullable=True),
        sa.Column("modified_at", sa.DateTime(), nullable=True),
        sa.Column("source", sa.String(length=50), nullable=False, server_default="OSV"),
        sa.Column("raw_json", sa.JSON(), nullable=False),
        *timestamps(),
    )
    op.create_table(
        "vulnerability_aliases",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "vulnerability_id",
            sa.String(length=36),
            sa.ForeignKey("vulnerabilities.id"),
            nullable=False,
        ),
        sa.Column("alias", sa.String(length=255), nullable=False),
        sa.Column("alias_type", sa.String(length=50), nullable=False),
        *timestamps(),
    )
    op.create_table(
        "advisory_references",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "vulnerability_id",
            sa.String(length=36),
            sa.ForeignKey("vulnerabilities.id"),
            nullable=False,
        ),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("reference_type", sa.String(length=100), nullable=True),
        *timestamps(),
    )
    op.create_table(
        "repo_files",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("repo_id", sa.String(length=36), sa.ForeignKey("repos.id"), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("file_type", sa.String(length=100), nullable=False),
        sa.Column("content_hash", sa.String(length=128), nullable=False),
        sa.Column("content_text", sa.Text(), nullable=True),
        *timestamps(),
    )
    op.create_table(
        "package_vulnerabilities",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("package_id", sa.String(length=36), sa.ForeignKey("packages.id"), nullable=False),
        sa.Column(
            "vulnerability_id",
            sa.String(length=36),
            sa.ForeignKey("vulnerabilities.id"),
            nullable=False,
        ),
        sa.Column("affected_version", sa.String(length=255), nullable=True),
        sa.Column("fixed_versions_json", sa.JSON(), nullable=False),
        sa.Column("is_affected", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        *timestamps(),
    )
    op.create_table(
        "embeddings",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("repo_id", sa.String(length=36), sa.ForeignKey("repos.id"), nullable=True),
        sa.Column("source_type", sa.String(length=100), nullable=False),
        sa.Column("source_id", sa.String(length=36), nullable=True),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("embedding", sa.Text(), nullable=True),
        *timestamps(),
    )
    op.execute("ALTER TABLE embeddings ALTER COLUMN embedding TYPE vector(1536) USING NULL::vector(1536)")
    op.create_table(
        "reachability_assessments",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "package_vulnerability_id",
            sa.String(length=36),
            sa.ForeignKey("package_vulnerabilities.id"),
            nullable=False,
        ),
        sa.Column("reachability", sa.String(length=50), nullable=False),
        sa.Column("runtime_scope", sa.String(length=50), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("evidence_json", sa.JSON(), nullable=False),
        *timestamps(),
    )
    op.create_table(
        "remediation_tasks",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("repo_id", sa.String(length=36), sa.ForeignKey("repos.id"), nullable=False),
        sa.Column(
            "package_vulnerability_id",
            sa.String(length=36),
            sa.ForeignKey("package_vulnerabilities.id"),
            nullable=False,
        ),
        sa.Column("priority", sa.String(length=50), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="open"),
        sa.Column("owner", sa.String(length=255), nullable=True),
        sa.Column("recommended_action", sa.String(length=100), nullable=False),
        sa.Column("patch_plan_json", sa.JSON(), nullable=False),
        sa.Column("test_plan_json", sa.JSON(), nullable=False),
        sa.Column("rollback_plan_json", sa.JSON(), nullable=False),
        sa.Column("citations_json", sa.JSON(), nullable=False),
        *timestamps(),
    )
    op.create_table(
        "human_approvals",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "remediation_task_id",
            sa.String(length=36),
            sa.ForeignKey("remediation_tasks.id"),
            nullable=False,
        ),
        sa.Column("action_type", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("requested_by", sa.String(length=255), nullable=True),
        sa.Column("approved_by", sa.String(length=255), nullable=True),
        sa.Column("decision_reason", sa.Text(), nullable=True),
        *timestamps(),
    )
    op.create_table(
        "eval_cases",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("case_type", sa.String(length=100), nullable=False),
        sa.Column("input_json", sa.JSON(), nullable=False),
        sa.Column("expected_json", sa.JSON(), nullable=False),
        *timestamps(),
    )
    op.create_table(
        "eval_runs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("case_id", sa.String(length=36), sa.ForeignKey("eval_cases.id"), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("actual_json", sa.JSON(), nullable=False),
        sa.Column("score_json", sa.JSON(), nullable=False),
        *timestamps(),
    )
    op.create_table(
        "llm_traces",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("trace_id", sa.String(length=255), nullable=False),
        sa.Column("agent_name", sa.String(length=255), nullable=False),
        sa.Column("input_json", sa.JSON(), nullable=False),
        sa.Column("retrieved_context_json", sa.JSON(), nullable=False),
        sa.Column("output_json", sa.JSON(), nullable=False),
        sa.Column("model", sa.String(length=255), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("token_count", sa.Integer(), nullable=True),
        sa.Column("cost_usd", sa.Float(), nullable=True),
        *timestamps(),
    )

    op.create_index("ix_packages_repo_name", "packages", ["repo_id", "name"])
    op.create_index("ix_aliases_alias", "vulnerability_aliases", ["alias"])
    op.create_index("ix_tasks_repo_priority", "remediation_tasks", ["repo_id", "priority"])


def downgrade() -> None:
    op.drop_index("ix_tasks_repo_priority", table_name="remediation_tasks")
    op.drop_index("ix_aliases_alias", table_name="vulnerability_aliases")
    op.drop_index("ix_packages_repo_name", table_name="packages")
    for table in [
        "llm_traces",
        "eval_runs",
        "eval_cases",
        "human_approvals",
        "remediation_tasks",
        "reachability_assessments",
        "embeddings",
        "package_vulnerabilities",
        "repo_files",
        "advisory_references",
        "vulnerability_aliases",
        "vulnerabilities",
        "packages",
        "scans",
        "repos",
        "organizations",
        "users",
    ]:
        op.drop_table(table)
