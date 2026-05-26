"""Add persistence identity constraints.

Revision ID: 0002_add_persistence_identity_constraints
Revises: 0001_initial_schema
Create Date: 2026-05-26
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0002_add_persistence_identity_constraints"
down_revision: Union[str, None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_repos_provider_full_name",
        "repos",
        ["provider", "full_name"],
    )
    op.create_unique_constraint(
        "uq_vulnerability_aliases_identity",
        "vulnerability_aliases",
        ["vulnerability_id", "alias"],
    )
    op.create_unique_constraint(
        "uq_advisory_references_identity",
        "advisory_references",
        ["vulnerability_id", "url"],
    )
    op.create_index(
        "uq_packages_identity",
        "packages",
        [
            "repo_id",
            "name",
            "ecosystem",
            sa.text("coalesce(current_version, '')"),
            sa.text("coalesce(parent_package, '')"),
        ],
        unique=True,
    )
    op.create_index(
        "uq_package_vulnerabilities_identity",
        "package_vulnerabilities",
        [
            "package_id",
            "vulnerability_id",
            sa.text("coalesce(affected_version, '')"),
        ],
        unique=True,
    )
    op.create_index(
        "uq_remediation_tasks_open",
        "remediation_tasks",
        ["repo_id", "package_vulnerability_id"],
        unique=True,
        postgresql_where=sa.text("status = 'open'"),
        sqlite_where=sa.text("status = 'open'"),
    )


def downgrade() -> None:
    op.drop_index("uq_remediation_tasks_open", table_name="remediation_tasks")
    op.drop_index(
        "uq_package_vulnerabilities_identity",
        table_name="package_vulnerabilities",
    )
    op.drop_index("uq_packages_identity", table_name="packages")
    op.drop_constraint(
        "uq_advisory_references_identity",
        "advisory_references",
        type_="unique",
    )
    op.drop_constraint(
        "uq_vulnerability_aliases_identity",
        "vulnerability_aliases",
        type_="unique",
    )
    op.drop_constraint("uq_repos_provider_full_name", "repos", type_="unique")
