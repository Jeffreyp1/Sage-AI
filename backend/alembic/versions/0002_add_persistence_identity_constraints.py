"""Add persistence identity constraints.

Revision ID: 0002_add_persistence_identity_constraints
Revises: 0001_initial_schema
Create Date: 2026-05-26
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine import Connection

revision: str = "0002_add_persistence_identity_constraints"
down_revision: Union[str, None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    _deduplicate_existing_identity_rows(op.get_bind())

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


def _deduplicate_existing_identity_rows(bind: Connection) -> None:
    _deduplicate_packages(bind)
    _deduplicate_package_vulnerabilities(bind)
    _deduplicate_open_remediation_tasks(bind)


def _deduplicate_packages(bind: Connection) -> None:
    bind.execute(
        sa.text(
            """
            with package_identity_rows as (
                select
                    id,
                    first_value(id) over (
                        partition by
                            repo_id,
                            name,
                            ecosystem,
                            coalesce(current_version, ''),
                            coalesce(parent_package, '')
                        order by created_at, id
                    ) as canonical_id
                from packages
            )
            update package_vulnerabilities
            set package_id = (
                select canonical_id
                from package_identity_rows
                where package_identity_rows.id = package_vulnerabilities.package_id
            )
            where package_id in (
                select id
                from package_identity_rows
                where id != canonical_id
            )
            """
        )
    )
    bind.execute(
        sa.text(
            """
            with package_identity_rows as (
                select
                    id,
                    first_value(id) over (
                        partition by
                            repo_id,
                            name,
                            ecosystem,
                            coalesce(current_version, ''),
                            coalesce(parent_package, '')
                        order by created_at, id
                    ) as canonical_id
                from packages
            )
            delete from packages
            where id in (
                select id
                from package_identity_rows
                where id != canonical_id
            )
            """
        )
    )


def _deduplicate_package_vulnerabilities(bind: Connection) -> None:
    bind.execute(
        sa.text(
            """
            with package_vulnerability_identity_rows as (
                select
                    id,
                    first_value(id) over (
                        partition by
                            package_id,
                            vulnerability_id,
                            coalesce(affected_version, '')
                        order by created_at, id
                    ) as canonical_id
                from package_vulnerabilities
            )
            update reachability_assessments
            set package_vulnerability_id = (
                select canonical_id
                from package_vulnerability_identity_rows
                where package_vulnerability_identity_rows.id =
                    reachability_assessments.package_vulnerability_id
            )
            where package_vulnerability_id in (
                select id
                from package_vulnerability_identity_rows
                where id != canonical_id
            )
            """
        )
    )
    bind.execute(
        sa.text(
            """
            with package_vulnerability_identity_rows as (
                select
                    id,
                    first_value(id) over (
                        partition by
                            package_id,
                            vulnerability_id,
                            coalesce(affected_version, '')
                        order by created_at, id
                    ) as canonical_id
                from package_vulnerabilities
            )
            update remediation_tasks
            set package_vulnerability_id = (
                select canonical_id
                from package_vulnerability_identity_rows
                where package_vulnerability_identity_rows.id =
                    remediation_tasks.package_vulnerability_id
            )
            where package_vulnerability_id in (
                select id
                from package_vulnerability_identity_rows
                where id != canonical_id
            )
            """
        )
    )
    bind.execute(
        sa.text(
            """
            with package_vulnerability_identity_rows as (
                select
                    id,
                    first_value(id) over (
                        partition by
                            package_id,
                            vulnerability_id,
                            coalesce(affected_version, '')
                        order by created_at, id
                    ) as canonical_id
                from package_vulnerabilities
            )
            delete from package_vulnerabilities
            where id in (
                select id
                from package_vulnerability_identity_rows
                where id != canonical_id
            )
            """
        )
    )


def _deduplicate_open_remediation_tasks(bind: Connection) -> None:
    bind.execute(
        sa.text(
            """
            with open_remediation_task_identity_rows as (
                select
                    id,
                    first_value(id) over (
                        partition by repo_id, package_vulnerability_id
                        order by created_at, id
                    ) as canonical_id
                from remediation_tasks
                where status = 'open'
            )
            update human_approvals
            set remediation_task_id = (
                select canonical_id
                from open_remediation_task_identity_rows
                where open_remediation_task_identity_rows.id =
                    human_approvals.remediation_task_id
            )
            where remediation_task_id in (
                select id
                from open_remediation_task_identity_rows
                where id != canonical_id
            )
            """
        )
    )
    bind.execute(
        sa.text(
            """
            with open_remediation_task_identity_rows as (
                select
                    id,
                    first_value(id) over (
                        partition by repo_id, package_vulnerability_id
                        order by created_at, id
                    ) as canonical_id
                from remediation_tasks
                where status = 'open'
            )
            delete from remediation_tasks
            where id in (
                select id
                from open_remediation_task_identity_rows
                where id != canonical_id
            )
            """
        )
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
