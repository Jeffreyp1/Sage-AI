import importlib.util
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError


def test_0002_deduplicates_identity_rows_before_unique_indexes():
    migration = load_0002_migration()
    engine = create_engine("sqlite:///:memory:")

    with engine.begin() as connection:
        create_old_identity_schema(connection)
        seed_duplicate_identity_rows(connection)

        dedupe = getattr(migration, "_deduplicate_existing_identity_rows", None)
        if dedupe is None:
            with pytest.raises(IntegrityError):
                create_identity_indexes(connection)
            return

        dedupe(connection)

        assert_duplicate_count(connection, "packages", PACKAGE_IDENTITY_DUPLICATES, 0)
        assert_duplicate_count(
            connection,
            "package_vulnerabilities",
            PACKAGE_VULNERABILITY_IDENTITY_DUPLICATES,
            0,
        )
        assert_duplicate_count(
            connection,
            "remediation_tasks",
            OPEN_REMEDIATION_TASK_DUPLICATES,
            0,
        )
        assert_scalar(
            connection,
            "select count(*) from package_vulnerabilities where package_id != 'pkg-a'",
            0,
        )
        assert_scalar(
            connection,
            "select count(*) from reachability_assessments where package_vulnerability_id != 'pv-a'",
            0,
        )
        assert_scalar(
            connection,
            "select count(*) from remediation_tasks where package_vulnerability_id != 'pv-a'",
            0,
        )
        assert_scalar(connection, "select count(*) from remediation_tasks where id = 'task-b'", 0)
        assert_scalar(
            connection,
            "select count(*) from human_approvals where remediation_task_id = 'task-b'",
            0,
        )
        assert_scalar(connection, "select count(*) from remediation_tasks where id = 'task-closed'", 1)

        create_identity_indexes(connection)


PACKAGE_IDENTITY_DUPLICATES = """
select count(*)
from (
    select 1
    from packages
    group by repo_id, name, ecosystem, coalesce(current_version, ''), coalesce(parent_package, '')
    having count(*) > 1
) duplicate_groups
"""

PACKAGE_VULNERABILITY_IDENTITY_DUPLICATES = """
select count(*)
from (
    select 1
    from package_vulnerabilities
    group by package_id, vulnerability_id, coalesce(affected_version, '')
    having count(*) > 1
) duplicate_groups
"""

OPEN_REMEDIATION_TASK_DUPLICATES = """
select count(*)
from (
    select 1
    from remediation_tasks
    where status = 'open'
    group by repo_id, package_vulnerability_id
    having count(*) > 1
) duplicate_groups
"""


def load_0002_migration():
    migration_path = (
        Path(__file__).resolve().parents[1]
        / "alembic"
        / "versions"
        / "0002_add_persistence_identity_constraints.py"
    )
    spec = importlib.util.spec_from_file_location("migration_0002", migration_path)
    assert spec is not None
    assert spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    return migration


def create_old_identity_schema(connection):
    connection.execute(
        text(
            """
            create table packages (
                id text primary key,
                repo_id text not null,
                name text not null,
                ecosystem text not null,
                current_version text,
                parent_package text,
                created_at text not null
            )
            """
        )
    )
    connection.execute(
        text(
            """
            create table package_vulnerabilities (
                id text primary key,
                package_id text not null,
                vulnerability_id text not null,
                affected_version text,
                created_at text not null
            )
            """
        )
    )
    connection.execute(
        text(
            """
            create table reachability_assessments (
                id text primary key,
                package_vulnerability_id text not null
            )
            """
        )
    )
    connection.execute(
        text(
            """
            create table remediation_tasks (
                id text primary key,
                repo_id text not null,
                package_vulnerability_id text not null,
                status text not null,
                created_at text not null
            )
            """
        )
    )
    connection.execute(
        text(
            """
            create table human_approvals (
                id text primary key,
                remediation_task_id text not null
            )
            """
        )
    )


def seed_duplicate_identity_rows(connection):
    connection.execute(
        text(
            """
            insert into packages (
                id, repo_id, name, ecosystem, current_version, parent_package, created_at
            )
            values
                ('pkg-a', 'repo-a', 'archive-utils', 'npm', null, null, '2026-05-26 00:00:00'),
                ('pkg-b', 'repo-a', 'archive-utils', 'npm', '', null, '2026-05-26 00:01:00'),
                ('pkg-c', 'repo-a', 'archive-utils', 'npm', null, '', '2026-05-26 00:02:00')
            """
        )
    )
    connection.execute(
        text(
            """
            insert into package_vulnerabilities (
                id, package_id, vulnerability_id, affected_version, created_at
            )
            values
                ('pv-a', 'pkg-a', 'vuln-a', null, '2026-05-26 00:00:00'),
                ('pv-b', 'pkg-b', 'vuln-a', '', '2026-05-26 00:01:00')
            """
        )
    )
    connection.execute(
        text(
            """
            insert into reachability_assessments (id, package_vulnerability_id)
            values
                ('reach-a', 'pv-a'),
                ('reach-b', 'pv-b')
            """
        )
    )
    connection.execute(
        text(
            """
            insert into remediation_tasks (
                id, repo_id, package_vulnerability_id, status, created_at
            )
            values
                ('task-a', 'repo-a', 'pv-a', 'open', '2026-05-26 00:00:00'),
                ('task-b', 'repo-a', 'pv-b', 'open', '2026-05-26 00:01:00'),
                ('task-closed', 'repo-a', 'pv-b', 'closed', '2026-05-26 00:02:00')
            """
        )
    )
    connection.execute(
        text(
            """
            insert into human_approvals (id, remediation_task_id)
            values
                ('approval-a', 'task-a'),
                ('approval-b', 'task-b')
            """
        )
    )


def create_identity_indexes(connection):
    connection.execute(
        text(
            """
            create unique index uq_packages_identity
            on packages (
                repo_id,
                name,
                ecosystem,
                coalesce(current_version, ''),
                coalesce(parent_package, '')
            )
            """
        )
    )
    connection.execute(
        text(
            """
            create unique index uq_package_vulnerabilities_identity
            on package_vulnerabilities (
                package_id,
                vulnerability_id,
                coalesce(affected_version, '')
            )
            """
        )
    )
    connection.execute(
        text(
            """
            create unique index uq_remediation_tasks_open
            on remediation_tasks (repo_id, package_vulnerability_id)
            where status = 'open'
            """
        )
    )


def assert_duplicate_count(connection, table_name, query, expected):
    assert_scalar(connection, query, expected), table_name


def assert_scalar(connection, query, expected):
    assert connection.execute(text(query)).scalar_one() == expected
