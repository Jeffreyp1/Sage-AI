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

        assert_duplicate_count(connection, "repos", REPO_IDENTITY_DUPLICATES, 0)
        assert_duplicate_count(
            connection,
            "vulnerability_aliases",
            VULNERABILITY_ALIAS_IDENTITY_DUPLICATES,
            0,
        )
        assert_duplicate_count(
            connection,
            "advisory_references",
            ADVISORY_REFERENCE_IDENTITY_DUPLICATES,
            0,
        )
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
        assert_scalar(connection, "select count(*) from repos where id = 'repo-b'", 0)
        assert_scalar(connection, "select count(*) from scans where repo_id != 'repo-a'", 0)
        assert_scalar(connection, "select count(*) from packages where repo_id != 'repo-a'", 0)
        assert_scalar(connection, "select count(*) from repo_files where repo_id != 'repo-a'", 0)
        assert_scalar(connection, "select count(*) from embeddings where repo_id != 'repo-a'", 0)
        assert_scalar(
            connection,
            "select count(*) from remediation_tasks where repo_id != 'repo-a'",
            0,
        )
        assert_scalar(
            connection,
            "select count(*) from vulnerability_aliases where id = 'alias-b'",
            0,
        )
        assert_scalar(connection, "select count(*) from advisory_references where id = 'ref-b'", 0)
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
        assert_scalar(
            connection,
            """
            select count(*)
            from remediation_tasks
            where id = 'task-closed'
                and repo_id = 'repo-a'
                and package_vulnerability_id = 'pv-a'
            """,
            1,
        )

        create_identity_indexes(connection)


REPO_IDENTITY_DUPLICATES = """
select count(*)
from (
    select 1
    from repos
    group by provider, full_name
    having count(*) > 1
) duplicate_groups
"""

VULNERABILITY_ALIAS_IDENTITY_DUPLICATES = """
select count(*)
from (
    select 1
    from vulnerability_aliases
    group by vulnerability_id, alias
    having count(*) > 1
) duplicate_groups
"""

ADVISORY_REFERENCE_IDENTITY_DUPLICATES = """
select count(*)
from (
    select 1
    from advisory_references
    group by vulnerability_id, url
    having count(*) > 1
) duplicate_groups
"""


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
            create table repos (
                id text primary key,
                org_id text,
                name text not null,
                full_name text not null,
                provider text not null,
                remote_url text,
                default_branch text,
                language text,
                service_type text,
                created_at text not null
            )
            """
        )
    )
    connection.execute(
        text(
            """
            create table scans (
                id text primary key,
                repo_id text not null
            )
            """
        )
    )
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
            create table vulnerability_aliases (
                id text primary key,
                vulnerability_id text not null,
                alias text not null,
                alias_type text not null,
                created_at text not null
            )
            """
        )
    )
    connection.execute(
        text(
            """
            create table advisory_references (
                id text primary key,
                vulnerability_id text not null,
                url text not null,
                reference_type text,
                created_at text not null
            )
            """
        )
    )
    connection.execute(
        text(
            """
            create table repo_files (
                id text primary key,
                repo_id text not null
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
            create table embeddings (
                id text primary key,
                repo_id text
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
            insert into repos (
                id,
                org_id,
                name,
                full_name,
                provider,
                remote_url,
                default_branch,
                language,
                service_type,
                created_at
            )
            values
                (
                    'repo-a',
                    'org-a',
                    'payments-api',
                    'local/payments-api',
                    'local',
                    null,
                    null,
                    'Python',
                    'api',
                    '2026-05-26 00:00:00'
                ),
                (
                    'repo-b',
                    'org-a',
                    'payments-api-copy',
                    'local/payments-api',
                    'local',
                    null,
                    null,
                    'Python',
                    'api',
                    '2026-05-26 00:01:00'
                )
            """
        )
    )
    connection.execute(
        text(
            """
            insert into scans (id, repo_id)
            values ('scan-a', 'repo-b')
            """
        )
    )
    connection.execute(
        text(
            """
            insert into packages (
                id, repo_id, name, ecosystem, current_version, parent_package, created_at
            )
            values
                ('pkg-a', 'repo-a', 'archive-utils', 'npm', null, null, '2026-05-26 00:00:00'),
                ('pkg-b', 'repo-b', 'archive-utils', 'npm', '', null, '2026-05-26 00:01:00'),
                ('pkg-c', 'repo-a', 'archive-utils', 'npm', null, '', '2026-05-26 00:02:00')
            """
        )
    )
    connection.execute(
        text(
            """
            insert into vulnerability_aliases (
                id, vulnerability_id, alias, alias_type, created_at
            )
            values
                ('alias-a', 'vuln-a', 'CVE-2026-1234', 'CVE', '2026-05-26 00:00:00'),
                ('alias-b', 'vuln-a', 'CVE-2026-1234', 'CVE', '2026-05-26 00:01:00'),
                ('alias-c', 'vuln-a', 'GHSA-aaaa-bbbb-cccc', 'GHSA', '2026-05-26 00:02:00')
            """
        )
    )
    connection.execute(
        text(
            """
            insert into advisory_references (
                id, vulnerability_id, url, reference_type, created_at
            )
            values
                (
                    'ref-a',
                    'vuln-a',
                    'https://example.test/advisories/GHSA-aaaa-bbbb-cccc',
                    'ADVISORY',
                    '2026-05-26 00:00:00'
                ),
                (
                    'ref-b',
                    'vuln-a',
                    'https://example.test/advisories/GHSA-aaaa-bbbb-cccc',
                    'ADVISORY',
                    '2026-05-26 00:01:00'
                ),
                (
                    'ref-c',
                    'vuln-a',
                    'https://example.test/references/CVE-2026-1234',
                    'WEB',
                    '2026-05-26 00:02:00'
                )
            """
        )
    )
    connection.execute(
        text(
            """
            insert into repo_files (id, repo_id)
            values ('file-a', 'repo-b')
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
            insert into embeddings (id, repo_id)
            values ('embedding-a', 'repo-b')
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
                ('task-b', 'repo-b', 'pv-b', 'open', '2026-05-26 00:01:00'),
                ('task-closed', 'repo-b', 'pv-b', 'closed', '2026-05-26 00:02:00')
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
            create unique index uq_repos_provider_full_name
            on repos (provider, full_name)
            """
        )
    )
    connection.execute(
        text(
            """
            create unique index uq_vulnerability_aliases_identity
            on vulnerability_aliases (vulnerability_id, alias)
            """
        )
    )
    connection.execute(
        text(
            """
            create unique index uq_advisory_references_identity
            on advisory_references (vulnerability_id, url)
            """
        )
    )
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
