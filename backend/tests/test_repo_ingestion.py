import json

from app.services.repo_ingestion import profile_repo


def test_profile_repo_ignores_manifest_and_lockfile_symlink_escapes(tmp_path):
    root = tmp_path / "repo"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    outside_manifest = outside / "package.json"
    outside_lockfile = outside / "package-lock.json"
    outside_manifest.write_text(
        json.dumps(
            {
                "scripts": {"test": "vitest run"},
                "dependencies": {"outside-lib": "1.0.0"},
            }
        ),
        encoding="utf-8",
    )
    outside_lockfile.write_text(
        json.dumps({"lockfileVersion": 3, "packages": {}}),
        encoding="utf-8",
    )
    (root / "package.json").symlink_to(outside_manifest)
    (root / "package-lock.json").symlink_to(outside_lockfile)

    profile = profile_repo(str(root))

    assert profile.package_managers == []
    assert profile.dependency_files == []
    assert profile.lockfiles == []
    assert profile.test_commands == []


def test_profile_repo_ignores_dockerfile_and_codeowners_symlink_escapes(tmp_path):
    root = tmp_path / "repo"
    outside = tmp_path / "outside"
    (root / "src" / "routes").mkdir(parents=True)
    outside.mkdir()
    outside_dockerfile = outside / "Dockerfile"
    outside_codeowners = outside / "CODEOWNERS"
    outside_dockerfile.write_text("FROM node:22\n", encoding="utf-8")
    outside_codeowners.write_text("src/routes/ @outside-team\n", encoding="utf-8")
    (root / "Dockerfile").symlink_to(outside_dockerfile)
    (root / "CODEOWNERS").symlink_to(outside_codeowners)

    profile = profile_repo(str(root))

    assert profile.service_type == "api"
    assert profile.codeowners == {}


def test_profile_repo_ignores_service_layout_symlink_escapes(tmp_path):
    root = tmp_path / "repo"
    outside = tmp_path / "outside"
    (root / "src").mkdir(parents=True)
    (root / "Dockerfile").write_text("FROM node:22\n", encoding="utf-8")
    outside.mkdir()
    (root / "src" / "routes").symlink_to(outside, target_is_directory=True)
    (root / "src" / "workers").symlink_to(outside, target_is_directory=True)

    profile = profile_repo(str(root))

    assert profile.service_type == "unknown"
