import json
import subprocess
from pathlib import Path

from pentimento.services.calibration import current_commit, load_registry


def test_load_registry_parses_json_into_typed_entries(tmp_path: Path) -> None:
    registry = tmp_path / "registry.json"
    registry.write_text(
        json.dumps(
            [
                {
                    "corpus": "euler_earn",
                    "component": "breadth_pass",
                    "model": "deepseek:deepseek-chat",
                    "date": "2026-09-03",
                    "commit": "abc123",
                    "result": "2/14 recall",
                    "methodology_ref": "README.md",
                }
            ]
        )
    )

    entries = load_registry(registry)

    assert len(entries) == 1
    assert entries[0].corpus == "euler_earn"
    assert entries[0].note == ""  # default applied when the JSON omits it


def test_current_commit_returns_a_real_hash_inside_a_git_repo(tmp_path: Path) -> None:
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)  # noqa: S603, S607
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=tmp_path, capture_output=True, check=True)  # noqa: S603, S607
    subprocess.run(["git", "config", "user.name", "t"], cwd=tmp_path, capture_output=True, check=True)  # noqa: S603, S607
    (tmp_path / "f.txt").write_text("x")
    subprocess.run(["git", "add", "f.txt"], cwd=tmp_path, capture_output=True, check=True)  # noqa: S603, S607
    subprocess.run(["git", "commit", "-m", "x"], cwd=tmp_path, capture_output=True, check=True)  # noqa: S603, S607

    commit = current_commit(tmp_path)

    assert len(commit) == 40  # a real git sha, not empty


def test_current_commit_returns_empty_string_outside_a_git_repo(tmp_path: Path) -> None:
    assert current_commit(tmp_path) == ""
