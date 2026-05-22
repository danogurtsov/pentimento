"""
Phase 9 orchestration: loads the calibration registry off disk (a plain, hand-populated
JSON file — see `detection/calibration.py`'s own docstring on why this is never
automatically generated) and determines pentimento's own current git commit, so
`detection/calibration.render_registry` can flag stale entries live rather than requiring
someone to remember to update a "still current" flag by hand.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from pentimento.detection.calibration import CalibrationEntry


def load_registry(path: Path) -> list[CalibrationEntry]:
    data = json.loads(path.read_text())
    return [CalibrationEntry(**entry) for entry in data]


def current_commit(repo_root: Path) -> str:
    """pentimento's own current HEAD commit — empty string if git isn't on PATH or
    `repo_root` isn't a git checkout at all (never guessed at; see `detection.calibration.
    is_stale`, which treats an empty commit as "can't tell", not "not stale")."""
    try:
        result = subprocess.run(  # noqa: S603, S607
            ["git", "rev-parse", "HEAD"], cwd=repo_root, capture_output=True, text=True, timeout=10, check=False
        )
    except FileNotFoundError:
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""
