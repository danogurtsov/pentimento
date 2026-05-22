"""Adapter: auto-load Foundry-style `remappings.txt` if a target project has one."""
from __future__ import annotations

from pathlib import Path


def load_remappings(project_root: Path) -> list[str]:
    """One `prefix=path` per line, `#`-comments and blank lines skipped. Returns []
    if the project has no `remappings.txt` (e.g. it's a Hardhat project resolving
    imports straight from `node_modules/` — nothing to auto-detect there yet)."""
    remappings_file = project_root / "remappings.txt"
    if not remappings_file.exists():
        return []
    lines = remappings_file.read_text().splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]
