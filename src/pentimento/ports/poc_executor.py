"""
Port for actually EXECUTING a generated Foundry PoC test — the Level 1, deterministic
oracle that stands as the strongest verification tier ("framework
itself re-verifies the exploit reproduces... the model does NOT decide whether the check
passed — code does"). Kept to the smallest possible contract (run one test file, hand back
forge's own raw output) so `services/poc_verification.py`'s orchestration is fully testable
against a fake, and so all INTERPRETATION of forge's output stays in `detection/
poc_verdict.py`'s pure, LLM-free `parse_forge_output` — never inside the adapter itself,
same "port returns raw, a pure function in detection/ decides" split as `LLMPort`.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class ForgeRunResult:
    exit_code: int
    output: str  # combined stdout+stderr


class PoCExecutorPort(Protocol):
    def run_test(self, test_file: Path, project_root: Path) -> ForgeRunResult:
        """Runs the Foundry test at `test_file` (already written to disk, inside
        `project_root`'s own test tree) and returns forge's raw result — exit code plus
        combined stdout/stderr, uninterpreted."""
        ...
