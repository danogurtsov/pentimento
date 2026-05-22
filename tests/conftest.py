from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def solc_path() -> str:
    """Resolve a usable solc binary: env override -> Foundry's svm cache -> PATH.

    No network fetch anywhere in this repo (see solc_adapter.py docstring) — CI installs
    a pinned static binary directly (see .github/workflows/ci.yml); local dev reuses
    whatever Foundry already cached under ~/.svm/.
    """
    if env_path := os.environ.get("PENTIMENTO_SOLC_PATH"):
        return env_path
    svm_cached = Path.home() / ".svm" / "0.8.24" / "solc-0.8.24"
    if svm_cached.exists():
        return str(svm_cached)
    if found := shutil.which("solc"):
        return found
    pytest.skip("no solc binary available (set PENTIMENTO_SOLC_PATH)")
