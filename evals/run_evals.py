"""
Runs the repo->CDV converter against every fixture in evals/golden/cdv/ and checks the
output matches exactly: the golden set is committed in evals/golden/cdv/ and run in CI on
every change to the converter.

100% match required on this set by design — this is the foundation everything else builds
on, not a place for "mostly right".
"""
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pentimento.adapters.remappings import load_remappings  # noqa: E402
from pentimento.adapters.solc_adapter import SolcAdapter  # noqa: E402
from pentimento.services.converter import convert  # noqa: E402


def _resolve_solc() -> str:
    if env_path := os.environ.get("PENTIMENTO_SOLC_PATH"):
        return env_path
    svm_cached = Path.home() / ".svm" / "0.8.24" / "solc-0.8.24"
    if svm_cached.exists():
        return str(svm_cached)
    found = shutil.which("solc")
    if found:
        return found
    print("no solc binary available (set PENTIMENTO_SOLC_PATH)")
    sys.exit(1)


def run() -> int:
    solc_path = _resolve_solc()
    golden_dir = ROOT / "evals" / "golden" / "cdv"
    failures: list[str] = []
    total = 0

    for golden_file in sorted(golden_dir.glob("*.json")):
        total += 1
        spec = json.loads(golden_file.read_text())
        fixture_dir = ROOT / spec["fixture_dir"]
        sol_files = sorted(fixture_dir.rglob("*.sol"))

        project_root = (ROOT / spec["project_root"]).resolve() if "project_root" in spec else None
        contracts_prefix = str(fixture_dir.resolve().relative_to(project_root)) + "/" if project_root else None
        remappings = load_remappings(project_root) if spec.get("auto_remappings") and project_root else None

        graph = convert(
            sol_files,
            SolcAdapter(solc_path=solc_path),
            project_root=project_root,
            contracts_prefix=contracts_prefix,
            remappings=remappings,
        )

        actual = sorted(
            (
                u.unit_id,
                u.node_type.value,
                u.proxy_kind.value,
                tuple(sorted(Path(f).stem for f in u.source_files)),
                u.factory_creates,
                u.factory_of,
                u.factory_enumeration,
                tuple(sorted(u.merged_facets)),
                u.logical_entity_creator,
            )
            for u in graph.units
        )
        expected = sorted(
            (
                u["unit_id"],
                u["node_type"],
                u["proxy_kind"],
                tuple(sorted(u["merged_from"])),
                u.get("factory_creates"),
                u.get("factory_of"),
                u.get("factory_enumeration"),
                tuple(sorted(u.get("merged_facets", []))),
                u.get("logical_entity_creator"),
            )
            for u in spec["expected_units"]
        )

        if actual == expected:
            print(f"PASS  {golden_file.stem}")
        else:
            failures.append(golden_file.stem)
            print(f"FAIL  {golden_file.stem}\n  expected: {expected}\n  actual:   {actual}")

    print(f"\n{total - len(failures)}/{total} golden fixtures passed.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(run())
