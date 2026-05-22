"""Port: what the converter service needs from a Solidity compiler, nothing more."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass
class CompiledContract:
    contract_name: str
    source_file: str  # reported relative to `base_path` when one is given — see compile()
    abi: list[dict]
    source_text: str  # SCOPED to just this contract/interface's own declaration, not the
    # whole file it lives in — a file may declare several (see source_scope.py)


class CompilerPort(Protocol):
    def compile(
        self,
        sol_files: list[Path],
        base_path: Path | None = None,
        remappings: list[str] | None = None,
    ) -> list[CompiledContract]:
        """`base_path` anchors both remapping resolution and how `source_file` gets
        reported (confirmed empirically: even absolute `sol_files` paths get reported
        relative to `base_path`) — needed so the converter can tell "our own contract"
        apart from "resolved from a remapped external dependency" by path prefix alone.
        `remappings` are Foundry-style `prefix=path` strings (e.g.
        `"@openzeppelin/=lib/openzeppelin-contracts/"`), passed straight to solc."""
        ...
