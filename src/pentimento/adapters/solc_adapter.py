"""
Adapter: shells out to a local `solc` binary to get each contract's ABI + source text.

Determinism-first, per the CDV standard's own principle: parsing/compilation is code, not
LLM. No network calls: this adapter never fetches a compiler — it expects one to already be
on PATH or pointed at explicitly (e.g. a Foundry `~/.svm/<version>/solc-<version>`
binary already cached locally).
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from pentimento.domain.source_scope import extract_contract_source
from pentimento.ports.compiler import CompiledContract


class SolcNotFoundError(RuntimeError):
    pass


class SolcCompilationError(RuntimeError):
    pass


class SolcAdapter:
    def __init__(self, solc_path: str = "solc") -> None:
        self.solc_path = solc_path

    def compile(
        self,
        sol_files: list[Path],
        base_path: Path | None = None,
        remappings: list[str] | None = None,
    ) -> list[CompiledContract]:
        if not sol_files:
            return []
        cmd = [self.solc_path, "--combined-json", "abi"]
        if base_path is not None:
            cmd += ["--base-path", str(base_path)]
        cmd += list(remappings or [])
        cmd += [str(p) for p in sol_files]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)  # noqa: S603
        except FileNotFoundError as e:
            raise SolcNotFoundError(f"solc binary not found at {self.solc_path!r}") from e

        if result.returncode != 0:
            raise SolcCompilationError(result.stderr or result.stdout)

        payload = json.loads(result.stdout)
        contracts_raw: dict = payload.get("contracts", {})

        # source_file, as reported by solc, is relative to base_path when one was given
        # (confirmed empirically — even with absolute sol_files paths) — resolve against
        # it to actually read the file; without a base_path it's whatever was passed in.
        source_cache: dict[str, str] = {}
        out: list[CompiledContract] = []
        for key, entry in contracts_raw.items():
            # solc combined-json key format: "path/to/File.sol:ContractName"
            source_file, _, contract_name = key.rpartition(":")
            abi_raw = entry.get("abi", [])
            abi = json.loads(abi_raw) if isinstance(abi_raw, str) else abi_raw

            if source_file not in source_cache:
                real_path = (base_path / source_file) if base_path is not None else Path(source_file)
                source_cache[source_file] = real_path.read_text()

            # scoped to just THIS contract/interface — found the hard way that a raw
            # whole-file text silently breaks every domain detector once a file declares
            # more than one contract (see source_scope.py's docstring for the real case
            # that caught this: DeFiHackLabs' Euler_exp.sol declares six in one file).
            out.append(
                CompiledContract(
                    contract_name=contract_name,
                    source_file=source_file,
                    abi=abi,
                    source_text=extract_contract_source(source_cache[source_file], contract_name),
                )
            )
        return out
