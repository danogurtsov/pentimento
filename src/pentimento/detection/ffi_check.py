"""
Detects whether a target project's own foundry.toml enables the `ffi` cheatcode under ANY
profile — a real, evidence-based secrets/sandbox concern for `services/poc_verification.py`,
not a hypothetical: `_external/scabench-minimal-delegation/foundry.toml` (already fetched
into this project's own corpus) has `ffi = true`. Foundry's `vm.ffi(...)`
cheatcode lets a test/script execute an ARBITRARY shell command during `forge test` — the
Level 1 PoC oracle (`services/poc_verification.py`) runs `forge test` against the TARGET
project's own directory, meaning an ffi-enabled project can execute arbitrary commands on
the operator's own machine during exactly the phase this tool exists to run.

Deliberately conservative: checks every profile section in the TOML, not just whichever one
happens to be active by default — `FOUNDRY_PROFILE` can retarget which section applies, and
a real attacker-controlled project could rely on exactly that. A false positive here (an
unused profile happening to set `ffi = true`) costs an explicit `--allow-ffi` override; a
false negative would be a real, silent remote-code-execution surface. The caller's own
refusal is a HARD default-deny, not a soft flag (unlike `injection_scan.py`'s text-content
signals) — this is real subprocess code execution, not LLM prompt content, and the two
categories get different treatment throughout this project (see `services/cost_ceiling.py`'s
own hard abort for the same reasoning: real, irreversible risk gets a hard stop).
"""
from __future__ import annotations

import tomllib
from pathlib import Path


def foundry_toml_has_ffi(project_root: Path) -> bool:
    """True only on a CONFIRMED `ffi = true` in some profile section. False (not an error)
    when there's no foundry.toml, or it fails to parse — an absent/unreadable config is not
    evidence of an ffi risk (forge's own default is ffi=false), so the caller's
    default-refuse posture only triggers on a confirmed positive, never on "couldn't check"."""
    toml_path = project_root / "foundry.toml"
    if not toml_path.is_file():
        return False
    try:
        data = tomllib.loads(toml_path.read_text())
    except (tomllib.TOMLDecodeError, UnicodeDecodeError, OSError):
        return False
    profiles = data.get("profile", {})
    if not isinstance(profiles, dict):
        return False
    return any(isinstance(section, dict) and section.get("ffi") is True for section in profiles.values())
