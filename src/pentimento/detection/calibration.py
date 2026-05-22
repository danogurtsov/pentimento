"""
Public calibration registry — Phase 9's explicit requirement: a public, honestly-updated
calibration registry (the same pattern krait uses) — including an explicit "this version
hasn't been re-measured yet" marker, never silence. Pure data model + rendering — no
LLM, no network (`services/calibration.py` is what reads the registry file and the current
git commit off disk).

Deliberately NOT an automated recall/precision scorer. Every measurement recorded here came
from a human (or an agent doing the same careful work) reading raw tool output and matching
it against ground truth by MEANING, not string overlap — the exact discipline this repo's
own baseline comparisons already insist on (`evals/golden/detection/
euler_earn_baseline_comparison.md`'s own explicit refusal to count a "same line, different
reason" near-miss as a hit). A naive automated string/keyword matcher would corrupt this
registry with false precision — worse than the un-calibrated, marketing-numbers problem it
exists to solve. This module only stores and renders numbers a careful read already
produced elsewhere.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CalibrationEntry:
    corpus: str  # e.g. "euler_earn"
    component: str  # e.g. "breadth_pass", "baseline_slither", "verification_standard_path"
    model: str  # e.g. "deepseek:deepseek-chat", "claude-cli:haiku", "n/a" for a static tool
    date: str  # ISO date the measurement was actually taken
    commit: str  # pentimento git commit at measurement time
    result: str  # human-readable result, e.g. "2/14 recall"
    methodology_ref: str  # where the full methodology/raw data lives
    note: str = ""


def is_stale(entry: CalibrationEntry, current_commit: str) -> bool:
    """An entry is stale once the code has moved on since it was measured — its recorded
    commit no longer matches HEAD. An empty `current_commit` (git unavailable) never marks
    anything stale — that would be guessing, not measuring.

    Deliberately coarse: ANY commit since the measurement marks it stale, not a diff check
    of whether the actually-relevant detection code changed — an unrelated README edit
    trips this too. A finer-grained "did the relevant file(s) actually change" check is real
    future work, not faked here; over-flagging (a human re-checks a number that was still
    fine) is the safe failure direction, the opposite of silently trusting a stale one."""
    return bool(current_commit) and entry.commit != current_commit


def render_registry(entries: list[CalibrationEntry], current_commit: str) -> str:
    lines = [
        "# Pentimento Calibration Registry",
        "",
        "Honest, dated recall/precision measurements — see each entry's `methodology_ref` "
        "for the full raw data and methodology. An entry marked STALE was measured against "
        "an earlier commit; the number may no longer reflect the current code — it is NOT "
        "automatically re-verified, it is flagged for a human to re-check, per this "
        'registry\'s own "explicit not-yet-re-measured, not silence" principle.',
        "",
    ]
    for entry in entries:
        stale_marker = " **[STALE — re-measure]**" if is_stale(entry, current_commit) else ""
        lines.extend(
            [
                f"## {entry.corpus} / {entry.component}{stale_marker}",
                f"- Model: {entry.model}",
                f"- Measured: {entry.date} at commit `{entry.commit[:12]}`",
                f"- Result: **{entry.result}**",
                f"- Methodology: {entry.methodology_ref}",
            ]
        )
        if entry.note:
            lines.append(f"- Note: {entry.note}")
        lines.append("")
    return "\n".join(lines)
