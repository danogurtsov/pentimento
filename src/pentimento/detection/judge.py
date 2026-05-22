"""
LLM-judge semantic verdict — deterministic PARSING of a separate model's judgment on
whether a breadth-pass response correctly identifies a known ground-truth vulnerability.
Same "model produces structured text, code parses/decides" discipline as every other
model-facing parser in this codebase (`detection/verdict.py::parse_gate_results`,
`detection/routing.py::parse_routing_response`) — the judge's own prose reasoning is never
trusted, only its final `JUDGE_VERDICT: MATCH|NO_MATCH` line.

This is NOT the naive string-matching this project's own calibration registry explicitly
rejects ("deliberately NOT an automated recall scorer... to avoid corrupting the registry
with false precision") — it's semantic judgment by an INDEPENDENT model call, exactly the
"LLM-judge" pattern the field's own most rigorous regression tools use (krait's own blind
shadow-eval, GiAnt Corpus's recursive-repair-loop with an LLM-judge PASS/FAIL).
Built specifically to power `evals/run_detection_regression.py`, Phase 9's first real "fast
tier" gate for DETECTION QUALITY (CDV structural correctness already had `evals/
run_evals.py`; recall/FP had no automated regression protection at all until now).
"""
from __future__ import annotations

import re
from enum import StrEnum


class JudgeVerdict(StrEnum):
    MATCH = "match"
    NO_MATCH = "no_match"
    UNPARSEABLE = "unparseable"  # the judge never answered in the expected format - not a
    # fact either way, recorded honestly rather than silently coerced into NO_MATCH


def build_judge_prompt(ground_truth_description: str, breadth_pass_response: str) -> str:
    return "\n".join(
        [
            "# Semantic regression judge",
            "",
            "A known, ground-truth vulnerability is described below. Decide whether the "
            "detection response that follows correctly identifies THIS SPECIFIC "
            "vulnerability — not just any finding, and not a superficially similar but "
            "substantively different issue.",
            "",
            "## Ground-truth vulnerability",
            ground_truth_description,
            "",
            "## Detection response to judge",
            "```",
            breadth_pass_response,
            "```",
            "",
            "## Task",
            "Does ANY finding in the response above correctly identify the SAME root cause "
            "as the ground-truth vulnerability? A different severity/confidence rating, or "
            "extra unrelated findings alongside it, do NOT disqualify a match — only "
            "whether the ROOT CAUSE genuinely aligns matters. Answer with EXACTLY one line, "
            "nothing else:",
            "```",
            "JUDGE_VERDICT: MATCH|NO_MATCH",
            "```",
        ]
    )


_JUDGE_LINE_RE = re.compile(r"JUDGE_VERDICT:\s*(MATCH|NO_MATCH)", re.IGNORECASE)


def parse_judge_verdict(raw: str) -> JudgeVerdict:
    match = _JUDGE_LINE_RE.search(raw)
    if not match:
        return JudgeVerdict.UNPARSEABLE
    return JudgeVerdict.MATCH if match.group(1).upper() == "MATCH" else JudgeVerdict.NO_MATCH
