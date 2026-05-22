"""
Complexity-based model escalation — directly motivated by a live, measured finding
(documented in `evals/golden/detection/model_capacity_test.md`), not a hunch: the
IDENTICAL fixed BSA prompt caught a real, cataloged bug on `claude-cli:sonnet` but missed
it TWICE on `claude-cli:haiku`, on a real ~30-import, multi-inheritance contract
(`scabench-minimal-delegation`'s `MinimalDelegation.sol`) — confirmed by changing only the
model and getting an exact hit. That finding is what this module closes: matching model
capability to target complexity is a real, evidenced consideration, and this adds
adaptive model-selection-by-complexity.

Same "route before you spend" principle as `engine_selection.py`/`domain_signals.py`: a
cheap, deterministic signal computed from the source text alone, before any LLM call,
decides whether a unit's own complexity warrants escalating to a stronger model.

Deliberately simple counting heuristics — import count, function count, line count — not a
real complexity metric (cyclomatic complexity, call-graph depth, inheritance depth). These
are grounded in the ACTUAL observation that motivated this module (a large import count on
a real miss), not a more sophisticated metric invented without evidence.

Honest scope note on the thresholds themselves: they are a first, reasoned guess informed by
ONE real observed failure point (~30 imports), deliberately set BELOW it rather than tuned
to it — n=1 data point, not a calibrated/swept parameter. A real calibration would need many
more paired cheap/strong-model runs across many real units, which is future work, not faked
here as a precise number.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_IMPORT_RE = re.compile(r"^\s*import\b", re.MULTILINE)
_FUNCTION_RE = re.compile(r"^\s*function\b", re.MULTILINE)

# Deliberately well below the ~30-import contract where the real miss was observed — a
# conservative first guess, not a tuned threshold (see module docstring).
IMPORT_THRESHOLD = 15
FUNCTION_THRESHOLD = 20
LINE_THRESHOLD = 300


@dataclass(frozen=True)
class ComplexityMetrics:
    import_count: int
    function_count: int
    line_count: int


@dataclass(frozen=True)
class ModelDecision:
    """Recorded on every unit regardless of whether a stronger model was actually
    available — `recommended_escalation` is visible even when `escalated` ends up False
    because no `strong_llm` was configured, same "signal built, action optionally taken,
    never silent" precedent as `detection.routing.RoutingDecision`."""

    metrics: ComplexityMetrics
    recommended_escalation: bool
    model_used: str
    escalated: bool  # recommended AND a stronger model was actually available and used


def measure_complexity(source_code: str) -> ComplexityMetrics:
    return ComplexityMetrics(
        import_count=len(_IMPORT_RE.findall(source_code)),
        function_count=len(_FUNCTION_RE.findall(source_code)),
        line_count=len(source_code.splitlines()),
    )


def should_escalate(metrics: ComplexityMetrics) -> bool:
    """True if this unit's complexity crosses ANY threshold — a single very-long file with
    few functions, or a short file with unusually many functions, are both plausible signs
    a cheap model's attention may not hold, same reasoning as the real observed failure.

    Checked against every unit this project has ever run live detection against (5 real
    cases): correctly flags the one real observed miss (`MinimalDelegation.sol`,
    31 imports) AND flags 2 units the cheap model ALREADY succeeded on (`EulerEarn.sol`,
    `GenesisPoolManager.sol` — both large by function count/line count even though the cheap
    model found real bugs there unescalated). This is an honest, accepted cost of an
    OR-of-3-signals heuristic calibrated on a single real failure: it optimizes for not
    missing another `MinimalDelegation`-shaped case, at the cost of some over-triggering
    (spending on a stronger model where the cheap one would have been fine) — the same
    "over-flag rather than silently trust" direction already chosen for the calibration
    registry's own staleness check. NOT tuned to exclude those 2 cases after the fact —
    that would be fitting a threshold to 5 known points, not evidence."""
    return (
        metrics.import_count >= IMPORT_THRESHOLD
        or metrics.function_count >= FUNCTION_THRESHOLD
        or metrics.line_count >= LINE_THRESHOLD
    )
