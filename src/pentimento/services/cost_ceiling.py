"""
A real, enforced per-run budget ceiling — Phase 8, a standing budget circuit-breaker.
Scoped honestly to what this tool can actually
track today: no central model gateway exists yet to enforce budgets centrally — every
adapter calls its own vendor directly (see `ports/llm.py`'s own docstring) — so this wraps
whatever `LLMPort` a caller already has and reads cost per call from `last_cost_usd`, an
attribute currently only `adapters/claude_cli_adapter.py`'s `ClaudeCliLLM` exposes (from the
CLI's own `--output-format json`). Wrapping a port that doesn't expose it still works — it
just can't track spend for that port, and `SharedBudget.tracked` says so honestly rather
than silently assuming zero cost.

Cannot be a hard, real-time PREEMPTIVE limit — a call's cost is only known AFTER it
completes (no pre-call cost estimator exists). This is a circuit breaker: once cumulative
tracked spend already exceeds the ceiling, the NEXT call is refused before it's made. One
call's worth of overshoot past the ceiling is possible and expected, not a bug.

A SINGLE `SharedBudget` is meant to be reused across every role in one CLI invocation
(scout/strategist/verifier/poc) — each gets its own `BudgetedLLM` wrapper, but they all
check and record against the same shared cumulative total: one budget per
task, for a single `pentimento investigate`/`breadth-pass` run.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from pentimento.ports.llm import LLMPort


class BudgetExceededError(RuntimeError):
    def __init__(self, spent: float, ceiling: float) -> None:
        super().__init__(
            f"cost ceiling exceeded: ${spent:.4f} already spent (ceiling ${ceiling:.4f}) — "
            "refusing further calls"
        )
        self.spent = spent
        self.ceiling = ceiling


@dataclass
class SharedBudget:
    ceiling_usd: float
    spent_usd: float = field(default=0.0, init=False)
    tracked: bool = field(default=False, init=False)  # True once any real cost has been observed

    def check(self) -> None:
        if self.spent_usd > self.ceiling_usd:
            raise BudgetExceededError(self.spent_usd, self.ceiling_usd)

    def record(self, cost: float | None) -> None:
        if cost is not None:
            self.spent_usd += cost
            self.tracked = True


@dataclass
class BudgetedLLM:
    """Wraps one role's `LLMPort` against a shared budget. `model_of`/`build_llm` in
    `cli.py` construct the real inner port; this only ever adds the check/record steps
    around it — it never changes what gets sent or returned."""

    inner: LLMPort
    budget: SharedBudget

    def complete(self, prompt: str, *, model: str) -> str:
        self.budget.check()
        result = self.inner.complete(prompt, model=model)
        self.budget.record(getattr(self.inner, "last_cost_usd", None))
        return result
