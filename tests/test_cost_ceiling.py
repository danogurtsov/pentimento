import pytest

from pentimento.services.cost_ceiling import BudgetedLLM, BudgetExceededError, SharedBudget


class FakeCostReportingLLM:
    """Mimics ClaudeCliLLM's own shape - a `last_cost_usd` attribute set after each call."""

    def __init__(self, cost_per_call: float) -> None:
        self.cost_per_call = cost_per_call
        self.last_cost_usd: float | None = None
        self.calls = 0

    def complete(self, prompt: str, *, model: str) -> str:
        self.calls += 1
        self.last_cost_usd = self.cost_per_call
        return "response"


class FakeNonReportingLLM:
    """Mimics an adapter with no cost visibility at all - no last_cost_usd attribute."""

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, prompt: str, *, model: str) -> str:
        self.calls += 1
        return "response"


def test_calls_under_the_ceiling_all_succeed() -> None:
    inner = FakeCostReportingLLM(cost_per_call=0.10)
    budget = SharedBudget(ceiling_usd=1.0)
    llm = BudgetedLLM(inner, budget)

    for _ in range(5):
        llm.complete("prompt", model="m")

    assert inner.calls == 5
    assert budget.spent_usd == pytest.approx(0.50)
    assert budget.tracked is True


def test_a_call_that_would_exceed_the_ceiling_is_refused_before_it_happens() -> None:
    inner = FakeCostReportingLLM(cost_per_call=0.60)
    budget = SharedBudget(ceiling_usd=1.0)
    llm = BudgetedLLM(inner, budget)

    llm.complete("prompt", model="m")  # spent 0.60, still under 1.0
    llm.complete("prompt", model="m")  # spent 1.20, now over - allowed since check() ran BEFORE

    with pytest.raises(BudgetExceededError) as exc_info:
        llm.complete("prompt", model="m")

    assert inner.calls == 2  # the third call never reached the inner port at all
    assert exc_info.value.spent == pytest.approx(1.20)
    assert exc_info.value.ceiling == 1.0


def test_a_shared_budget_is_shared_across_multiple_wrapped_ports() -> None:
    scout = FakeCostReportingLLM(cost_per_call=0.5)
    verifier = FakeCostReportingLLM(cost_per_call=0.5)
    budget = SharedBudget(ceiling_usd=1.0)
    scout_llm = BudgetedLLM(scout, budget)
    verifier_llm = BudgetedLLM(verifier, budget)

    scout_llm.complete("p", model="m")
    verifier_llm.complete("p", model="m")  # combined spend now exactly 1.0 - not OVER yet (> not >=)
    scout_llm.complete("p", model="m")  # combined spend now 1.5, still allowed (check ran at 1.0)
    with pytest.raises(BudgetExceededError):
        verifier_llm.complete("p", model="m")  # NOW refused, regardless of which role calls


def test_a_port_with_no_cost_visibility_is_never_tracked_never_blocked() -> None:
    inner = FakeNonReportingLLM()
    budget = SharedBudget(ceiling_usd=0.01)
    llm = BudgetedLLM(inner, budget)

    for _ in range(10):
        llm.complete("prompt", model="m")

    assert inner.calls == 10  # never refused - an untrackable port can't be enforced against
    assert budget.tracked is False
    assert budget.spent_usd == 0.0
