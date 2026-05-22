from pentimento.detection.complexity import ComplexityMetrics, measure_complexity, should_escalate


def test_measures_imports_functions_and_lines() -> None:
    source = """
import "./A.sol";
import "./B.sol";

contract Foo {
    function a() external {}
    function b() external {}
    function c() external {}
}
"""
    metrics = measure_complexity(source)
    assert metrics.import_count == 2
    assert metrics.function_count == 3
    assert metrics.line_count == len(source.splitlines())


def test_a_simple_small_contract_does_not_escalate() -> None:
    metrics = ComplexityMetrics(import_count=0, function_count=5, line_count=80)
    assert should_escalate(metrics) is False


def test_many_imports_alone_triggers_escalation() -> None:
    # the exact shape of a real observed miss: MinimalDelegation.sol had 31 imports but
    # only 10 functions.
    metrics = ComplexityMetrics(import_count=31, function_count=10, line_count=210)
    assert should_escalate(metrics) is True


def test_many_functions_alone_triggers_escalation() -> None:
    metrics = ComplexityMetrics(import_count=2, function_count=25, line_count=150)
    assert should_escalate(metrics) is True


def test_many_lines_alone_triggers_escalation() -> None:
    metrics = ComplexityMetrics(import_count=2, function_count=5, line_count=350)
    assert should_escalate(metrics) is True


def test_thresholds_are_inclusive_at_the_boundary() -> None:
    assert should_escalate(ComplexityMetrics(15, 0, 0)) is True
    assert should_escalate(ComplexityMetrics(14, 0, 0)) is False
