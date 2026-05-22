from pentimento.detection.poc_verdict import PoCOutcome, extract_solidity_block, parse_forge_output


def test_a_clean_pass_is_reproduced() -> None:
    output = "Ran 1 test for test/Foo.t.sol:Foo\n[PASS] testExploit() (gas: 12345)\n"
    assert parse_forge_output(0, output) == PoCOutcome.REPRODUCED


def test_a_failing_test_is_not_reproduced() -> None:
    output = "Ran 1 test for test/Foo.t.sol:Foo\n[FAIL. Reason: assertion failed] testExploit()\n"
    assert parse_forge_output(1, output) == PoCOutcome.NOT_REPRODUCED


def test_a_compiler_error_is_compile_error_even_with_a_nonzero_exit_code() -> None:
    output = "Compiler run failed:\nError (1234): Undeclared identifier."
    assert parse_forge_output(1, output) == PoCOutcome.COMPILE_ERROR


def test_a_parser_error_is_compile_error() -> None:
    output = "ParserError: Expected ';' but got '}'"
    assert parse_forge_output(1, output) == PoCOutcome.COMPILE_ERROR


def test_compile_error_markers_take_priority_over_exit_code_zero() -> None:
    # defensive: a compile-error signature should never be read as a real pass, regardless
    # of exit code - see parse_forge_output's own ordering.
    output = "Compiler run failed:\nTypeError: mismatched types."
    assert parse_forge_output(0, output) == PoCOutcome.COMPILE_ERROR


def test_extract_solidity_block_pulls_the_fenced_code() -> None:
    raw = "Here is the test:\n```solidity\ncontract Foo {}\n```\nDone."
    assert extract_solidity_block(raw) == "contract Foo {}"


def test_extract_solidity_block_returns_none_when_absent() -> None:
    assert extract_solidity_block("I cannot write this test.") is None
