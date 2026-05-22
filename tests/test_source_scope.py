from pentimento.domain.source_scope import extract_contract_source

MULTI_DECL_SOURCE = """
interface IFoo {
    function foo() external;
}

contract Alpha {
    function a() external { new Beta(); }
}

contract Beta is Alpha {
    function b() external {}
}
"""


def test_extracts_only_the_named_contract() -> None:
    scoped = extract_contract_source(MULTI_DECL_SOURCE, "Beta")
    assert "contract Beta is Alpha" in scoped
    assert "function b() external" in scoped
    # must NOT bleed in Alpha's body -> the actual bug found on real-world DeFiHackLabs code
    assert "new Beta()" not in scoped
    assert "function a()" not in scoped


def test_interface_is_scoped_too_and_never_contains_a_new_expression() -> None:
    scoped = extract_contract_source(MULTI_DECL_SOURCE, "IFoo")
    assert "function foo() external;" in scoped
    assert "new Beta()" not in scoped


def test_handles_inheritance_clause_before_brace() -> None:
    scoped = extract_contract_source(MULTI_DECL_SOURCE, "Beta")
    assert scoped.startswith("contract Beta is Alpha")


def test_falls_back_to_full_source_when_name_not_found() -> None:
    assert extract_contract_source(MULTI_DECL_SOURCE, "DoesNotExist") == MULTI_DECL_SOURCE


def test_single_contract_file_is_unaffected() -> None:
    # trailing newline after the closing brace is correctly NOT included -> scoping stops
    # exactly at the matched brace, nothing after it
    source = "contract Solo {\n    function f() external {}\n}\n"
    assert extract_contract_source(source, "Solo") == source.rstrip("\n")
