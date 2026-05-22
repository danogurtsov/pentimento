from pentimento.domain.deployability import is_deployable
from pentimento.domain.source_scope import extract_contract_source

MULTI_DECL_SOURCE = """
interface IThing {
    function foo() external view returns (uint256);
}

abstract contract BaseThing {
    function foo() external view virtual returns (uint256);
}

library AllInternal {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }
}

library HasExternal {
    function double(uint256 a) external pure returns (uint256) {
        return a * 2;
    }
}

contract Thing {
    function foo() external pure returns (uint256) {
        return 1;
    }
}
"""


def _scoped(name: str) -> str:
    return extract_contract_source(MULTI_DECL_SOURCE, name)


def test_interface_is_never_deployable() -> None:
    assert is_deployable(_scoped("IThing")) is False


def test_abstract_contract_is_never_deployable() -> None:
    assert is_deployable(_scoped("BaseThing")) is False


def test_all_internal_library_is_not_deployable() -> None:
    # fully inlined at every call site - real bug found on Tremolo's VarianceMath, which
    # was getting a top-level CDV unit despite having no real bytecode of its own.
    assert is_deployable(_scoped("AllInternal")) is False


def test_library_with_an_external_function_is_deployable() -> None:
    # the positive case: a library isn't ALWAYS filtered - one with real entry points needs
    # to be deployed and delegatecall'd into just like any other unit.
    assert is_deployable(_scoped("HasExternal")) is True


def test_plain_contract_is_deployable() -> None:
    assert is_deployable(_scoped("Thing")) is True


def test_unscoped_text_without_a_leading_declaration_keyword_defaults_to_deployable() -> None:
    # same "never silently hide findings" fallback as extract_contract_source's own
    # not-found case - an unrecognized shape should never end up silently excluded.
    assert is_deployable("// just a comment, no declaration here") is True
