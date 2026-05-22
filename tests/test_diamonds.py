from pentimento.domain.diamonds import find_facet_contracts, resolve_facet_contracts
from pentimento.domain.factories import ContractKey


def test_finds_contracts_matching_facet_convention() -> None:
    assert find_facet_contracts({"Diamond", "TokenFacet", "OwnershipFacet"}, exclude={"Diamond"}) == {
        "TokenFacet",
        "OwnershipFacet",
    }


def test_excludes_the_diamond_itself_even_if_it_matches_the_naming_convention() -> None:
    # the diamond happens to be named "...Facet" too (unusual, but exclude= must still win)
    assert find_facet_contracts({"MyFacet", "OtherFacet"}, exclude={"MyFacet"}) == {"OtherFacet"}


def test_no_facets_when_nothing_matches() -> None:
    assert find_facet_contracts({"Diamond", "Helper"}, exclude={"Diamond"}) == set()


def test_empty_known_names() -> None:
    assert find_facet_contracts(set()) == set()


def test_resolve_facet_contracts_prefers_the_directory_closest_to_the_diamond() -> None:
    # regression test for a real collision found on aavegotchi-contracts: 5 separate
    # diamonds in one monorepo reuse the SAME facet name across DIFFERENT diamonds, each
    # under its own top-level directory.
    real_facet = ContractKey("dir_a/facets/SharedFacet.sol", "SharedFacet")
    unrelated_facet = ContractKey("dir_b/facets/SharedFacet.sol", "SharedFacet")
    by_name = {"SharedFacet": [real_facet, unrelated_facet]}

    resolved = resolve_facet_contracts("dir_a/Diamond.sol", {"SharedFacet"}, by_name)

    assert resolved == [real_facet]


def test_resolve_facet_contracts_is_unambiguous_when_globally_unique() -> None:
    only = ContractKey("src/facets/TokenFacet.sol", "TokenFacet")
    by_name = {"TokenFacet": [only]}

    assert resolve_facet_contracts("src/Diamond.sol", {"TokenFacet"}, by_name) == [only]


def test_resolve_facet_contracts_skips_a_true_tie_rather_than_guessing() -> None:
    # both candidates are equally (un)related to the diamond's own directory - a real tie,
    # not resolvable by proximity - must be skipped, never guessed.
    a = ContractKey("other_a/facets/TieFacet.sol", "TieFacet")
    b = ContractKey("other_b/facets/TieFacet.sol", "TieFacet")
    by_name = {"TieFacet": [a, b]}

    assert resolve_facet_contracts("dir_a/Diamond.sol", {"TieFacet"}, by_name) == []


def test_resolve_facet_contracts_skips_unknown_name() -> None:
    assert resolve_facet_contracts("dir_a/Diamond.sol", {"GhostFacet"}, {}) == []
