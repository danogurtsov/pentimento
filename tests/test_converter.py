from pathlib import Path

from pentimento.adapters.solc_adapter import SolcAdapter
from pentimento.domain.models import NodeType, ProxyKind
from pentimento.services.converter import convert
from tests.conftest import FIXTURES


def test_plain_token_becomes_single_token_unit(solc_path: str) -> None:
    sol_files = sorted((FIXTURES / "plain_token").glob("*.sol"))
    graph = convert(sol_files, SolcAdapter(solc_path=solc_path))

    assert len(graph.units) == 1
    unit = graph.units[0]
    assert unit.contract_name == "Token"
    assert unit.node_type == NodeType.TOKEN
    assert unit.proxy_kind == ProxyKind.NONE


def test_proxy_and_implementation_merge_into_one_unit(solc_path: str) -> None:
    sol_files = sorted((FIXTURES / "proxy_impl").glob("*.sol"))
    graph = convert(sol_files, SolcAdapter(solc_path=solc_path))

    # this is the whole point of CDV §2: proxy+impl = ONE unit, not two.
    assert len(graph.units) == 1
    unit = graph.units[0]
    assert unit.contract_name == "Proxy"
    assert unit.proxy_kind == ProxyKind.EIP1967_UUPS
    # node_type comes from the IMPLEMENTATION's ABI, not the proxy's own (near-empty) ABI
    assert unit.node_type == NodeType.TOKEN
    assert {Path(f).name for f in unit.source_files} == {"Proxy.sol", "Implementation.sol"}
    assert any("Implementation" in note for note in unit.notes)


def test_factory_and_template_stay_separate_units_with_cross_references(solc_path: str) -> None:
    sol_files = sorted((FIXTURES / "factory_getter").glob("*.sol"))
    graph = convert(sol_files, SolcAdapter(solc_path=solc_path))

    # unlike proxy+impl, factory+template are NOT merged: one is the class, one is the
    # (unknown-count, until onchain) template it deploys.
    assert len(graph.units) == 2
    units_by_name = {u.unit_id: u for u in graph.units}

    factory = units_by_name["Factory"]
    assert factory.node_type == NodeType.FACTORY
    assert factory.factory_creates == "Pool"

    pool = units_by_name["Pool"]
    assert pool.factory_of == "Factory"
    assert any("instantiated by factory" in note for note in pool.notes)


def test_event_only_factory_is_still_classified_as_factory(solc_path: str) -> None:
    sol_files = sorted((FIXTURES / "factory_event").glob("*.sol"))
    graph = convert(sol_files, SolcAdapter(solc_path=solc_path))

    assert len(graph.units) == 2
    factory = next(u for u in graph.units if u.unit_id == "Factory")
    pair = next(u for u in graph.units if u.unit_id == "Pair")

    # no getter anywhere in this fixture (see factory_event/Factory.sol) — the event alone
    # must be enough to classify FACTORY, distinctly labeled from the getter case.
    assert factory.node_type == NodeType.FACTORY
    assert factory.factory_enumeration == "event"
    assert any("creation event" in note for note in factory.notes)
    assert pair.factory_of == "Factory"


def test_diamond_merges_all_facets_into_one_unit(solc_path: str) -> None:
    sol_files = sorted((FIXTURES / "diamond").glob("*.sol"))
    graph = convert(sol_files, SolcAdapter(solc_path=solc_path))

    # this is the whole point of primitive #3: N facets -> ONE unit, unlike proxy+impl
    # (exactly 1 impl) or factory+template (deliberately kept SEPARATE) — a third distinct
    # merge shape, not a variation of either earlier one.
    assert len(graph.units) == 1
    unit = graph.units[0]
    assert unit.contract_name == "Diamond"
    assert unit.proxy_kind == ProxyKind.DIAMOND
    assert set(unit.merged_facets) == {"TokenFacet", "OwnershipFacet"}
    # node_type comes from the COMBINED facet ABIs, same "type comes from the real logic,
    # not the dispatcher" principle already established for proxy+impl
    assert unit.node_type == NodeType.TOKEN
    assert {Path(f).name for f in unit.source_files} == {"Diamond.sol", "TokenFacet.sol", "OwnershipFacet.sol"}
    assert any("TokenFacet" in note for note in unit.notes)
    assert any("OwnershipFacet" in note for note in unit.notes)


def test_diamond_facet_collision_does_not_pull_in_an_unrelated_same_named_facet(solc_path: str) -> None:
    # regression test for a real collision found on aavegotchi-contracts (see
    # diamonds.py's module docstring): dir_b/facets/SharedFacet.sol is an UNRELATED facet
    # reusing the exact same bare name as dir_a's real facet - must never be merged in.
    sol_files = sorted((FIXTURES / "diamond_facet_collision").rglob("*.sol"))
    graph = convert(sol_files, SolcAdapter(solc_path=solc_path))

    # 2 units, not 1: the diamond (merged with dir_a's REAL SharedFacet) AND dir_b's
    # unrelated SharedFacet, which stays its own standalone unit rather than being pulled
    # into a diamond it has nothing to do with.
    assert len(graph.units) == 2
    diamond = next(u for u in graph.units if u.proxy_kind == ProxyKind.DIAMOND)
    standalone = next(u for u in graph.units if u.proxy_kind == ProxyKind.NONE)

    assert diamond.merged_facets == ["SharedFacet"]
    assert {Path(f).name for f in diamond.source_files} == {"Diamond.sol", "SharedFacet.sol"}
    assert any("dir_a" in f for f in diamond.source_files)
    # the real facet's own ABI (symbol/transfer) must win node_type classification, not the
    # unrelated one's (latestRoundData/latestAnswer) - proof the RIGHT SharedFacet merged in.
    assert diamond.node_type == NodeType.TOKEN

    assert standalone.contract_name == "SharedFacet"
    assert "dir_b" in standalone.source_files[0]
    assert standalone.node_type == NodeType.ORACLE


def test_dispatcher_merges_with_its_named_extension(solc_path: str) -> None:
    sol_files = sorted((FIXTURES / "dispatcher").glob("*.sol"))
    graph = convert(sol_files, SolcAdapter(solc_path=solc_path))

    # a FOURTH distinct merge shape: unlike proxy+impl (impl has ~all the logic, proxy
    # ~none) or diamond (facets have ALL the logic), here BOTH Core and CoreExt
    # contribute real functions to the combined node_type.
    assert len(graph.units) == 1
    unit = graph.units[0]
    assert unit.contract_name == "Core"
    assert unit.proxy_kind == ProxyKind.DISPATCHER
    assert unit.node_type == NodeType.TOKEN
    assert {Path(f).name for f in unit.source_files} == {"Core.sol", "CoreExt.sol"}
    assert any("extension merged: CoreExt" in note for note in unit.notes)


def test_singleton_flags_logical_entity_creator_without_merging_anything(solc_path: str) -> None:
    sol_files = sorted((FIXTURES / "singleton").glob("*.sol"))
    graph = convert(sol_files, SolcAdapter(solc_path=solc_path))

    # unlike every other primitive so far, this one needs NO merge at all — it's a single
    # contract, flagged as minting internal (addressless) entities, not a factory.
    assert len(graph.units) == 1
    unit = graph.units[0]
    assert unit.contract_name == "Singleton"
    assert unit.logical_entity_creator == "createMarket"
    assert unit.factory_creates is None  # must NOT also be flagged as a factory
    assert any("logical entity" in note for note in unit.notes)


def test_singleton_flags_counter_based_logical_entity_creator(solc_path: str) -> None:
    # same primitive as the hash-based case above, second real id scheme (see
    # singletons.py's module docstring: Uniswap V3/Aavegotchi/Tremolo all use a plain
    # counter, not a hash, for their internal logical-entity ids).
    sol_files = sorted((FIXTURES / "singleton_counter").glob("*.sol"))
    graph = convert(sol_files, SolcAdapter(solc_path=solc_path))

    assert len(graph.units) == 1
    unit = graph.units[0]
    assert unit.logical_entity_creator == "createEntry"
    assert unit.factory_creates is None
    assert any("logical entity" in note for note in unit.notes)


def test_remapped_external_import_resolves_without_becoming_its_own_unit(solc_path: str) -> None:
    project_root = FIXTURES / "with_remapping"
    src_dir = project_root / "src"
    sol_files = sorted(src_dir.rglob("*.sol"))

    graph = convert(
        sol_files,
        SolcAdapter(solc_path=solc_path),
        project_root=project_root,
        contracts_prefix="src/",
        remappings=["lib/=vendor/"],
    )

    # the inconvenient fact: every fixture before this one was self-contained, but real
    # repos always import something external. MinimalERC20
    # (vendor/) must resolve correctly AND must NOT show up as its own CDV unit — solc
    # reports it as a compiled contract just like MyToken, so filtering it out by prefix
    # is load-bearing, not decorative.
    assert len(graph.units) == 1
    unit = graph.units[0]
    assert unit.contract_name == "MyToken"
    # solc flattens inherited functions into MyToken's own ABI automatically — classify()
    # needed zero special-casing for this to resolve correctly.
    assert unit.node_type == NodeType.TOKEN
    assert unit.source_files == ["src/MyToken.sol"]


def test_bare_interfaces_and_all_internal_libraries_never_become_their_own_unit(solc_path: str) -> None:
    # regression test for a real bug found on Tremolo's own contracts:
    # solc's compiled output includes an ABI(+bin) entry for every interface/library
    # declaration too, not just concrete deployable contracts. Before the deployability.py
    # fix, IThing and MathLib each became their own top-level CDV unit despite neither ever
    # having real bytecode - directly contradicting CDV's own "one unit = one resolved,
    # as-if-deployed contract" principle. PublicLib (a library WITH an external function)
    # is the positive control: not every library is filtered, only ones with no real
    # deployed logic.
    sol_files = sorted((FIXTURES / "non_deployable").glob("*.sol"))
    graph = convert(sol_files, SolcAdapter(solc_path=solc_path))

    assert {u.unit_id for u in graph.units} == {"Thing", "PublicLib"}


def test_oracle_interface_shape_is_not_misclassified_as_token(solc_path: str) -> None:
    # same real bug, converter-level: Tremolo's IChainlinkAggregator-shaped contract used to
    # come back node_type=TOKEN purely from decimals() winning a tie against ORACLE.
    sol_files = sorted((FIXTURES / "oracle_shape").glob("*.sol"))
    graph = convert(sol_files, SolcAdapter(solc_path=solc_path))

    assert len(graph.units) == 1
    assert graph.units[0].node_type == NodeType.ORACLE


def test_erc6909_shaped_contract_is_classified_as_token(solc_path: str) -> None:
    # same real-world repo, a distinct gap: Tremolo's VarianceMarket (ERC-6909 multi-token
    # accounting) used to come back node_type=UNKNOWN because none of its signatures are
    # exact (name, types) matches for the ERC-20-only TOKEN group that existed before.
    sol_files = sorted((FIXTURES / "multitoken").glob("*.sol"))
    graph = convert(sol_files, SolcAdapter(solc_path=solc_path))

    assert len(graph.units) == 1
    assert graph.units[0].node_type == NodeType.TOKEN


def test_same_contract_name_in_unrelated_files_does_not_cross_contaminate(solc_path: str) -> None:
    # regression test for a real bug found on DeFiHackLabs: two UNRELATED files each
    # declare their own "Widget" — before the fix, whichever file solc/Python processed
    # LAST silently overwrote the other's entry in a bare-name-keyed dict, so one file's
    # factory relationship got wrongly applied to the OTHER file's same-named contract.
    fixture_dir = FIXTURES / "name_collision"
    sol_files = sorted(fixture_dir.rglob("*.sol"))
    graph = convert(sol_files, SolcAdapter(solc_path=solc_path))

    assert len(graph.units) == 4  # Target1, Target2, Widget@A, Widget@B — never collapsed
    units_by_id = {u.unit_id: u for u in graph.units}

    widget_a = units_by_id["Widget@A"]
    widget_b = units_by_id["Widget@B"]
    assert any("Target1" in note for note in widget_a.notes)
    assert not any("Target2" in note for note in widget_a.notes)
    assert any("Target2" in note for note in widget_b.notes)
    assert not any("Target1" in note for note in widget_b.notes)
