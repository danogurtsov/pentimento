from pentimento.domain.factories import (
    ContractKey,
    detect_factory_relationships,
    find_instantiated_contracts,
    has_enumeration_getter,
    has_event_announcement,
)

GETTER_FACTORY_SOURCE = """
contract Factory {
    address[] public allPools;
    function createPool(address a, address b) external returns (address p) {
        Pool newPool = new Pool(a, b);
        p = address(newPool);
        allPools.push(p);
    }
    function allPoolsLength() external view returns (uint256) { return allPools.length; }
}
"""

EVENT_FACTORY_SOURCE = """
contract Factory {
    event PairCreated(address indexed tokenA, address indexed tokenB, address pair);
    function createPair(address tokenA, address tokenB) external returns (address pair) {
        Pair newPair = new Pair(tokenA, tokenB);
        pair = address(newPair);
        emit PairCreated(tokenA, tokenB, pair);
    }
}
"""

NEITHER_FACTORY_SOURCE = """
contract Deployer {
    function deployOnce(address a) external returns (address) {
        Helper h = new Helper(a);
        return address(h);
    }
}
"""

EVENT_WITHOUT_ADDRESS_SOURCE = """
contract Deployer {
    event Deployed(uint256 count);
    function deployOnce(address a) external returns (address) {
        Helper h = new Helper(a);
        emit Deployed(1);
        return address(h);
    }
}
"""

EVENT_IN_WRONG_FUNCTION_SOURCE = """
contract Deployer {
    event SomethingHappened(address who);
    function deployOnce(address a) external returns (address) {
        Helper h = new Helper(a);
        return address(h);
    }
    function unrelated() external {
        emit SomethingHappened(msg.sender);
    }
}
"""

PLAIN_SOURCE = "contract Plain { function foo() external {} }"


def test_finds_instantiated_contract_via_new_expression() -> None:
    assert find_instantiated_contracts(GETTER_FACTORY_SOURCE, {"Factory", "Pool"}) == {"Pool"}


def test_ignores_new_of_unknown_identifier() -> None:
    assert find_instantiated_contracts("new bytes(10);", {"Factory"}) == set()


def test_detects_enumeration_array_getter() -> None:
    assert has_enumeration_getter(GETTER_FACTORY_SOURCE) is True


def test_detects_enumeration_length_function() -> None:
    source = "function allWidgetsLength() external view returns (uint256) {}"
    assert has_enumeration_getter(source) is True


def test_no_enumeration_getter_on_event_only_factory() -> None:
    assert has_enumeration_getter(EVENT_FACTORY_SOURCE) is False


def test_detects_event_announcement() -> None:
    assert has_event_announcement(EVENT_FACTORY_SOURCE) is True


def test_no_event_announcement_when_event_has_no_address_param() -> None:
    assert has_event_announcement(EVENT_WITHOUT_ADDRESS_SOURCE) is False


def test_no_event_announcement_when_emit_is_in_a_different_function() -> None:
    assert has_event_announcement(EVENT_IN_WRONG_FUNCTION_SOURCE) is False


def test_no_event_announcement_on_plain_source() -> None:
    assert has_event_announcement(PLAIN_SOURCE) is False


def test_detect_factory_relationships_getter_case() -> None:
    contracts = [
        (ContractKey("Factory.sol", "Factory"), GETTER_FACTORY_SOURCE),
        (ContractKey("Pool.sol", "Pool"), PLAIN_SOURCE),
    ]
    rels = detect_factory_relationships(contracts)
    assert len(rels) == 1
    assert rels[0].factory == ContractKey("Factory.sol", "Factory")
    assert rels[0].template == ContractKey("Pool.sol", "Pool")
    assert rels[0].enumeration_kind == "getter"


def test_detect_factory_relationships_event_case() -> None:
    contracts = [
        (ContractKey("Factory.sol", "Factory"), EVENT_FACTORY_SOURCE),
        (ContractKey("Pair.sol", "Pair"), PLAIN_SOURCE),
    ]
    rels = detect_factory_relationships(contracts)
    assert len(rels) == 1
    assert rels[0].template == ContractKey("Pair.sol", "Pair")
    assert rels[0].enumeration_kind == "event"


def test_detect_factory_relationships_none_case() -> None:
    contracts = [
        (ContractKey("Deployer.sol", "Deployer"), NEITHER_FACTORY_SOURCE),
        (ContractKey("Helper.sol", "Helper"), PLAIN_SOURCE),
    ]
    rels = detect_factory_relationships(contracts)
    assert len(rels) == 1
    assert rels[0].enumeration_kind == "none"


def test_no_relationship_when_nothing_instantiated() -> None:
    assert detect_factory_relationships([(ContractKey("Plain.sol", "Plain"), PLAIN_SOURCE)]) == []


def test_name_collision_across_unrelated_files_does_not_cross_contaminate() -> None:
    # the exact real-world bug found via DeFiHackLabs: two DIFFERENT, unrelated files each
    # declare their own "Factory" contract, each deploying a DIFFERENT, correctly-scoped
    # target. Neither must see the other's relationship, and neither target name is
    # globally unique enough to guess — only same-file resolution is trustworthy here
    # once "Factory" itself collides.
    source_a = GETTER_FACTORY_SOURCE  # Factory -> new Pool(...)
    source_b = EVENT_FACTORY_SOURCE  # Factory -> new Pair(...)
    contracts = [
        (ContractKey("A.sol", "Factory"), source_a),
        (ContractKey("A.sol", "Pool"), PLAIN_SOURCE),
        (ContractKey("B.sol", "Factory"), source_b),
        (ContractKey("B.sol", "Pair"), PLAIN_SOURCE),
    ]
    rels = detect_factory_relationships(contracts)
    by_factory_key = {r.factory: r for r in rels}
    assert by_factory_key[ContractKey("A.sol", "Factory")].template == ContractKey("A.sol", "Pool")
    assert by_factory_key[ContractKey("B.sol", "Factory")].template == ContractKey("B.sol", "Pair")


def test_ambiguous_cross_file_target_is_not_guessed() -> None:
    # "Helper" declared in TWO unrelated files, neither matching the instantiator's own
    # file -> must not resolve to either one.
    deployer_source = """
    contract Deployer {
        function deployOnce() external returns (address) {
            Helper h = new Helper();
            return address(h);
        }
    }
    """
    contracts = [
        (ContractKey("Deployer.sol", "Deployer"), deployer_source),
        (ContractKey("X.sol", "Helper"), PLAIN_SOURCE),
        (ContractKey("Y.sol", "Helper"), PLAIN_SOURCE),
    ]
    assert detect_factory_relationships(contracts) == []
