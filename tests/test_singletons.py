from pentimento.domain.singletons import find_logical_entity_creator

SINGLETON_SOURCE = """
contract Singleton {
    mapping(bytes32 => Market) public market;
    function createMarket(MarketParams memory p) external {
        bytes32 id = keccak256(abi.encode(p));
        market[id].lastUpdate = 1;
    }
}
"""

# has a create* function AND keccak256(abi.encode(...)) SOMEWHERE, but the create
# function itself deploys a contract -> this is a FACTORY, not a logical entity
FACTORY_LOOKALIKE_SOURCE = """
contract Factory {
    function createPool(address a, address b) external returns (address) {
        Pool p = new Pool(a, b);
        return address(p);
    }
    function hashOf(bytes memory data) external pure returns (bytes32) {
        return keccak256(abi.encode(data));
    }
}
"""

# create* function exists but doesn't compute an id via keccak256(abi.encode(...)) at all
CREATE_WITHOUT_ID_SOURCE = """
contract Thing {
    function createSomething() external {
        emit Created();
    }
}
"""

PLAIN_SOURCE = "contract Plain { function foo() external {} }"

# real-world-motivated (Uniswap V3's NonfungiblePositionManager.mint(): `tokenId =
# _nextId++`; Aavegotchi's DAOFacet: `itemId = itemTypesLength++`; our own Tremolo's
# VarianceMarket.createSeries(): `seriesId = ++seriesCount`) - a counter, not a hash.
COUNTER_SINGLETON_SOURCE = """
contract Registry {
    uint256 private nextId = 1;
    mapping(uint256 => Entry) public entries;
    function createEntry(address owner) external returns (uint256 entryId) {
        entryId = nextId++;
        entries[entryId].owner = owner;
    }
}
"""

# real-world-motivated (Gearbox Protocol's AccountFactory: deploys a clone PER credit
# account via OpenZeppelin's Clones.clone(), which compiles to an inline-assembly `create`
# opcode - contains NO `new` keyword at all, and also increments a counter). Must NOT be
# flagged as a logical entity despite the counter-shaped id - it deploys a real contract.
CLONE_FACTORY_SOURCE = """
contract CloneFactory {
    uint256 public nextId;
    address public implementation;
    function createAccount() external returns (address accountId) {
        accountId = implementation.clone();
        nextId++;
    }
}
"""

# same real Gearbox shape, but via bare assembly `create` instead of a `.clone()` helper -
# the actual EIP-1167 minimal-proxy bytecode OZ's Clones library expands to under the hood.
ASSEMBLY_CREATE_FACTORY_SOURCE = """
contract CloneFactory {
    uint256 public nextId;
    function createAccount(address impl) external returns (address accountId) {
        assembly {
            accountId := create(0, impl, 0x37)
        }
        nextId++;
    }
}
"""

# a counter increment that ISN'T assigned to an id-looking variable - must not fire just
# because SOME arithmetic vaguely resembling "+1" appears in a create*-named function.
UNRELATED_ARITHMETIC_SOURCE = """
contract Thing {
    function createSomething(uint256 total) external returns (uint256) {
        uint256 doubled = total + 1;
        return doubled;
    }
}
"""


def test_finds_logical_entity_creator() -> None:
    assert find_logical_entity_creator(SINGLETON_SOURCE) == "createMarket"


def test_finds_counter_based_logical_entity_creator() -> None:
    assert find_logical_entity_creator(COUNTER_SINGLETON_SOURCE) == "createEntry"


def test_clone_based_factory_is_not_a_logical_entity_despite_counter_shaped_id() -> None:
    assert find_logical_entity_creator(CLONE_FACTORY_SOURCE) is None


def test_assembly_create_factory_is_not_a_logical_entity_despite_counter_shaped_id() -> None:
    assert find_logical_entity_creator(ASSEMBLY_CREATE_FACTORY_SOURCE) is None


def test_unrelated_arithmetic_does_not_look_like_a_counter_id() -> None:
    assert find_logical_entity_creator(UNRELATED_ARITHMETIC_SOURCE) is None


def test_factory_with_new_expression_is_not_a_logical_entity_even_with_keccak_elsewhere() -> None:
    # the keccak256(abi.encode(...)) is in a DIFFERENT function (hashOf), not in createPool
    # itself, and createPool contains `new Pool(...)` -> must not be flagged
    assert find_logical_entity_creator(FACTORY_LOOKALIKE_SOURCE) is None


def test_create_function_without_keccak_id_is_not_a_logical_entity() -> None:
    assert find_logical_entity_creator(CREATE_WITHOUT_ID_SOURCE) is None


def test_plain_contract_has_no_logical_entity_creator() -> None:
    assert find_logical_entity_creator(PLAIN_SOURCE) is None
