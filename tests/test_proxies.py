from pentimento.domain.models import ProxyKind
from pentimento.domain.proxies import detect_proxy_kind, is_upgradeable_implementation_candidate

UUPS_SOURCE = """
contract Proxy {
    bytes32 private constant _IMPLEMENTATION_SLOT = bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
    fallback() external payable {
        address impl;
        assembly { impl := sload(_IMPLEMENTATION_SLOT) }
        assembly { let r := delegatecall(gas(), impl, 0, calldatasize(), 0, 0) }
    }
}
"""

TRANSPARENT_SOURCE = (
    UUPS_SOURCE
    + '\nbytes32 private constant _ADMIN_SLOT = bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1);\n'
)

DIAMOND_SOURCE = """
contract Diamond {
    function facetAddresses() external view returns (address[] memory) {}
    function diamondCut(bytes calldata) external {}
}
"""

PLAIN_SOURCE = """
contract Plain {
    function foo() external {}
}
"""

IMPL_SOURCE = """
contract Impl {
    modifier initializer() { _; }
    function initialize(uint256 x) external initializer {}
}
"""

DISPATCHER_SOURCE = """
contract Main {
    address public immutable mainExtension;
    function realFunction() external returns (uint256) { return 1; }
    fallback() external {
        (bool ok, ) = mainExtension.delegatecall(msg.data);
        require(ok);
    }
}
"""

# has delegatecall but no extension-address declaration -> should NOT be a dispatcher
DELEGATECALL_WITHOUT_EXTENSION_SOURCE = """
contract Weird {
    function forward(address target) external {
        target.delegatecall(msg.data);
    }
}
"""


def test_detects_uups_proxy() -> None:
    assert detect_proxy_kind(UUPS_SOURCE) == ProxyKind.EIP1967_UUPS


def test_detects_transparent_proxy_when_admin_slot_present() -> None:
    assert detect_proxy_kind(TRANSPARENT_SOURCE) == ProxyKind.EIP1967_TRANSPARENT


def test_detects_diamond() -> None:
    assert detect_proxy_kind(DIAMOND_SOURCE) == ProxyKind.DIAMOND


def test_plain_contract_is_not_a_proxy() -> None:
    assert detect_proxy_kind(PLAIN_SOURCE) == ProxyKind.NONE


def test_detects_dispatcher_proxy() -> None:
    assert detect_proxy_kind(DISPATCHER_SOURCE) == ProxyKind.DISPATCHER


def test_delegatecall_alone_without_extension_address_is_not_a_dispatcher() -> None:
    assert detect_proxy_kind(DELEGATECALL_WITHOUT_EXTENSION_SOURCE) == ProxyKind.NONE


def test_eip1967_takes_priority_over_dispatcher_if_both_markers_present() -> None:
    # a contract that happens to name something "...Extension" but is really a standard
    # EIP-1967 proxy must still classify as EIP-1967, not dispatcher (priority order in
    # detect_proxy_kind — the strongest/most standard signal wins).
    mixed = UUPS_SOURCE + "\naddress public someExtensionThing;\n"
    assert detect_proxy_kind(mixed) == ProxyKind.EIP1967_UUPS


def test_detects_upgradeable_implementation_candidate() -> None:
    assert is_upgradeable_implementation_candidate(IMPL_SOURCE) is True


def test_plain_contract_is_not_an_implementation_candidate() -> None:
    assert is_upgradeable_implementation_candidate(PLAIN_SOURCE) is False
