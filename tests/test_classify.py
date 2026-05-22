from pentimento.domain.classify import classify
from pentimento.domain.models import NodeType


def _fn(name: str, *arg_types: str) -> dict:
    return {"type": "function", "name": name, "inputs": [{"type": t} for t in arg_types]}


def test_classifies_token_by_erc20_signatures() -> None:
    abi = [
        _fn("transfer", "address", "uint256"),
        _fn("balanceOf", "address"),
        _fn("totalSupply"),
        _fn("decimals"),
        _fn("symbol"),
        _fn("approve", "address", "uint256"),
    ]
    assert classify(abi) == NodeType.TOKEN


def test_classifies_multisig_by_safe_signatures() -> None:
    abi = [_fn("getOwners"), _fn("getThreshold")]
    assert classify(abi) == NodeType.MULTISIG


def test_classifies_custom_propose_approve_execute_multisig() -> None:
    # real ABI shape from a private TimeLockedMultisig.sol fixture - a genuine N-of-M
    # multisig that used to classify UNKNOWN because it doesn't match Gnosis Safe's own
    # execTransaction()/getOwners() signatures.
    abi = [
        _fn("isSigner", "address"),
        _fn("threshold"),
        _fn("delay"),
        _fn("admin"),
        _fn("proposals", "uint256"),
        _fn("proposalCount"),
        _fn("propose", "address", "uint256", "bytes"),
        _fn("approve", "uint256"),
        _fn("execute", "uint256"),
    ]
    assert classify(abi) == NodeType.MULTISIG


def test_a_lone_threshold_getter_still_resolves_to_multisig_absent_anything_better() -> None:
    # same min-1-match design already established for ORACLE/decimals() above: a single
    # signature is enough evidence when no other group scores higher. threshold() is
    # somewhat generic on its own (lending protocols use the word too), but this codebase's
    # existing corpus has no real contract where it collides with a stronger match elsewhere.
    abi = [_fn("threshold")]
    assert classify(abi) == NodeType.MULTISIG


def test_governance_propose_does_not_collide_with_multisig_propose() -> None:
    # GOVERNANCE's own propose(address[],uint256[],bytes[],string) is a different (name,
    # types) tuple than MULTISIG's propose(address,uint256,bytes) - must not double-count.
    abi = [
        _fn("castVote", "uint256", "uint8"),
        _fn("propose", "address[]", "uint256[]", "bytes[]", "string"),
        _fn("quorum", "uint256"),
    ]
    assert classify(abi) == NodeType.GOVERNANCE


def test_unknown_when_no_signatures_match() -> None:
    abi = [_fn("doSomethingBespoke", "uint256")]
    assert classify(abi) == NodeType.UNKNOWN


def test_empty_abi_is_unknown() -> None:
    assert classify([]) == NodeType.UNKNOWN


def test_non_function_entries_are_ignored() -> None:
    abi = [{"type": "event", "name": "Transfer", "inputs": []}]
    assert classify(abi) == NodeType.UNKNOWN


def test_classifies_erc4626_vault_over_its_own_erc20_share_surface() -> None:
    # a real ERC-4626 vault exposes ALL 6 TOKEN signatures too (shares are an ERC20) —
    # VAULT must still win because it has more of its OWN distinguishing signatures.
    abi = [
        _fn("asset"),
        _fn("totalAssets"),
        _fn("convertToShares", "uint256"),
        _fn("convertToAssets", "uint256"),
        _fn("deposit", "uint256", "address"),
        _fn("mint", "uint256", "address"),
        _fn("withdraw", "uint256", "address", "address"),
        _fn("redeem", "uint256", "address", "address"),
        # inherited ERC20 surface (full TOKEN group overlap):
        _fn("transfer", "address", "uint256"),
        _fn("balanceOf", "address"),
        _fn("totalSupply"),
        _fn("decimals"),
        _fn("symbol"),
        _fn("approve", "address", "uint256"),
    ]
    assert classify(abi) == NodeType.VAULT


def test_plain_token_is_not_misclassified_as_vault() -> None:
    # totalSupply()/decimals() alone (both plain ERC20 AND coincidentally vault-adjacent
    # words) must not tip a plain token into VAULT.
    abi = [
        _fn("transfer", "address", "uint256"),
        _fn("balanceOf", "address"),
        _fn("totalSupply"),
        _fn("decimals"),
        _fn("symbol"),
        _fn("approve", "address", "uint256"),
    ]
    assert classify(abi) == NodeType.TOKEN


def test_picks_highest_scoring_group_on_partial_overlap() -> None:
    # only 1 of 2 oracle signatures + all 5 token signatures present -> token wins
    abi = [
        _fn("transfer", "address", "uint256"),
        _fn("balanceOf", "address"),
        _fn("totalSupply"),
        _fn("symbol"),
        _fn("approve", "address", "uint256"),
        _fn("latestRoundData"),
    ]
    assert classify(abi) == NodeType.TOKEN


def test_decimals_alone_never_tips_a_real_oracle_into_token() -> None:
    # real bug found on Tremolo's IChainlinkAggregator: a plain Chainlink-shaped price-feed
    # interface exposing only decimals()+latestRoundData() used to tie TOKEN 1-1 against
    # ORACLE and TOKEN silently won every tie by being declared first in the signature-group
    # dict. decimals() isn't token-specific - it must never be able to out-score a dedicated
    # ORACLE match.
    abi = [_fn("decimals"), _fn("latestRoundData")]
    assert classify(abi) == NodeType.ORACLE


def test_classifies_erc6909_multitoken_shape() -> None:
    # EIP-6909 multi-token accounting (Tremolo's VarianceMarket via solady's ERC6909):
    # names overlap with ERC-20 (transfer/approve/balanceOf/...), but every one of them
    # takes an extra `id` parameter - a genuinely different signature, previously UNKNOWN.
    abi = [
        _fn("balanceOf", "address", "uint256"),
        _fn("allowance", "address", "address", "uint256"),
        _fn("isOperator", "address", "address"),
        _fn("transfer", "address", "uint256", "uint256"),
        _fn("transferFrom", "address", "address", "uint256", "uint256"),
        _fn("approve", "address", "uint256", "uint256"),
        _fn("setOperator", "address", "bool"),
    ]
    assert classify(abi) == NodeType.TOKEN
