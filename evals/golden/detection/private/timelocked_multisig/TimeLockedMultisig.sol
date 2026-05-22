// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title TimeLockedMultisig
/// @notice N-of-M multisig: signers propose and approve arbitrary calls; once `threshold`
/// approvals are reached, a timelock `delay` must pass before anyone can execute.
contract TimeLockedMultisig {
    mapping(address => bool) public isSigner;
    uint256 public threshold;
    uint256 public delay;
    address public admin;

    struct Proposal {
        address target;
        uint256 value;
        bytes data;
        uint256 approvals;
        uint256 readyAt; // 0 until threshold is reached
        bool executed;
    }

    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;

    event Proposed(uint256 indexed id, address target, uint256 value);
    event Approved(uint256 indexed id, address indexed signer, uint256 approvals);
    event Executed(uint256 indexed id);

    modifier onlySigner() {
        require(isSigner[msg.sender], "not a signer");
        _;
    }

    constructor(address[] memory signers, uint256 threshold_, uint256 delay_) {
        require(threshold_ > 0 && threshold_ <= signers.length, "bad threshold");
        for (uint256 i = 0; i < signers.length; i++) {
            isSigner[signers[i]] = true;
        }
        threshold = threshold_;
        delay = delay_;
        admin = msg.sender;
    }

    function propose(address target, uint256 value, bytes calldata data) external onlySigner returns (uint256 id) {
        id = proposalCount++;
        Proposal storage p = proposals[id];
        p.target = target;
        p.value = value;
        p.data = data;
    }

    /// @notice Approve a pending proposal. Once enough approvals accumulate, the timelock
    /// clock starts.
    function approve(uint256 id) external onlySigner {
        Proposal storage p = proposals[id];
        require(!p.executed, "already executed");
        p.approvals += 1;
        emit Approved(id, msg.sender, p.approvals);
        if (p.approvals >= threshold && p.readyAt == 0) {
            p.readyAt = block.timestamp + delay;
        }
    }

    function execute(uint256 id) external payable {
        Proposal storage p = proposals[id];
        require(p.readyAt != 0, "not approved yet");
        require(block.timestamp >= p.readyAt, "timelock not elapsed");
        require(!p.executed, "already executed");
        p.executed = true;
        (bool ok, ) = p.target.call{value: p.value}(p.data);
        require(ok, "call failed");
        emit Executed(id);
    }

    receive() external payable {}
}
