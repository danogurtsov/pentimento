// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title LinearVestingEscrow
/// @notice Linear token vesting with an admin-revocable schedule (e.g. employee token
/// grants that can be clawed back if the employee leaves before fully vesting).
contract LinearVestingEscrow {
    IERC20 public immutable token;
    address public admin;

    struct Schedule {
        uint256 totalAmount; // total tokens granted, shrinks once sweepUnvested() runs
        uint256 startTime;
        uint256 duration;
        uint256 claimed;
        uint256 revokedAt; // 0 if not revoked
    }

    mapping(address => Schedule) public schedules;

    event Granted(address indexed beneficiary, uint256 amount, uint256 startTime, uint256 duration);
    event Claimed(address indexed beneficiary, uint256 amount);
    event Revoked(address indexed beneficiary, uint256 vestedAtRevoke);
    event Swept(address indexed beneficiary, uint256 amount);

    modifier onlyAdmin() {
        require(msg.sender == admin, "not admin");
        _;
    }

    constructor(address token_) {
        token = IERC20(token_);
        admin = msg.sender;
    }

    function grant(address beneficiary, uint256 amount, uint256 startTime, uint256 duration) external onlyAdmin {
        require(schedules[beneficiary].totalAmount == 0, "already granted");
        require(duration > 0, "zero duration");
        schedules[beneficiary] = Schedule(amount, startTime, duration, 0, 0);
        emit Granted(beneficiary, amount, startTime, duration);
    }

    /// @notice Tokens vested so far, out of the schedule's current totalAmount. Vesting
    /// freezes at the moment of revocation instead of continuing to the present.
    function vestedAmount(address beneficiary) public view returns (uint256) {
        Schedule memory s = schedules[beneficiary];
        if (s.totalAmount == 0) return 0;

        uint256 elapsed;
        if (s.revokedAt != 0) {
            elapsed = s.revokedAt - s.startTime;
        } else if (block.timestamp < s.startTime) {
            return 0;
        } else {
            elapsed = block.timestamp - s.startTime;
        }

        if (elapsed >= s.duration) {
            return s.totalAmount;
        }
        return (s.totalAmount * elapsed) / s.duration;
    }

    function claimable(address beneficiary) public view returns (uint256) {
        return vestedAmount(beneficiary) - schedules[beneficiary].claimed;
    }

    function claim() external {
        uint256 amount = claimable(msg.sender);
        require(amount > 0, "nothing to claim");
        schedules[msg.sender].claimed += amount;
        require(token.transfer(msg.sender, amount), "transfer failed");
        emit Claimed(msg.sender, amount);
    }

    /// @notice Admin revokes a schedule. The beneficiary keeps whatever had already vested
    /// up to this moment; nothing vests afterward.
    function revoke(address beneficiary) external onlyAdmin {
        Schedule storage s = schedules[beneficiary];
        require(s.totalAmount > 0, "no schedule");
        require(s.revokedAt == 0, "already revoked");
        s.revokedAt = block.timestamp;
        emit Revoked(beneficiary, vestedAmount(beneficiary));
    }

    /// @notice Admin sweeps back whatever never vested, once a schedule is revoked.
    function sweepUnvested(address beneficiary) external onlyAdmin {
        Schedule storage s = schedules[beneficiary];
        require(s.revokedAt != 0, "not revoked");

        uint256 unvested = s.totalAmount - vestedAmount(beneficiary);
        s.totalAmount = vestedAmount(beneficiary);

        require(token.transfer(admin, unvested), "sweep failed");
        emit Swept(beneficiary, unvested);
    }
}
