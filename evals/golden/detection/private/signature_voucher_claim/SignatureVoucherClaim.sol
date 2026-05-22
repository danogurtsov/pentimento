// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SignatureVoucherClaim
/// @notice An admin signs off-chain vouchers authorizing a one-time ETH payout to a
/// recipient; anyone holding a valid signature can redeem it on-chain by calling claim().
contract SignatureVoucherClaim {
    address public immutable admin;

    event Claimed(address indexed recipient, uint256 amount, uint256 voucherId);

    constructor(address admin_) {
        admin = admin_;
    }

    receive() external payable {}

    function claim(address recipient, uint256 amount, uint256 voucherId, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encodePacked(recipient, amount, voucherId, address(this)));
        address signer = _recover(digest, signature);
        require(signer == admin, "bad signature");

        // THE BUG: no per-voucher "used" tracking of any kind (no mapping keyed by
        // voucherId or by the signature/digest itself). A valid voucher signature remains
        // valid forever and can be submitted an unlimited number of times, draining the
        // contract far beyond what the admin ever authorized for that single voucher.
        (bool ok, ) = recipient.call{value: amount}("");
        require(ok, "transfer failed");
        emit Claimed(recipient, amount, voucherId);
    }

    function _recover(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        require(signature.length == 65, "bad signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        bytes32 ethSignedDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        return ecrecover(ethSignedDigest, v, r, s);
    }
}
