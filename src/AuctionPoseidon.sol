// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {PoseidonT3} from "./vendor/PoseidonT3.sol";
import {IAuctionPoseidon} from "./interfaces/IAuctionProofs.sol";

/// @notice Non-upgradeable Circom-compatible BN254 Poseidon hash with two inputs.
/// @dev The vendored hash is inlined; there is no delegatecall or replaceable library.
contract AuctionPoseidon is IAuctionPoseidon {
    function hash(uint256[2] calldata input) external pure returns (uint256) {
        return PoseidonT3.hash(input);
    }
}
