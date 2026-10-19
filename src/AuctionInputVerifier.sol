// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IAuctionInputVerifier, IAuctionOpenVmVerifier} from "./interfaces/IAuctionProofs.sol";

/// @dev The pinned Barretenberg EVM ZK verifier generated for auction_input.
interface IAuctionNoirVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}

/// @notice Compose private sparse BFV encryption with public serialized-byte binding.
/// @dev Deploy only with the actual generated immutable Noir verifier and an immutable
/// OpenVM receipt verifier for the input-binding guest. Test doubles are not a release.
/// The private proof authenticates SAFE key/ciphertext commitments; the byte receipt
/// authenticates the SAME ciphertext commitment, exact ciphertext hash and all statement words.
contract AuctionInputVerifier is IAuctionInputVerifier {
    error InvalidConfiguration();
    error NoncanonicalProof();

    bytes32 private constant DOMAIN = keccak256("interfold.auction.input.secure8192.composed.v1");
    uint256 private constant FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    bytes32 private constant PARAMS_HASH = 0x1b2620f6a5919d5ee19a51f34026369816f479efd0404b56585ad37d31c52317;

    IAuctionNoirVerifier public immutable encryptionVerifier;
    IAuctionOpenVmVerifier public immutable bindingVerifier;
    bytes32 public immutable encryptionVerifierCodeHash;
    bytes32 public immutable bindingVerifierCodeHash;
    bytes32 public immutable encryptionAcirSha256;
    bytes32 public immutable bindingImageId;
    bytes32 public immutable circuitId;

    constructor(address encryption_, address binding_, bytes32 acirSha256_, bytes32 imageId_) {
        if (encryption_.code.length == 0 || binding_.code.length == 0 || acirSha256_ == 0 || imageId_ == 0) {
            revert InvalidConfiguration();
        }
        if (IAuctionOpenVmVerifier(binding_).imageId() != imageId_) revert InvalidConfiguration();
        encryptionVerifier = IAuctionNoirVerifier(encryption_);
        bindingVerifier = IAuctionOpenVmVerifier(binding_);
        encryptionVerifierCodeHash = encryption_.codehash;
        bindingVerifierCodeHash = binding_.codehash;
        encryptionAcirSha256 = acirSha256_;
        bindingImageId = imageId_;
        circuitId = keccak256(abi.encode(DOMAIN, encryption_.codehash, binding_.codehash, acirSha256_, imageId_));
    }

    /// @param proof Canonical abi.encode(bytes encryptionProof, bytes bindingSeal).
    function verify(bytes calldata proof, Statement calldata statement) external view returns (bool) {
        if (address(encryptionVerifier).codehash != encryptionVerifierCodeHash
            || address(bindingVerifier).codehash != bindingVerifierCodeHash
            || bindingVerifier.imageId() != bindingImageId) return false;
        if (statement.chainId != 11155111 || statement.paramsHash != PARAMS_HASH
            || statement.slot >= 32 || statement.maxTick != 100
            || statement.program == address(0) || statement.interfold == address(0)
            || statement.auction == address(0) || statement.bidder == address(0)
            || uint256(statement.committeePublicKey) >= FIELD
            || uint256(statement.ciphertextCommitment) >= FIELD) return false;
        (bytes memory encryptionProof, bytes memory bindingSeal) = abi.decode(proof, (bytes, bytes));
        if (keccak256(proof) != keccak256(abi.encode(encryptionProof, bindingSeal))) revert NoncanonicalProof();
        if (encryptionProof.length == 0 || bindingSeal.length == 0) return false;

        bytes memory encoded = abi.encode(statement);
        bytes32[] memory publicInputs = new bytes32[](26);
        // Canonical u128 high/low limbs preserve every bit of each ABI word.
        for (uint256 i; i < 13; ++i) {
            uint256 value;
            assembly ("memory-safe") { value := mload(add(add(encoded, 32), mul(i, 32))) }
            publicInputs[2 * i] = bytes32(value >> 128);
            publicInputs[2 * i + 1] = bytes32(uint256(uint128(value)));
        }
        try encryptionVerifier.verify(encryptionProof, publicInputs) returns (bool valid) {
            if (!valid) return false;
        } catch { return false; }
        try bindingVerifier.verify(bindingSeal, bindingImageId, sha256(encoded)) {
            return true;
        } catch { return false; }
    }
}
