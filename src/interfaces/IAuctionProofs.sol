// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice Public statement the secure-8192 sparse-bid circuit MUST authenticate.
/// @dev This is an integration ABI, not an implementation of the circuit. Generated
/// verifier adapters must split 256-bit digests into field-safe limbs without truncation.
interface IAuctionInputVerifier {
    struct Statement {
        uint256 chainId;
        address program;
        address interfold;
        address auction;
        bytes32 context;
        uint256 e3Id;
        bytes32 committeePublicKey;
        bytes32 paramsHash;
        uint256 slot;
        address bidder;
        uint256 maxTick;
        bytes32 ciphertextHash;
        bytes32 ciphertextCommitment;
    }

    function circuitId() external view returns (bytes32);
    function verify(bytes calldata proof, Statement calldata statement) external view returns (bool);
}

/// @notice Exact receipt-verifier ABI used by Interfold v0.19.0.
interface IAuctionOpenVmVerifier {
    function imageId() external view returns (bytes32);
    function verify(bytes calldata seal, bytes32 imageId_, bytes32 journalDigest) external view;
}

interface IAuctionDataAvailabilityVerifier {
    struct DataReference {
        bytes32 contentHash;
        uint32 blockNumber;
        uint128 leafIndex;
    }

    function verifyDataAvailability(bytes32 expectedContentHash, bytes calldata proof)
        external
        view
        returns (DataReference memory);
}

/// @notice Circom-compatible BN254 Poseidon with two inputs, as upstream's IMT uses.
interface IAuctionPoseidon {
    function hash(uint256[2] calldata input) external view returns (uint256);
}

/// @notice Pinned signatures used by Interfold's ERC165 registration probe.
interface IAuctionInterfoldProgram {
    function validate(uint256, uint256, bytes calldata, bytes calldata, bytes calldata) external returns (bytes32);
    function verify(uint256, bytes32, bytes32, bytes memory) external returns (bool);
    function publishInput(uint256, bytes memory) external;
}

interface IAuctionInterfoldAvailability {
    function verifyDataAvailability(bytes32, bytes calldata)
        external
        view
        returns (IAuctionDataAvailabilityVerifier.DataReference memory);
}
