// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

/// @notice Read-only ABI subset pinned to Interfold v0.19.0 (c65722fc).
/// @dev The E3 tuple order exactly matches upstream interfaces/IE3.sol.
interface IInterfoldRead {
    struct E3 {
        uint256 seed;
        uint8 committeeSize;
        uint256 requestBlock;
        uint256[2] inputWindow;
        bytes32 encryptionSchemeId;
        address e3Program;
        uint8 paramSet;
        bytes customParams;
        address decryptionVerifier;
        address pkVerifier;
        bytes32 committeePublicKey;
        bytes32 ciphertextOutput;
        bytes plaintextOutput;
        address requester;
        bytes32 ciphertextCommitment;
    }

    function getE3(uint256 e3Id) external view returns (E3 memory);
    function getE3Stage(uint256 e3Id) external view returns (uint8);
    function e3Programs(address program) external view returns (bool);
    function requestsPaused() external view returns (bool);
}

/// @notice Required on-chain ledger of the future verified auction E3 program.
/// @dev Implementations MUST authenticate every bid, its slot/range proof and ciphertext
/// commitment, and bind compute proofs to the same ordered input transcript as the escrow.
interface IAuctionE3ProgramRead {
    function auctionEscrow() external view returns (address);
    function auctionContext(uint256 e3Id) external view returns (bytes32);
    function inputRoot(uint256 e3Id) external view returns (bytes32);
    function bidCount(uint256 e3Id) external view returns (uint256);
    function publishInput(uint256 e3Id, bytes calldata data) external;
}
