// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IAuctionResultSource} from "./SealedBidAuction.sol";
import {IInterfoldRead, IAuctionE3ProgramRead} from "./interfaces/IInterfoldRead.sol";

interface IAuctionConfigurationRead {
    function seller() external view returns (address);
    function biddingEnds() external view returns (uint64);
}

/// @notice Fail-closed boundary between auction escrow and Interfold's published E3 result.
/// @dev Initially disabled. The deployer may pin ONE registered, reviewed program. There is
/// no mock, fallback signer, result setter, or ability to replace that program afterward.
/// This contract authenticates protocol results; it does not implement the missing E3 program.
contract InterfoldResultSource is IAuctionResultSource {
    IInterfoldRead public immutable interfold;
    address public immutable binder;
    uint8 public constant REQUIRED_PARAM_SET = 2; // secure-8192
    bytes32 public constant BFV_SCHEME = keccak256("fhe.rs:BFV");
    address public program;

    error Unauthorized();
    error InvalidProgram();
    error AlreadyBound();
    error InputAdmissionFailed();
    event ProgramBound(address indexed program, address indexed escrow);

    constructor(address protocol, address programBinder) {
        require(protocol.code.length != 0 && programBinder != address(0), "invalid configuration");
        interfold = IInterfoldRead(protocol);
        binder = programBinder;
    }

    /// @notice Operational trust decision: review the program/circuits before this one-time call.
    /// Registration alone does not establish that a program implements a secure auction.
    function bindProgram(address candidate) external {
        if (msg.sender != binder) revert Unauthorized();
        if (program != address(0)) revert AlreadyBound();
        if (candidate.code.length == 0 || !interfold.e3Programs(candidate)) revert InvalidProgram();
        address escrow = IAuctionE3ProgramRead(candidate).auctionEscrow();
        if (escrow.code.length == 0) revert InvalidProgram();
        program = candidate;
        emit ProgramBound(candidate, escrow);
    }

    function isReady() external view returns (bool) {
        return program != address(0) && interfold.e3Programs(program) && !interfold.requestsPaused();
    }

    function validateAuction(bytes32 context, uint256 e3Id, uint64 end) public view returns (bool) {
        if (
            program == address(0) || !interfold.e3Programs(program) || interfold.requestsPaused()
                || interfold.getE3Stage(e3Id) != 3
        ) return false;
        IAuctionE3ProgramRead p = IAuctionE3ProgramRead(program);
        IInterfoldRead.E3 memory e3 = interfold.getE3(e3Id);
        return p.auctionEscrow() == msg.sender && p.auctionContext(e3Id) == context && e3.e3Program == program
            && e3.paramSet == REQUIRED_PARAM_SET && e3.encryptionSchemeId == BFV_SCHEME
            && e3.committeePublicKey != bytes32(0) && e3.requester == IAuctionConfigurationRead(msg.sender).seller()
            && e3.inputWindow[0] <= block.timestamp && e3.inputWindow[1] == end
            && keccak256(e3.customParams) == keccak256(abi.encode(context));
    }

    /// @notice Admit a bid through the pinned program before collateral is accepted.
    /// @dev Any failed proof, unavailable ciphertext or mismatched transcript reverts the
    /// complete submission, including the escrow's deposit and tentative state changes.
    /// The program must authorize only this source for publishInput.
    function publishBid(
        bytes32 context,
        uint256 e3Id,
        uint32 index,
        address bidder,
        bytes calldata envelope,
        bytes32 commitment,
        bytes32 nextInputRoot
    ) external {
        if (program == address(0)) revert InputAdmissionFailed();
        IAuctionE3ProgramRead p = IAuctionE3ProgramRead(program);
        if (
            p.auctionEscrow() != msg.sender
                || !validateAuction(context, e3Id, IAuctionConfigurationRead(msg.sender).biddingEnds())
                || p.bidCount(e3Id) != index
                || keccak256(abi.encode(p.inputRoot(e3Id), uint256(index), bidder, keccak256(envelope), commitment))
                    != nextInputRoot
        ) {
            revert InputAdmissionFailed();
        }
        p.publishInput(e3Id, abi.encode(context, index, bidder, envelope, commitment));
        if (p.inputRoot(e3Id) != nextInputRoot || p.bidCount(e3Id) != uint256(index) + 1) {
            revert InputAdmissionFailed();
        }
    }

    /// @param result ABI-encoded uint256[] ticks in bid order.
    /// @dev Protocol plaintext uses polynomial coefficients serialized as little-endian u64s.
    /// Each bidder occupies one coefficient; all remaining coefficients must be zero.
    function verifyResult(
        bytes32 context,
        uint256 e3Id,
        bytes32 expectedInputRoot,
        uint256 count,
        bytes calldata result
    ) external view returns (bool) {
        if (program == address(0) || count > 32 || interfold.getE3Stage(e3Id) != 5) return false;
        IAuctionE3ProgramRead p = IAuctionE3ProgramRead(program);
        if (
            p.auctionEscrow() != msg.sender || p.auctionContext(e3Id) != context
                || p.inputRoot(e3Id) != expectedInputRoot || p.bidCount(e3Id) != count
        ) return false;
        IInterfoldRead.E3 memory e3 = interfold.getE3(e3Id);
        if (
            e3.e3Program != program || e3.paramSet != REQUIRED_PARAM_SET || e3.encryptionSchemeId != BFV_SCHEME
                || e3.committeePublicKey == bytes32(0) || e3.ciphertextOutput == bytes32(0)
                || e3.requester != IAuctionConfigurationRead(msg.sender).seller()
                || e3.inputWindow[1] != IAuctionConfigurationRead(msg.sender).biddingEnds()
                || keccak256(e3.customParams) != keccak256(abi.encode(context))
        ) return false;

        uint256[] memory ticks = abi.decode(result, (uint256[]));
        // v0.19.0's decryption proof exposes exactly 50 u64 coefficients (400 bytes),
        // even for secure-8192. See upstream BfvDecryptionVerifier.MESSAGE_COEFFS_COUNT.
        if (ticks.length != count || e3.plaintextOutput.length != 50 * 8) return false;
        for (uint256 i; i < 50; ++i) {
            uint64 value;
            for (uint256 j; j < 8; ++j) {
                value |= uint64(uint8(e3.plaintextOutput[i * 8 + j])) << uint64(j * 8);
            }
            if (i < count ? value != ticks[i] : value != 0) return false;
        }
        return true;
    }
}
