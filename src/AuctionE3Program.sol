// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IInterfoldRead} from "./interfaces/IInterfoldRead.sol";
import {
    IAuctionInputVerifier,
    IAuctionOpenVmVerifier,
    IAuctionDataAvailabilityVerifier,
    IAuctionPoseidon,
    IAuctionInterfoldProgram,
    IAuctionInterfoldAvailability
} from "./interfaces/IAuctionProofs.sol";

interface IAuctionProgramEscrow {
    function seller() external view returns (address);
    function nft() external view returns (address);
    function tokenId() external view returns (uint256);
    function collateralWei() external view returns (uint256);
    function tickWei() external view returns (uint256);
    function priceLevels() external view returns (uint16);
    function maxBidders() external view returns (uint32);
    function resultSource() external view returns (address);
}

/// @notice Immutable admission and computation gate for one second-price auction.
/// @dev This contract is NOT a proof system. It cannot run without reviewed secure-8192
/// input and application-specific OpenVM verifiers, a real DA verifier and Poseidon.
/// No verifier setters, administrator input bypass or plaintext result setters exist.
contract AuctionE3Program {
    bytes32 public constant ENCRYPTION_SCHEME_ID = keccak256("fhe.rs:BFV");
    uint256 public constant SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 public constant MAX_ENVELOPE_BYTES = 16_384;
    uint8 public constant REQUIRED_PARAM_SET = 2;

    struct Configuration {
        address interfold;
        address auctionEscrow;
        address resultSource;
        address inputVerifier;
        address receiptVerifier;
        address availabilityVerifier;
        address poseidon;
        bytes32 paramsHash;
        bytes32 inputCircuitId;
        bytes32 imageId;
        uint64 biddingEnds;
        uint64 settlementDeadline;
    }

    struct Envelope {
        uint8 version;
        bytes32 ciphertextHash;
        bytes inputProof;
        bytes availabilityProof;
    }

    struct Admission {
        bytes32 context;
        uint32 index;
        address bidder;
        bytes encoded;
        bytes32 commitment;
    }

    IInterfoldRead public immutable interfold;
    address public immutable auctionEscrow;
    address public immutable resultSource;
    IAuctionInputVerifier public immutable inputVerifier;
    IAuctionOpenVmVerifier public immutable receiptVerifier;
    IAuctionDataAvailabilityVerifier public immutable availabilityVerifier;
    IAuctionPoseidon public immutable poseidon;
    bytes32 public immutable paramsHash;
    bytes32 public immutable inputCircuitId;
    bytes32 public immutable imageId;
    uint64 public immutable biddingEnds;
    uint64 public immutable settlementDeadline;
    uint32 public immutable maxBidders;
    uint16 public immutable priceLevels;
    bytes32 public immutable inputVerifierCodeHash;
    bytes32 public immutable receiptVerifierCodeHash;
    bytes32 public immutable availabilityVerifierCodeHash;
    bytes32 public immutable poseidonCodeHash;

    bool public initialized;
    uint256 public initializedE3Id;
    mapping(uint256 => bytes32) public auctionContext;
    mapping(uint256 => bytes32) public inputRoot;
    mapping(uint256 => uint256) public bidCount;
    mapping(uint256 => bytes32) public computeInputRoot;
    mapping(uint256 => mapping(uint256 => uint256)) public inputLeaves;
    mapping(uint256 => mapping(address => bool)) public admittedBidder;

    error InvalidConfiguration();
    error Unauthorized();
    error AlreadyInitialized();
    error InvalidComputation();
    error InvalidInput();
    error InvalidInputProof();
    error InvalidAvailability();
    error InvalidComputeProof();
    error DependencyChanged();

    event AuctionConfigured(uint256 indexed e3Id, bytes32 indexed context, bytes32 paramsHash);
    event InputPublished(
        uint256 indexed e3Id,
        uint256 indexed index,
        address indexed bidder,
        bytes envelope,
        bytes32 ciphertextCommitment,
        bytes32 ciphertextHash,
        uint32 availabilityBlock,
        uint128 availabilityLeaf,
        bytes32 inputRoot,
        bytes32 computeInputRoot
    );

    constructor(Configuration memory c) {
        if (
            c.interfold.code.length == 0 || c.auctionEscrow.code.length == 0 || c.resultSource.code.length == 0
                || c.inputVerifier.code.length == 0 || c.receiptVerifier.code.length == 0
                || c.availabilityVerifier.code.length == 0 || c.poseidon.code.length == 0 || c.paramsHash == 0
                || c.inputCircuitId == 0 || c.imageId == 0 || c.biddingEnds <= block.timestamp
                || c.settlementDeadline <= c.biddingEnds
        ) revert InvalidConfiguration();
        IAuctionProgramEscrow escrow = IAuctionProgramEscrow(c.auctionEscrow);
        uint32 limit = escrow.maxBidders();
        uint16 levels = escrow.priceLevels();
        if (limit == 0 || limit > 32 || levels < 2 || escrow.resultSource() != c.resultSource) {
            revert InvalidConfiguration();
        }
        if (
            IAuctionInputVerifier(c.inputVerifier).circuitId() != c.inputCircuitId
                || IAuctionOpenVmVerifier(c.receiptVerifier).imageId() != c.imageId
        ) revert InvalidConfiguration();
        interfold = IInterfoldRead(c.interfold);
        auctionEscrow = c.auctionEscrow;
        resultSource = c.resultSource;
        inputVerifier = IAuctionInputVerifier(c.inputVerifier);
        receiptVerifier = IAuctionOpenVmVerifier(c.receiptVerifier);
        availabilityVerifier = IAuctionDataAvailabilityVerifier(c.availabilityVerifier);
        poseidon = IAuctionPoseidon(c.poseidon);
        paramsHash = c.paramsHash;
        inputCircuitId = c.inputCircuitId;
        imageId = c.imageId;
        biddingEnds = c.biddingEnds;
        settlementDeadline = c.settlementDeadline;
        maxBidders = limit;
        priceLevels = levels;
        inputVerifierCodeHash = c.inputVerifier.codehash;
        receiptVerifierCodeHash = c.receiptVerifier.codehash;
        availabilityVerifierCodeHash = c.availabilityVerifier.codehash;
        poseidonCodeHash = c.poseidon.codehash;
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == 0x01ffc9a7 || interfaceId == type(IAuctionInterfoldProgram).interfaceId
            || interfaceId == type(IAuctionInterfoldAvailability).interfaceId;
    }

    /// @notice Interfold stores the provisional request before calling this hook.
    /// @dev One program instance serves one E3 only. The context fixes both deadlines.
    function validate(
        uint256 e3Id,
        uint256,
        bytes calldata e3ProgramParams,
        bytes calldata,
        bytes calldata customParams
    ) external returns (bytes32) {
        if (msg.sender != address(interfold)) revert Unauthorized();
        if (initialized) revert AlreadyInitialized();
        _checkDependencies();
        IInterfoldRead.E3 memory e3 = interfold.getE3(e3Id);
        bytes32 context = contextFor(e3Id);
        if (
            e3.e3Program != address(this) || e3.requester != IAuctionProgramEscrow(auctionEscrow).seller()
                || e3.paramSet != REQUIRED_PARAM_SET || e3.inputWindow[0] >= biddingEnds
                || e3.inputWindow[1] != biddingEnds || biddingEnds <= block.timestamp
                || keccak256(e3ProgramParams) != paramsHash || keccak256(customParams) != keccak256(abi.encode(context))
                || keccak256(e3.customParams) != keccak256(customParams)
        ) revert InvalidComputation();
        initialized = true;
        initializedE3Id = e3Id;
        auctionContext[e3Id] = context;
        inputRoot[e3Id] = context;
        emit AuctionConfigured(e3Id, context, paramsHash);
        return ENCRYPTION_SCHEME_ID;
    }

    function contextFor(uint256 e3Id) public view returns (bytes32) {
        IAuctionProgramEscrow escrow = IAuctionProgramEscrow(auctionEscrow);
        return keccak256(
            abi.encode(
                block.chainid,
                auctionEscrow,
                escrow.seller(),
                escrow.nft(),
                escrow.tokenId(),
                escrow.collateralWei(),
                escrow.tickWei(),
                priceLevels,
                maxBidders,
                e3Id,
                biddingEnds,
                settlementDeadline
            )
        );
    }

    /// @notice Called atomically by the immutable result source during escrow.submitBid.
    function publishInput(uint256 e3Id, bytes memory data) external {
        if (msg.sender != resultSource) revert Unauthorized();
        _checkDependencies();
        IInterfoldRead.E3 memory e3 = _activeE3(e3Id);
        if (interfold.getE3Stage(e3Id) != 3 || block.timestamp < e3.inputWindow[0] || block.timestamp >= biddingEnds) {
            revert InvalidComputation();
        }
        Admission memory a;
        (a.context, a.index, a.bidder, a.encoded, a.commitment) =
            abi.decode(data, (bytes32, uint32, address, bytes, bytes32));
        if (
            a.context != auctionContext[e3Id] || a.index != bidCount[e3Id] || a.index >= maxBidders
                || a.bidder == address(0) || admittedBidder[e3Id][a.bidder] || a.encoded.length == 0
                || a.encoded.length > MAX_ENVELOPE_BYTES || a.commitment == 0 || uint256(a.commitment) >= SCALAR_FIELD
        ) revert InvalidInput();
        (bytes32 ciphertextHash, IAuctionDataAvailabilityVerifier.DataReference memory receipt) =
            _verifyInput(e3Id, a, e3.committeePublicKey);
        _recordInput(e3Id, a, ciphertextHash, receipt);
    }

    function _verifyInput(uint256 e3Id, Admission memory a, bytes32 committeePublicKey)
        private
        view
        returns (bytes32, IAuctionDataAvailabilityVerifier.DataReference memory)
    {
        Envelope memory envelope;
        (envelope.version, envelope.ciphertextHash, envelope.inputProof, envelope.availabilityProof) =
            abi.decode(a.encoded, (uint8, bytes32, bytes, bytes));
        if (
            envelope.version != 1 || envelope.ciphertextHash == 0 || envelope.inputProof.length == 0
                || envelope.availabilityProof.length == 0
                || keccak256(a.encoded)
                    != keccak256(
                        abi.encode(
                            envelope.version, envelope.ciphertextHash, envelope.inputProof, envelope.availabilityProof
                        )
                    )
        ) revert InvalidInput();
        IAuctionInputVerifier.Statement memory statement = IAuctionInputVerifier.Statement({
            chainId: block.chainid,
            program: address(this),
            interfold: address(interfold),
            auction: auctionEscrow,
            context: a.context,
            e3Id: e3Id,
            committeePublicKey: committeePublicKey,
            paramsHash: paramsHash,
            slot: a.index,
            bidder: a.bidder,
            maxTick: uint256(priceLevels) - 1,
            ciphertextHash: envelope.ciphertextHash,
            ciphertextCommitment: a.commitment
        });
        if (!inputVerifier.verify(envelope.inputProof, statement)) revert InvalidInputProof();
        return (envelope.ciphertextHash, _verifyAvailability(envelope.ciphertextHash, envelope.availabilityProof));
    }

    function _recordInput(
        uint256 e3Id,
        Admission memory a,
        bytes32 ciphertextHash,
        IAuctionDataAvailabilityVerifier.DataReference memory receipt
    ) private {
        bytes32 envelopeHash = keccak256(a.encoded);
        bytes32 nextRoot =
            keccak256(abi.encode(inputRoot[e3Id], uint256(a.index), a.bidder, envelopeHash, a.commitment));
        inputLeaves[e3Id][a.index] = inputLeaf(a.context, a.index, a.bidder, envelopeHash, a.commitment);
        uint256 count = uint256(a.index) + 1;
        bidCount[e3Id] = count;
        inputRoot[e3Id] = nextRoot;
        admittedBidder[e3Id][a.bidder] = true;
        bytes32 merkleRoot = _merkleRoot(e3Id, count);
        computeInputRoot[e3Id] = merkleRoot;
        emit InputPublished(
            e3Id,
            a.index,
            a.bidder,
            a.encoded,
            a.commitment,
            ciphertextHash,
            receipt.blockNumber,
            receipt.leafIndex,
            nextRoot,
            merkleRoot
        );
    }

    /// @notice The custom guest must reconstruct this exact leaf from authenticated input metadata.
    function inputLeaf(bytes32 context, uint256 index, address bidder, bytes32 envelopeHash, bytes32 commitment)
        public
        pure
        returns (uint256)
    {
        return uint256(keccak256(abi.encode(context, index, bidder, envelopeHash, commitment))) % SCALAR_FIELD;
    }

    /// @notice Verify Interfold's exact nine-word OpenVM journal against this complete admitted tree.
    function verify(uint256 e3Id, bytes32 outputHash, bytes32 outputCommitment, bytes memory proof)
        external
        view
        returns (bool)
    {
        if (msg.sender != address(interfold)) revert Unauthorized();
        _checkDependencies();
        IInterfoldRead.E3 memory e3 = _activeE3(e3Id);
        if (
            interfold.getE3Stage(e3Id) != 3 || block.timestamp < biddingEnds || block.timestamp >= settlementDeadline
                || bidCount[e3Id] == 0 || outputHash == 0 || outputCommitment == 0
                || uint256(outputCommitment) >= SCALAR_FIELD
        ) revert InvalidComputeProof();
        (bytes memory seal, bytes32 provenParamsHash, bytes32 provenRoot) = abi.decode(proof, (bytes, bytes32, bytes32));
        if (seal.length == 0 || provenParamsHash != paramsHash || provenRoot != computeInputRoot[e3Id]) {
            revert InvalidComputeProof();
        }
        bytes32 journalDigest = sha256(
            abi.encode(
                bytes32(block.chainid),
                bytes32(uint256(uint160(address(interfold)))),
                bytes32(e3Id),
                ENCRYPTION_SCHEME_ID,
                e3.committeePublicKey,
                outputHash,
                outputCommitment,
                paramsHash,
                provenRoot
            )
        );
        receiptVerifier.verify(seal, imageId, journalDigest);
        return true;
    }

    function verifyDataAvailability(bytes32 expectedContentHash, bytes calldata proof)
        external
        view
        returns (IAuctionDataAvailabilityVerifier.DataReference memory)
    {
        _checkDependencies();
        return _verifyAvailability(expectedContentHash, proof);
    }

    function _verifyAvailability(bytes32 hash, bytes memory proof)
        private
        view
        returns (IAuctionDataAvailabilityVerifier.DataReference memory receipt)
    {
        if (hash == 0 || proof.length == 0) revert InvalidAvailability();
        receipt = availabilityVerifier.verifyDataAvailability(hash, proof);
        // The production Avail path must return real bridge-finalized coordinates.
        if (receipt.contentHash != hash || receipt.blockNumber == 0) revert InvalidAvailability();
    }

    function _activeE3(uint256 e3Id) private view returns (IInterfoldRead.E3 memory e3) {
        if (!initialized || e3Id != initializedE3Id) revert InvalidComputation();
        e3 = interfold.getE3(e3Id);
        if (
            e3.e3Program != address(this) || e3.paramSet != REQUIRED_PARAM_SET
                || e3.encryptionSchemeId != ENCRYPTION_SCHEME_ID || e3.committeePublicKey == 0
                || e3.requester != IAuctionProgramEscrow(auctionEscrow).seller() || e3.inputWindow[1] != biddingEnds
                || keccak256(e3.customParams) != keccak256(abi.encode(auctionContext[e3Id]))
        ) revert InvalidComputation();
    }

    /// @dev At most 32 leaves. Rebuild the minimal-depth, zero-padded upstream IMT.
    function _merkleRoot(uint256 e3Id, uint256 count) private view returns (bytes32) {
        uint256 width = 2;
        while (width < count) width *= 2;
        uint256[] memory nodes = new uint256[](width);
        for (uint256 i; i < count; ++i) {
            nodes[i] = inputLeaves[e3Id][i];
        }
        while (width > 1) {
            for (uint256 i; i < width; i += 2) {
                uint256 value = poseidon.hash([nodes[i], nodes[i + 1]]);
                if (value >= SCALAR_FIELD) revert InvalidInput();
                nodes[i / 2] = value;
            }
            width /= 2;
        }
        return bytes32(nodes[0]);
    }

    /// @dev Proxy implementations require separate review; a proxy's codehash is not its logic hash.
    function _checkDependencies() private view {
        if (
            address(inputVerifier).codehash != inputVerifierCodeHash
                || address(receiptVerifier).codehash != receiptVerifierCodeHash
                || address(availabilityVerifier).codehash != availabilityVerifierCodeHash
                || address(poseidon).codehash != poseidonCodeHash || inputVerifier.circuitId() != inputCircuitId
                || receiptVerifier.imageId() != imageId
        ) revert DependencyChanged();
    }
}
