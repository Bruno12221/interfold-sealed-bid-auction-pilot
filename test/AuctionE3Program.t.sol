// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {AuctionE3Program} from "../src/AuctionE3Program.sol";
import {AuctionPoseidon} from "../src/AuctionPoseidon.sol";
import {SealedBidAuction} from "../src/SealedBidAuction.sol";
import {InterfoldResultSource} from "../src/InterfoldResultSource.sol";
import {DemoNFT} from "../src/DemoNFT.sol";
import {IInterfoldRead} from "../src/interfaces/IInterfoldRead.sol";
import {
    IAuctionInputVerifier,
    IAuctionOpenVmVerifier,
    IAuctionDataAvailabilityVerifier,
    IAuctionPoseidon,
    IAuctionInterfoldProgram,
    IAuctionInterfoldAvailability
} from "../src/interfaces/IAuctionProofs.sol";

interface ProgramVm {
    function warp(uint256) external;
    function prank(address) external;
    function expectRevert(bytes4) external;
    function expectRevert() external;
    function etch(address, bytes calldata) external;
    function deal(address, uint256) external;
}

/// @dev All dependencies below are TEST DOUBLES. These tests exercise authentication,
/// ABI/journal/transcript binding and rollback; they do not generate or verify real ZK proofs.
contract ProgramTestProtocol is IInterfoldRead {
    E3 private record;
    uint8 public stage = 3;
    mapping(address => bool) public e3Programs;
    bool public requestsPaused;

    function getE3(uint256) external view returns (E3 memory) {
        return record;
    }

    function getE3Stage(uint256) external view returns (uint8) {
        return stage;
    }

    function setRecord(E3 memory value) external {
        record = value;
    }

    function setStage(uint8 value) external {
        stage = value;
    }

    function setRegistered(address value) external {
        e3Programs[value] = true;
    }

    function initialize(AuctionE3Program p, uint256 id, bytes memory params, bytes memory custom) external {
        p.validate(id, 123, params, "", custom);
    }

    function verifyOutput(AuctionE3Program p, uint256 id, bytes32 output, bytes32 commitment, bytes memory proof)
        external
        view
        returns (bool)
    {
        return p.verify(id, output, commitment, proof);
    }
}

/// @dev Real escrow, bridge, auction program, NFT and Poseidon; protocol/proof/DA
/// dependencies remain explicit test doubles. NOT evidence of a real encrypted auction.
contract AuctionE3IntegrationTest {
    ProgramVm private constant vm = ProgramVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    ProgramTestProtocol private protocol;
    ProgramTestInputVerifier private inputVerifier;
    ProgramTestReceiptVerifier private receiptVerifier;
    ProgramTestAvailability private availability;
    AuctionPoseidon private hasher;
    AuctionE3Program private program;
    SealedBidAuction private auction;
    InterfoldResultSource private source;
    DemoNFT private nft;
    IInterfoldRead.E3 private e3;
    bytes32 private context;
    bytes private parameters = hex"81920002";
    uint256 private constant ID = 42;
    uint64 private constant END = 2000;
    uint64 private constant DEADLINE = 3000;
    address private constant SELLER = address(0x5E11);
    address private constant ALICE = address(0xA11CE);
    address private constant BOB = address(0xB0B);
    address private constant CAROL = address(0xCA401);
    uint256 private constant COLLATERAL = 0.001 ether;

    function setUp() public {
        vm.warp(1000);
        protocol = new ProgramTestProtocol();
        inputVerifier = new ProgramTestInputVerifier();
        receiptVerifier = new ProgramTestReceiptVerifier();
        availability = new ProgramTestAvailability();
        hasher = new AuctionPoseidon();
        nft = new DemoNFT();
        vm.prank(SELLER);
        nft.mint();
        source = new InterfoldResultSource(address(protocol), address(this));
        auction = new SealedBidAuction(SELLER, address(nft), 1, COLLATERAL, 0.00001 ether, 101, 3, address(source));
        AuctionE3Program.Configuration memory c = AuctionE3Program.Configuration({
            interfold: address(protocol),
            auctionEscrow: address(auction),
            resultSource: address(source),
            inputVerifier: address(inputVerifier),
            receiptVerifier: address(receiptVerifier),
            availabilityVerifier: address(availability),
            poseidon: address(hasher),
            paramsHash: keccak256(parameters),
            inputCircuitId: inputVerifier.circuitId(),
            imageId: receiptVerifier.imageId(),
            biddingEnds: END,
            settlementDeadline: DEADLINE
        });
        program = new AuctionE3Program(c);
        protocol.setRegistered(address(program));
        source.bindProgram(address(program));
        context = program.contextFor(ID);
        e3.e3Program = address(program);
        e3.requester = SELLER;
        e3.paramSet = 2;
        e3.inputWindow = [uint256(1000), uint256(END)];
        e3.encryptionSchemeId = program.ENCRYPTION_SCHEME_ID();
        e3.committeePublicKey = bytes32(uint256(0xC0FFEE));
        e3.customParams = abi.encode(context);
        protocol.setRecord(e3);
        protocol.initialize(program, ID, parameters, abi.encode(context));
        vm.prank(SELLER);
        nft.approve(address(auction), 1);
        vm.prank(SELLER);
        auction.open(ID, END, DEADLINE);
        vm.deal(ALICE, 1 ether);
        vm.deal(BOB, 1 ether);
        vm.deal(CAROL, 1 ether);
    }

    function _envelope() private pure returns (bytes memory) {
        return abi.encode(uint8(1), keccak256("raw TEST ciphertext"), hex"1234", hex"abcd");
    }

    function _bid(uint32 slot, address bidder) private {
        IAuctionInputVerifier.Statement memory s = IAuctionInputVerifier.Statement({
            chainId: block.chainid,
            program: address(program),
            interfold: address(protocol),
            auction: address(auction),
            context: context,
            e3Id: ID,
            committeePublicKey: e3.committeePublicKey,
            paramsHash: keccak256(parameters),
            slot: slot,
            bidder: bidder,
            maxTick: 100,
            ciphertextHash: keccak256("raw TEST ciphertext"),
            ciphertextCommitment: bytes32(uint256(99))
        });
        inputVerifier.setExpected(keccak256(abi.encode(s)));
        vm.prank(bidder);
        auction.submitBid{value: COLLATERAL}(slot, _envelope(), bytes32(uint256(99)));
    }

    function _publishTestResult() private {
        bytes32 outputHash = keccak256("output");
        bytes32 outputCommitment = bytes32(uint256(77));
        bytes32 root = program.computeInputRoot(ID);
        bytes32 digest = sha256(
            abi.encode(
                bytes32(block.chainid),
                bytes32(uint256(uint160(address(protocol)))),
                bytes32(ID),
                program.ENCRYPTION_SCHEME_ID(),
                e3.committeePublicKey,
                outputHash,
                outputCommitment,
                keccak256(parameters),
                root
            )
        );
        receiptVerifier.setExpected(digest);
        vm.warp(END);
        require(
            protocol.verifyOutput(
                program, ID, outputHash, outputCommitment, abi.encode(hex"5678", keccak256(parameters), root)
            )
        );
        // Simulate a protocol-verified threshold decryption at the test boundary.
        // No threshold decryption or real proof is performed by this fixture.
        e3.ciphertextOutput = outputHash;
        e3.ciphertextCommitment = outputCommitment;
        e3.plaintextOutput = new bytes(400);
        e3.plaintextOutput[0] = bytes1(uint8(31));
        e3.plaintextOutput[8] = bytes1(uint8(77));
        e3.plaintextOutput[16] = bytes1(uint8(42));
        protocol.setRecord(e3);
        protocol.setStage(5);
    }

    function testRealContractsComposeAndPaySecondPriceUsingTestProofBoundary() public {
        _bid(0, ALICE);
        _bid(1, BOB);
        _bid(2, CAROL);
        require(auction.inputRoot() == program.inputRoot(ID) && program.bidCount(ID) == 3);
        _publishTestResult();
        uint256[] memory ticks = new uint256[](3);
        ticks[0] = 31;
        ticks[1] = 77;
        ticks[2] = 42;
        auction.settle(abi.encode(ticks));
        require(auction.winner() == BOB && nft.ownerOf(1) == BOB);
        require(auction.winningPrice() == 0.00042 ether && auction.winningBid() == 0.00077 ether);
        require(auction.credits(ALICE) == COLLATERAL && auction.credits(CAROL) == COLLATERAL);
        require(auction.credits(BOB) == 0.00058 ether && auction.credits(SELLER) == 0.00042 ether);
        vm.prank(ALICE);
        auction.withdraw(payable(ALICE));
        vm.prank(BOB);
        auction.withdraw(payable(BOB));
        vm.prank(CAROL);
        auction.withdraw(payable(CAROL));
        vm.prank(SELLER);
        auction.withdraw(payable(SELLER));
        require(address(auction).balance == 0 && auction.totalCredits() == 0);
    }

    function testInvalidProofRollsBackEscrowDepositBidAndBothLedgers() public {
        inputVerifier.setReject(true);
        uint256 before = ALICE.balance;
        vm.expectRevert(AuctionE3Program.InvalidInputProof.selector);
        this.bidForTest(0, ALICE);
        require(ALICE.balance == before && address(auction).balance == 0);
        require(auction.bidCount() == 0 && program.bidCount(ID) == 0);
        require(!auction.hasBid(ALICE) && !program.admittedBidder(ID, ALICE));
        require(auction.inputRoot() == context && program.inputRoot(ID) == context);
    }

    function testUnavailableInputRollsBackBothLedgersAndDeposit() public {
        availability.setBadHash(true);
        uint256 before = ALICE.balance;
        // _bid first calls the test verifier to establish its expected statement.
        // Scope the expected revert to the external escrow call via a public trampoline.
        vm.expectRevert(AuctionE3Program.InvalidAvailability.selector);
        this.bidForTest(0, ALICE);
        require(ALICE.balance == before && address(auction).balance == 0);
        require(auction.bidCount() == 0 && program.bidCount(ID) == 0);
        require(auction.inputRoot() == context && program.inputRoot(ID) == context);
    }

    function bidForTest(uint32 slot, address bidder) external {
        require(msg.sender == address(this));
        _bid(slot, bidder);
    }

    function testRealPoseidonMatchesUpstreamZeroVector() public view {
        require(
            hasher.hash([uint256(0), uint256(0)]) == 0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864
        );
    }

    /// @dev Public fixture independently produced by the real secure-8192 Rust
    /// SecureProcess. Proofs are empty format fixtures and are never admitted.
    function testSolidityTranscriptMatchesNativeSecureProcessFixture() public view {
        bytes32 fixtureContext = 0x1111111111111111111111111111111111111111111111111111111111111111;
        bytes32[3] memory ciphertextHashes = [
            bytes32(0x021cb089f69c6220155dc1ebf359220781f30ef4f14d9bcd57a1a49571610ab0),
            bytes32(0x1848cc723b264eaa2424fb640b632815726bc9828e3bb057d1ac7cfe4d7c4710),
            bytes32(0x1dc42a511856639f49f8694ea216ec8f67e30177b427e05810eaed407fcaf74e)
        ];
        bytes32[3] memory commitments = [
            bytes32(0x1659161524d29806073da864b2c6953c0ddaac36f8badf9bd3095f4a24c66528),
            bytes32(0x22e805f7df91f39ede5647f9c2125c057eac65b60b8625d2189d5e28c36eee60),
            bytes32(0x0cbd7a26719523b7d833e17bc72059d1c7e459ffb91f8dc2e6912c384ffeb318)
        ];
        uint256[3] memory expectedLeaves = [
            uint256(0x026afeed9a3cfd4d7610565da28af092d81512ec367db6f86a7b02b9ca6a3b5e),
            uint256(0x219fd8bdc787459ff6880ba7abc39c13d41d686f6c1e7337d87240b617c9a228),
            uint256(0x1d24a235c9f4873058267fe47645b50ce37c58ab0a76108d808fc00c07801de0)
        ];
        bytes32 rolling = fixtureContext;
        for (uint256 i; i < 3; ++i) {
            address bidder = address(uint160(i + 1));
            bytes memory envelope = abi.encode(uint8(1), ciphertextHashes[i], hex"", hex"");
            bytes32 hash = keccak256(envelope);
            require(
                program.inputLeaf(fixtureContext, i, bidder, hash, commitments[i]) == expectedLeaves[i], "leaf differs"
            );
            rolling = keccak256(abi.encode(rolling, i, bidder, hash, commitments[i]));
        }
        require(rolling == 0x4989390d40f2eeecc96254e53e53d061fe1f8b430d4a3461f8e9eb42fd3a8bdc, "rolling differs");
        uint256 left = hasher.hash([expectedLeaves[0], expectedLeaves[1]]);
        uint256 right = hasher.hash([expectedLeaves[2], uint256(0)]);
        require(
            hasher.hash([left, right]) == 0x149df9360b93cdf49b751346cfe010a0a2e82cc2a5ac202d1398568a3031f1f0,
            "Poseidon differs"
        );
    }
}

contract ProgramTestEscrow {
    address public seller = address(0x5E11);
    address public nft = address(0x721);
    uint256 public tokenId = 1;
    uint256 public collateralWei = 0.001 ether;
    uint256 public tickWei = 0.00001 ether;
    uint16 public priceLevels = 101;
    uint32 public maxBidders = 3;
    address public resultSource;

    constructor(address source) {
        resultSource = source;
    }
}

contract ProgramTestSource {
    function publish(AuctionE3Program p, uint256 id, bytes memory data) external {
        p.publishInput(id, data);
    }
}

contract ProgramTestInputVerifier is IAuctionInputVerifier {
    bytes32 public circuitId = keccak256("TEST sparse input circuit");
    bytes32 public expected;
    bool public reject;

    function setExpected(bytes32 value) external {
        expected = value;
    }

    function setReject(bool value) external {
        reject = value;
    }

    function setCircuitId(bytes32 value) external {
        circuitId = value;
    }

    function verify(bytes calldata proof, Statement calldata s) external view returns (bool) {
        return !reject && keccak256(proof) == keccak256(hex"1234") && keccak256(abi.encode(s)) == expected;
    }
}

contract ProgramTestReceiptVerifier is IAuctionOpenVmVerifier {
    bytes32 public imageId = keccak256("TEST auction guest");
    bytes32 public expected;
    bool public reject;

    function setExpected(bytes32 value) external {
        expected = value;
    }

    function setReject(bool value) external {
        reject = value;
    }

    function setImageId(bytes32 value) external {
        imageId = value;
    }

    function verify(bytes calldata seal, bytes32 image, bytes32 digest) external view {
        require(
            !reject && image == imageId && digest == expected && keccak256(seal) == keccak256(hex"5678"),
            "test invalid receipt"
        );
    }
}

contract ProgramTestAvailability is IAuctionDataAvailabilityVerifier {
    bool public badHash;
    bool public zeroBlock;

    function setBadHash(bool value) external {
        badHash = value;
    }

    function setZeroBlock(bool value) external {
        zeroBlock = value;
    }

    function verifyDataAvailability(bytes32 contentHash, bytes calldata proof)
        external
        view
        returns (DataReference memory)
    {
        require(keccak256(proof) == keccak256(hex"abcd"), "test invalid DA proof");
        return DataReference(badHash ? bytes32(uint256(1)) : contentHash, zeroBlock ? 0 : 1234, 7);
    }
}

/// @dev Deliberately NOT Poseidon. Tests tree shape/order with an independently evaluated binary hash.
contract ProgramTestHash is IAuctionPoseidon {
    function hash(uint256[2] calldata inputs) external pure returns (uint256) {
        return uint256(keccak256(abi.encode(inputs[0], inputs[1])))
            % 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    }
}

contract AuctionE3ProgramTest {
    ProgramVm private constant vm = ProgramVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    ProgramTestProtocol private protocol;
    ProgramTestEscrow private escrow;
    ProgramTestSource private source;
    ProgramTestInputVerifier private inputVerifier;
    ProgramTestReceiptVerifier private receiptVerifier;
    ProgramTestAvailability private availability;
    ProgramTestHash private hasher;
    AuctionE3Program private program;
    bytes32 private context;
    bytes32 private acceptedRoot;
    bytes private parameters = hex"81920002";
    uint256 private constant ID = 42;
    uint64 private constant END = 2000;
    uint64 private constant DEADLINE = 3000;
    address private constant BIDDER = address(0xB1D);

    function setUp() public {
        vm.warp(1000);
        protocol = new ProgramTestProtocol();
        source = new ProgramTestSource();
        escrow = new ProgramTestEscrow(address(source));
        inputVerifier = new ProgramTestInputVerifier();
        receiptVerifier = new ProgramTestReceiptVerifier();
        availability = new ProgramTestAvailability();
        hasher = new ProgramTestHash();
        program = new AuctionE3Program(_configuration());
        context = program.contextFor(ID);
        _setE3();
        protocol.initialize(program, ID, parameters, abi.encode(program.contextFor(ID)));
    }

    function _configuration() private view returns (AuctionE3Program.Configuration memory c) {
        c = AuctionE3Program.Configuration({
            interfold: address(protocol),
            auctionEscrow: address(escrow),
            resultSource: address(source),
            inputVerifier: address(inputVerifier),
            receiptVerifier: address(receiptVerifier),
            availabilityVerifier: address(availability),
            poseidon: address(hasher),
            paramsHash: keccak256(parameters),
            inputCircuitId: inputVerifier.circuitId(),
            imageId: receiptVerifier.imageId(),
            biddingEnds: END,
            settlementDeadline: DEADLINE
        });
    }

    function _setE3() private {
        IInterfoldRead.E3 memory e3;
        e3.e3Program = address(program);
        e3.requester = escrow.seller();
        e3.paramSet = 2;
        e3.inputWindow = [uint256(1000), uint256(END)];
        e3.encryptionSchemeId = program.ENCRYPTION_SCHEME_ID();
        e3.committeePublicKey = bytes32(uint256(0xC0FFEE));
        e3.customParams = abi.encode(program.contextFor(ID));
        protocol.setRecord(e3);
    }

    function _envelope() private pure returns (bytes memory) {
        return abi.encode(uint8(1), keccak256("raw TEST ciphertext"), hex"1234", hex"abcd");
    }

    function _data(uint32 slot, address bidder, bytes memory envelope) private view returns (bytes memory) {
        return abi.encode(context, slot, bidder, envelope, bytes32(uint256(99)));
    }

    function _authorize(uint32 slot, address bidder) private {
        IAuctionInputVerifier.Statement memory s = IAuctionInputVerifier.Statement({
            chainId: block.chainid,
            program: address(program),
            interfold: address(protocol),
            auction: address(escrow),
            context: program.contextFor(ID),
            e3Id: ID,
            committeePublicKey: bytes32(uint256(0xC0FFEE)),
            paramsHash: keccak256(parameters),
            slot: slot,
            bidder: bidder,
            maxTick: 100,
            ciphertextHash: keccak256("raw TEST ciphertext"),
            ciphertextCommitment: bytes32(uint256(99))
        });
        inputVerifier.setExpected(keccak256(abi.encode(s)));
    }

    function _publish(uint32 slot, address bidder) private {
        _authorize(slot, bidder);
        source.publish(program, ID, _data(slot, bidder, _envelope()));
        acceptedRoot = program.computeInputRoot(ID);
    }

    function _proof() private view returns (bytes memory) {
        return abi.encode(hex"5678", keccak256(parameters), acceptedRoot);
    }

    function _authorizeOutput() private {
        bytes32 digest = sha256(
            abi.encode(
                bytes32(block.chainid),
                bytes32(uint256(uint160(address(protocol)))),
                bytes32(ID),
                program.ENCRYPTION_SCHEME_ID(),
                bytes32(uint256(0xC0FFEE)),
                keccak256("output"),
                bytes32(uint256(77)),
                keccak256(parameters),
                program.computeInputRoot(ID)
            )
        );
        receiptVerifier.setExpected(digest);
    }

    function _verify() private view returns (bool) {
        return protocol.verifyOutput(program, ID, keccak256("output"), bytes32(uint256(77)), _proof());
    }

    function testAdvertisesUpstreamRegistrationInterfaces() public view {
        require(program.supportsInterface(type(IAuctionInterfoldProgram).interfaceId));
        require(program.supportsInterface(type(IAuctionInterfoldAvailability).interfaceId));
        require(program.supportsInterface(0x01ffc9a7));
        require(!program.supportsInterface(0xffffffff));
    }

    function testCanonicalContextIncludesFixedDeadlinesAndEscrow() public view {
        bytes32 expected = keccak256(
            abi.encode(
                block.chainid,
                address(escrow),
                escrow.seller(),
                escrow.nft(),
                escrow.tokenId(),
                escrow.collateralWei(),
                escrow.tickWei(),
                uint16(101),
                uint32(3),
                ID,
                END,
                DEADLINE
            )
        );
        require(program.auctionContext(ID) == expected && program.inputRoot(ID) == expected);
    }

    function testValidateOnlyProtocol() public {
        vm.expectRevert(AuctionE3Program.Unauthorized.selector);
        program.validate(ID, 0, parameters, "", abi.encode(context));
    }

    function testCannotInitializeTwice() public {
        vm.expectRevert(AuctionE3Program.AlreadyInitialized.selector);
        protocol.initialize(program, ID, parameters, abi.encode(context));
    }

    function _freshProgram() private {
        program = new AuctionE3Program(_configuration());
        context = program.contextFor(ID);
        _setE3();
    }

    function testValidateRefusesUnexpectedSecureParameters() public {
        _freshProgram();
        vm.expectRevert(AuctionE3Program.InvalidComputation.selector);
        protocol.initialize(program, ID, hex"0000", abi.encode(context));
    }

    function testValidateRefusesInsecureParameterSet() public {
        _freshProgram();
        IInterfoldRead.E3 memory value = protocol.getE3(ID);
        value.paramSet = 0;
        protocol.setRecord(value);
        vm.expectRevert(AuctionE3Program.InvalidComputation.selector);
        protocol.initialize(program, ID, parameters, abi.encode(context));
    }

    function testValidateRefusesDifferentRequester() public {
        _freshProgram();
        IInterfoldRead.E3 memory value = protocol.getE3(ID);
        value.requester = BIDDER;
        protocol.setRecord(value);
        vm.expectRevert(AuctionE3Program.InvalidComputation.selector);
        protocol.initialize(program, ID, parameters, abi.encode(context));
    }

    function testValidateRefusesDifferentEndTime() public {
        _freshProgram();
        IInterfoldRead.E3 memory value = protocol.getE3(ID);
        value.inputWindow[1] += 1;
        protocol.setRecord(value);
        vm.expectRevert(AuctionE3Program.InvalidComputation.selector);
        protocol.initialize(program, ID, parameters, abi.encode(context));
    }

    function testValidateRefusesDifferentContext() public {
        _freshProgram();
        vm.expectRevert(AuctionE3Program.InvalidComputation.selector);
        protocol.initialize(program, ID, parameters, abi.encode(bytes32(uint256(1))));
    }

    function testValidateRefusesDifferentProgram() public {
        _freshProgram();
        IInterfoldRead.E3 memory value = protocol.getE3(ID);
        value.e3Program = address(0xBAD);
        protocol.setRecord(value);
        vm.expectRevert(AuctionE3Program.InvalidComputation.selector);
        protocol.initialize(program, ID, parameters, abi.encode(context));
    }

    function testRefusesMissingVerifierCode() public {
        AuctionE3Program.Configuration memory c = _configuration();
        c.inputVerifier = address(0x123);
        vm.expectRevert(AuctionE3Program.InvalidConfiguration.selector);
        new AuctionE3Program(c);
    }

    function testRefusesMismatchedCircuitIdentity() public {
        AuctionE3Program.Configuration memory c = _configuration();
        c.inputCircuitId = bytes32(uint256(1));
        vm.expectRevert(AuctionE3Program.InvalidConfiguration.selector);
        new AuctionE3Program(c);
    }

    function testRefusesMismatchedGuestIdentity() public {
        AuctionE3Program.Configuration memory c = _configuration();
        c.imageId = bytes32(uint256(1));
        vm.expectRevert(AuctionE3Program.InvalidConfiguration.selector);
        new AuctionE3Program(c);
    }

    function testInputOnlyPinnedSource() public {
        vm.expectRevert(AuctionE3Program.Unauthorized.selector);
        program.publishInput(ID, _data(0, BIDDER, _envelope()));
    }

    function testAdmissionBindsEveryPublicStatementFieldAndBothRoots() public {
        _publish(0, BIDDER);
        bytes32 expected = keccak256(
            abi.encode(program.contextFor(ID), uint256(0), BIDDER, keccak256(_envelope()), bytes32(uint256(99)))
        );
        require(program.inputRoot(ID) == expected && program.bidCount(ID) == 1);
        uint256 leaf =
            program.inputLeaf(program.contextFor(ID), 0, BIDDER, keccak256(_envelope()), bytes32(uint256(99)));
        require(program.inputLeaves(ID, 0) == leaf);
        require(program.computeInputRoot(ID) == bytes32(hasher.hash([leaf, uint256(0)])));
    }

    function testMinimalDepthTreePadsMissingLeavesWithZero() public {
        _publish(0, BIDDER);
        _publish(1, address(0xB1D2));
        _publish(2, address(0xB1D3));
        uint256 left = hasher.hash([program.inputLeaves(ID, 0), program.inputLeaves(ID, 1)]);
        uint256 right = hasher.hash([program.inputLeaves(ID, 2), uint256(0)]);
        require(program.computeInputRoot(ID) == bytes32(hasher.hash([left, right])));
    }

    function testRefusesInvalidInputProofAndRollsBack() public {
        inputVerifier.setReject(true);
        vm.expectRevert(AuctionE3Program.InvalidInputProof.selector);
        source.publish(program, ID, _data(0, BIDDER, _envelope()));
        require(program.bidCount(ID) == 0 && program.inputRoot(ID) == program.contextFor(ID));
    }

    function testProofForDifferentBidderCannotBeUsed() public {
        _authorize(0, BIDDER);
        vm.expectRevert(AuctionE3Program.InvalidInputProof.selector);
        source.publish(program, ID, _data(0, address(0xBAD), _envelope()));
    }

    function testProofForDifferentCiphertextCannotBeUsed() public {
        _authorize(0, BIDDER);
        bytes memory envelope = abi.encode(uint8(1), keccak256("different"), hex"1234", hex"abcd");
        vm.expectRevert(AuctionE3Program.InvalidInputProof.selector);
        source.publish(program, ID, _data(0, BIDDER, envelope));
    }

    function testRefusesUnavailableInputAndRollsBack() public {
        _authorize(0, BIDDER);
        availability.setBadHash(true);
        vm.expectRevert(AuctionE3Program.InvalidAvailability.selector);
        source.publish(program, ID, _data(0, BIDDER, _envelope()));
        require(program.bidCount(ID) == 0 && !program.admittedBidder(ID, BIDDER));
    }

    function testRefusesLocalZeroCoordinateAvailabilityMock() public {
        _authorize(0, BIDDER);
        availability.setZeroBlock(true);
        vm.expectRevert(AuctionE3Program.InvalidAvailability.selector);
        source.publish(program, ID, _data(0, BIDDER, _envelope()));
    }

    function testRefusesNonCanonicalEnvelopeTrailingData() public {
        vm.expectRevert(AuctionE3Program.InvalidInput.selector);
        source.publish(program, ID, _data(0, BIDDER, bytes.concat(_envelope(), hex"00")));
    }

    function testRefusesUnknownEnvelopeVersion() public {
        bytes memory envelope = abi.encode(uint8(2), keccak256("raw TEST ciphertext"), hex"1234", hex"abcd");
        vm.expectRevert(AuctionE3Program.InvalidInput.selector);
        source.publish(program, ID, _data(0, BIDDER, envelope));
    }

    function testRefusesEmptyProofs() public {
        bytes memory envelope = abi.encode(uint8(1), keccak256("raw TEST ciphertext"), hex"", hex"abcd");
        vm.expectRevert(AuctionE3Program.InvalidInput.selector);
        source.publish(program, ID, _data(0, BIDDER, envelope));
    }

    function testRefusesDuplicateBidder() public {
        _publish(0, BIDDER);
        vm.expectRevert(AuctionE3Program.InvalidInput.selector);
        source.publish(program, ID, _data(1, BIDDER, _envelope()));
    }

    function testRefusesWrongIndex() public {
        vm.expectRevert(AuctionE3Program.InvalidInput.selector);
        source.publish(program, ID, _data(1, BIDDER, _envelope()));
    }

    function testRefusesWrongContext() public {
        vm.expectRevert(AuctionE3Program.InvalidInput.selector);
        source.publish(
            program, ID, abi.encode(bytes32(uint256(1)), uint32(0), BIDDER, _envelope(), bytes32(uint256(99)))
        );
    }

    function testRefusesDifferentE3() public {
        vm.expectRevert(AuctionE3Program.InvalidComputation.selector);
        source.publish(program, ID + 1, _data(0, BIDDER, _envelope()));
    }

    function testRefusesBidBeforeWindow() public {
        vm.warp(999);
        vm.expectRevert(AuctionE3Program.InvalidComputation.selector);
        source.publish(program, ID, _data(0, BIDDER, _envelope()));
    }

    function testRefusesBidAtExclusiveDeadline() public {
        vm.warp(END);
        vm.expectRevert(AuctionE3Program.InvalidComputation.selector);
        source.publish(program, ID, _data(0, BIDDER, _envelope()));
    }

    function testRefusesBidWithoutPublishedKeyStage() public {
        protocol.setStage(2);
        vm.expectRevert(AuctionE3Program.InvalidComputation.selector);
        source.publish(program, ID, _data(0, BIDDER, _envelope()));
    }

    function testRefusesZeroCommitteeKey() public {
        IInterfoldRead.E3 memory value = protocol.getE3(ID);
        value.committeePublicKey = 0;
        protocol.setRecord(value);
        vm.expectRevert(AuctionE3Program.InvalidComputation.selector);
        source.publish(program, ID, _data(0, BIDDER, _envelope()));
    }

    function testRefusesNonFieldCommitment() public {
        bytes memory data = abi.encode(context, uint32(0), BIDDER, _envelope(), bytes32(program.SCALAR_FIELD()));
        vm.expectRevert(AuctionE3Program.InvalidInput.selector);
        source.publish(program, ID, data);
    }

    function testDetectsVerifierIdentityChange() public {
        inputVerifier.setCircuitId(bytes32(uint256(1)));
        vm.expectRevert(AuctionE3Program.DependencyChanged.selector);
        source.publish(program, ID, _data(0, BIDDER, _envelope()));
    }

    function testDetectsVerifierCodeChange() public {
        vm.etch(address(inputVerifier), hex"00");
        vm.expectRevert(AuctionE3Program.DependencyChanged.selector);
        source.publish(program, ID, _data(0, BIDDER, _envelope()));
    }

    function testOutputBindsExactNineWordUpstreamJournal() public {
        _publish(0, BIDDER);
        _authorizeOutput();
        vm.warp(END);
        require(_verify());
    }

    function testCannotVerifyOutputOutsideProtocol() public {
        vm.expectRevert(AuctionE3Program.Unauthorized.selector);
        program.verify(ID, keccak256("output"), bytes32(uint256(77)), _proof());
    }

    function testCannotVerifyOutputBeforeClose() public {
        _publish(0, BIDDER);
        vm.expectRevert(AuctionE3Program.InvalidComputeProof.selector);
        _verify();
    }

    function testCannotVerifyOutputAfterSettlementDeadline() public {
        _publish(0, BIDDER);
        vm.warp(DEADLINE + 1);
        vm.expectRevert(AuctionE3Program.InvalidComputeProof.selector);
        _verify();
    }

    function testNoBidAuctionCannotStartDecryption() public {
        vm.warp(END);
        vm.expectRevert(AuctionE3Program.InvalidComputeProof.selector);
        _verify();
    }

    function testOutputCannotOmitFinalInput() public {
        _publish(0, BIDDER);
        bytes32 oldRoot = program.computeInputRoot(ID);
        _publish(1, address(0xB1D2));
        vm.warp(END);
        vm.expectRevert(AuctionE3Program.InvalidComputeProof.selector);
        protocol.verifyOutput(
            program,
            ID,
            keccak256("output"),
            bytes32(uint256(77)),
            abi.encode(hex"5678", keccak256(parameters), oldRoot)
        );
    }

    function testOutputCannotSubstituteParameterHash() public {
        _publish(0, BIDDER);
        vm.warp(END);
        vm.expectRevert(AuctionE3Program.InvalidComputeProof.selector);
        protocol.verifyOutput(
            program,
            ID,
            keccak256("output"),
            bytes32(uint256(77)),
            abi.encode(hex"5678", bytes32(uint256(1)), acceptedRoot)
        );
    }

    function testOutputCannotSubstituteCiphertextHash() public {
        _publish(0, BIDDER);
        _authorizeOutput();
        vm.warp(END);
        vm.expectRevert();
        protocol.verifyOutput(program, ID, keccak256("different output"), bytes32(uint256(77)), _proof());
    }

    function testOutputCannotSubstituteCommitment() public {
        _publish(0, BIDDER);
        _authorizeOutput();
        vm.warp(END);
        vm.expectRevert();
        protocol.verifyOutput(program, ID, keccak256("output"), bytes32(uint256(78)), _proof());
    }

    function testInvalidReceiptCannotAuthorizeDecryption() public {
        _publish(0, BIDDER);
        _authorizeOutput();
        receiptVerifier.setReject(true);
        vm.warp(END);
        vm.expectRevert();
        _verify();
    }

    function testOutputAvailabilityUsesSamePinnedVerifier() public view {
        IAuctionDataAvailabilityVerifier.DataReference memory receipt =
            program.verifyDataAvailability(keccak256("output"), hex"abcd");
        require(receipt.contentHash == keccak256("output") && receipt.blockNumber == 1234 && receipt.leafIndex == 7);
    }
}
