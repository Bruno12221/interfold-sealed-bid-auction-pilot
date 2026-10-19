// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {InterfoldResultSource} from "../src/InterfoldResultSource.sol";
import {IInterfoldRead, IAuctionE3ProgramRead} from "../src/interfaces/IInterfoldRead.sol";

interface ResultSourceVm {
    function warp(uint256 timestamp) external;
    function prank(address sender) external;
    function expectRevert(bytes4 selector) external;
    function expectRevert() external;
}

interface ResultSourceAdmission {
    function publishBid(
        bytes32 context,
        uint256 id,
        uint32 index,
        address bidder,
        bytes calldata envelope,
        bytes32 commitment,
        bytes32 nextInputRoot
    ) external;
}

/// @dev These mocks isolate the bridge's authentication and output decoding. They
/// do not implement encryption, compute proofs, or a production auction program.
contract ResultSourceMockProtocol is IInterfoldRead {
    mapping(uint256 => E3) private computations;
    mapping(uint256 => uint8) private stages;
    mapping(address => bool) public e3Programs;
    bool public requestsPaused;

    function getE3(uint256 id) external view returns (E3 memory) {
        return computations[id];
    }

    function getE3Stage(uint256 id) external view returns (uint8) {
        return stages[id];
    }

    function setE3(uint256 id, E3 memory value) external {
        computations[id] = value;
    }

    function setStage(uint256 id, uint8 value) external {
        stages[id] = value;
    }

    function setRegistered(address candidate, bool value) external {
        e3Programs[candidate] = value;
    }

    function setPaused(bool value) external {
        requestsPaused = value;
    }
}

contract ResultSourceMockProgram is IAuctionE3ProgramRead {
    address public auctionEscrow;
    mapping(uint256 => bytes32) public auctionContext;
    mapping(uint256 => bytes32) public inputRoot;
    mapping(uint256 => uint256) public bidCount;
    address public lastPublisher;
    uint256 public lastE3Id;
    bytes public lastInput;
    uint256 public publishCalls;
    bool public rejectInput;
    bool private overrideRoot;
    bool private overrideCount;
    bytes32 private nextRootOverride;
    uint256 private nextCountOverride;

    error RejectedInput();

    constructor(address escrow) {
        auctionEscrow = escrow;
    }

    function setEscrow(address escrow) external {
        auctionEscrow = escrow;
    }

    function setContext(uint256 id, bytes32 value) external {
        auctionContext[id] = value;
    }

    function setRoot(uint256 id, bytes32 value) external {
        inputRoot[id] = value;
    }

    function setCount(uint256 id, uint256 value) external {
        bidCount[id] = value;
    }

    function setRejectInput(bool value) external {
        rejectInput = value;
    }

    function setNextRoot(bytes32 value) external {
        overrideRoot = true;
        nextRootOverride = value;
    }

    function setNextCount(uint256 value) external {
        overrideCount = true;
        nextCountOverride = value;
    }

    function publishInput(uint256 id, bytes calldata data) external {
        // Record before reverting to verify transaction-wide rollback through the bridge.
        lastPublisher = msg.sender;
        lastE3Id = id;
        lastInput = data;
        publishCalls += 1;
        if (rejectInput) revert RejectedInput();
        (, uint32 index, address bidder, bytes memory envelope, bytes32 commitment) =
            abi.decode(data, (bytes32, uint32, address, bytes, bytes32));
        inputRoot[id] = overrideRoot
            ? nextRootOverride
            : keccak256(abi.encode(inputRoot[id], uint256(index), bidder, keccak256(envelope), commitment));
        bidCount[id] = overrideCount ? nextCountOverride : uint256(index) + 1;
    }
}

contract ResultSourceMockEscrow {
    address public seller;
    uint64 public biddingEnds;

    constructor(address owner, uint64 end) {
        seller = owner;
        biddingEnds = end;
    }

    function validate(InterfoldResultSource source, bytes32 context, uint256 id, uint64 end)
        external
        view
        returns (bool)
    {
        return source.validateAuction(context, id, end);
    }

    function verify(
        InterfoldResultSource source,
        bytes32 context,
        uint256 id,
        bytes32 root,
        uint256 count,
        bytes calldata result
    ) external view returns (bool) {
        return source.verifyResult(context, id, root, count, result);
    }

    function publish(
        InterfoldResultSource source,
        bytes32 context,
        uint256 id,
        uint32 index,
        address bidder,
        bytes calldata envelope,
        bytes32 commitment,
        bytes32 nextInputRoot
    ) external {
        ResultSourceAdmission(address(source))
            .publishBid(context, id, index, bidder, envelope, commitment, nextInputRoot);
    }
}

contract InterfoldResultSourceTest {
    ResultSourceVm private constant vm = ResultSourceVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 private constant ID = 7;
    uint64 private constant END = 2_000;
    address private constant SELLER = address(0xBEEF);
    bytes32 private constant CONTEXT = keccak256("auction context");
    bytes32 private constant ROOT = keccak256("ordered input root");
    bytes32 private constant OTHER = keccak256("other value");
    bytes32 private constant BFV = keccak256("fhe.rs:BFV");
    address private constant BIDDER = address(0xCAFE);

    ResultSourceMockProtocol private protocol;
    ResultSourceMockProgram private program;
    ResultSourceMockEscrow private escrow;
    InterfoldResultSource private source;

    function setUp() public {
        vm.warp(1_000);
        protocol = new ResultSourceMockProtocol();
        escrow = new ResultSourceMockEscrow(SELLER, END);
        program = new ResultSourceMockProgram(address(escrow));
        program.setContext(ID, CONTEXT);
        program.setRoot(ID, ROOT);
        program.setCount(ID, 3);
        protocol.setRegistered(address(program), true);
        protocol.setStage(ID, 3);
        protocol.setE3(ID, _validE3());
        source = new InterfoldResultSource(address(protocol), address(this));
        source.bindProgram(address(program));
    }

    function _validE3() private view returns (IInterfoldRead.E3 memory value) {
        value.inputWindow = [uint256(900), uint256(END)];
        value.e3Program = address(program);
        value.paramSet = 2;
        value.encryptionSchemeId = BFV;
        value.committeePublicKey = keccak256("committee public key");
        value.ciphertextOutput = keccak256("ciphertext output");
        value.customParams = abi.encode(CONTEXT);
        value.requester = SELLER;
        value.plaintextOutput = _littleEndian(_ticks());
    }

    function _ticks() private pure returns (uint256[] memory values) {
        values = new uint256[](3);
        values[0] = 9;
        values[1] = 0;
        values[2] = 0x0102030405060708;
    }

    function _littleEndian(uint256[] memory values) private pure returns (bytes memory output) {
        output = new bytes(400);
        for (uint256 i; i < values.length; ++i) {
            for (uint256 j; j < 8; ++j) {
                output[i * 8 + j] = bytes1(uint8(values[i] >> (j * 8)));
            }
        }
    }

    function _validate() private view returns (bool) {
        return escrow.validate(source, CONTEXT, ID, END);
    }

    function _verify() private view returns (bool) {
        return escrow.verify(source, CONTEXT, ID, ROOT, 3, abi.encode(_ticks()));
    }

    function _settlementStage() private {
        protocol.setStage(ID, 5);
    }

    function _nextRoot() private pure returns (bytes32) {
        return keccak256(abi.encode(ROOT, uint256(3), BIDDER, keccak256(hex"112233"), OTHER));
    }

    function _publish() private {
        escrow.publish(source, CONTEXT, ID, 3, BIDDER, hex"112233", OTHER, _nextRoot());
    }

    function _assertUnchangedProgramLedger() private view {
        require(program.inputRoot(ID) == ROOT, "rejected input changed root");
        require(program.bidCount(ID) == 3, "rejected input changed count");
        require(program.publishCalls() == 0, "rejected input retained publish call");
        require(program.lastInput().length == 0, "rejected input retained payload");
        require(program.lastPublisher() == address(0), "rejected input retained sender");
    }

    function testBidAdmissionForwardsCanonicalPayloadAndAuthenticatesUpdatedLedger() public {
        _publish();
        require(program.lastPublisher() == address(source), "program did not receive source caller");
        require(program.lastE3Id() == ID && program.publishCalls() == 1, "program publication mismatch");
        require(
            keccak256(program.lastInput()) == keccak256(abi.encode(CONTEXT, uint32(3), BIDDER, hex"112233", OTHER)),
            "forwarded input payload mismatch"
        );
        require(program.inputRoot(ID) == _nextRoot(), "accepted input root mismatch");
        require(program.bidCount(ID) == 4, "accepted input count mismatch");
    }

    function testBidAdmissionRejectsUnboundSource() public {
        InterfoldResultSource unbound = new InterfoldResultSource(address(protocol), address(this));
        vm.expectRevert();
        escrow.publish(unbound, CONTEXT, ID, 3, BIDDER, hex"112233", OTHER, _nextRoot());
        _assertUnchangedProgramLedger();
    }

    function testBidAdmissionRejectsDirectCaller() public {
        vm.expectRevert();
        ResultSourceAdmission(address(source)).publishBid(CONTEXT, ID, 3, BIDDER, hex"112233", OTHER, _nextRoot());
        _assertUnchangedProgramLedger();
    }

    function testBidAdmissionRejectsAnotherEscrow() public {
        ResultSourceMockEscrow otherEscrow = new ResultSourceMockEscrow(SELLER, END);
        vm.expectRevert();
        otherEscrow.publish(source, CONTEXT, ID, 3, BIDDER, hex"112233", OTHER, _nextRoot());
        _assertUnchangedProgramLedger();
    }

    function testBidAdmissionRejectsWrongRequestedContext() public {
        vm.expectRevert();
        escrow.publish(source, OTHER, ID, 3, BIDDER, hex"112233", OTHER, _nextRoot());
        _assertUnchangedProgramLedger();
    }

    function testBidAdmissionRejectsWrongProgramContext() public {
        program.setContext(ID, OTHER);
        vm.expectRevert();
        _publish();
        _assertUnchangedProgramLedger();
    }

    function testBidAdmissionRequiresExactlyKeyPublishedStage() public {
        for (uint8 stage; stage <= 6; ++stage) {
            if (stage == 3) continue;
            protocol.setStage(ID, stage);
            vm.expectRevert();
            _publish();
            _assertUnchangedProgramLedger();
        }
    }

    function testBidAdmissionRejectsStaleIndex() public {
        vm.expectRevert();
        escrow.publish(source, CONTEXT, ID, 2, BIDDER, hex"112233", OTHER, _nextRoot());
        _assertUnchangedProgramLedger();
    }

    function testBidAdmissionRejectsFutureIndex() public {
        vm.expectRevert();
        escrow.publish(source, CONTEXT, ID, 4, BIDDER, hex"112233", OTHER, _nextRoot());
        _assertUnchangedProgramLedger();
    }

    function testBidAdmissionRejectsWrongRequestedNextRootAndRollsBack() public {
        vm.expectRevert();
        escrow.publish(source, CONTEXT, ID, 3, BIDDER, hex"112233", OTHER, OTHER);
        _assertUnchangedProgramLedger();
    }

    function testBidAdmissionRejectsWrongProgramNextRootAndRollsBack() public {
        program.setNextRoot(OTHER);
        vm.expectRevert();
        _publish();
        _assertUnchangedProgramLedger();
    }

    function testBidAdmissionRejectsUnchangedProgramCountAndRollsBack() public {
        program.setNextCount(3);
        vm.expectRevert();
        _publish();
        _assertUnchangedProgramLedger();
    }

    function testBidAdmissionRejectsOverincrementedProgramCountAndRollsBack() public {
        program.setNextCount(5);
        vm.expectRevert();
        _publish();
        _assertUnchangedProgramLedger();
    }

    function testBidAdmissionProgramRevertRollsBackAllProgramWrites() public {
        program.setRejectInput(true);
        vm.expectRevert(ResultSourceMockProgram.RejectedInput.selector);
        _publish();
        _assertUnchangedProgramLedger();
    }

    function testBidAdmissionRejectsUnregisteredProgram() public {
        protocol.setRegistered(address(program), false);
        vm.expectRevert();
        _publish();
        _assertUnchangedProgramLedger();
    }

    function testBidAdmissionRejectsPausedProtocol() public {
        protocol.setPaused(true);
        vm.expectRevert();
        _publish();
        _assertUnchangedProgramLedger();
    }

    function testBidAdmissionRejectsWrongE3Program() public {
        IInterfoldRead.E3 memory value = _validE3();
        value.e3Program = address(0x1234);
        protocol.setE3(ID, value);
        vm.expectRevert();
        _publish();
        _assertUnchangedProgramLedger();
    }

    function testBidAdmissionRejectsWrongParameterSet() public {
        IInterfoldRead.E3 memory value = _validE3();
        value.paramSet = 1;
        protocol.setE3(ID, value);
        vm.expectRevert();
        _publish();
        _assertUnchangedProgramLedger();
    }

    function testBidAdmissionRejectsWrongEncryptionScheme() public {
        IInterfoldRead.E3 memory value = _validE3();
        value.encryptionSchemeId = OTHER;
        protocol.setE3(ID, value);
        vm.expectRevert();
        _publish();
        _assertUnchangedProgramLedger();
    }

    function testBidAdmissionRejectsMissingCommitteeKey() public {
        IInterfoldRead.E3 memory value = _validE3();
        value.committeePublicKey = bytes32(0);
        protocol.setE3(ID, value);
        vm.expectRevert();
        _publish();
        _assertUnchangedProgramLedger();
    }

    function testBidAdmissionRejectsWrongRequester() public {
        IInterfoldRead.E3 memory value = _validE3();
        value.requester = address(0x1234);
        protocol.setE3(ID, value);
        vm.expectRevert();
        _publish();
        _assertUnchangedProgramLedger();
    }

    function testBidAdmissionRejectsFutureInputWindow() public {
        IInterfoldRead.E3 memory value = _validE3();
        value.inputWindow[0] = block.timestamp + 1;
        protocol.setE3(ID, value);
        vm.expectRevert();
        _publish();
        _assertUnchangedProgramLedger();
    }

    function testBidAdmissionRejectsWrongInputWindowEnd() public {
        IInterfoldRead.E3 memory value = _validE3();
        value.inputWindow[1] = END + 1;
        protocol.setE3(ID, value);
        vm.expectRevert();
        _publish();
        _assertUnchangedProgramLedger();
    }

    function testBidAdmissionRejectsWrongCustomParams() public {
        IInterfoldRead.E3 memory value = _validE3();
        value.customParams = abi.encode(OTHER);
        protocol.setE3(ID, value);
        vm.expectRevert();
        _publish();
        _assertUnchangedProgramLedger();
    }

    function testConstructorRejectsProtocolWithoutCode() public {
        vm.expectRevert();
        new InterfoldResultSource(address(0x1234), address(this));
    }

    function testConstructorRejectsZeroBinder() public {
        vm.expectRevert();
        new InterfoldResultSource(address(protocol), address(0));
    }

    function testOnlyBinderCanBind() public {
        InterfoldResultSource unbound = new InterfoldResultSource(address(protocol), address(this));
        vm.prank(address(0xCAFE));
        vm.expectRevert(InterfoldResultSource.Unauthorized.selector);
        unbound.bindProgram(address(program));
        require(unbound.program() == address(0), "unauthorized bind mutated program");
    }

    function testBindingIsOneTime() public {
        vm.expectRevert(InterfoldResultSource.AlreadyBound.selector);
        source.bindProgram(address(program));
    }

    function testBindingRejectsUnregisteredProgram() public {
        InterfoldResultSource unbound = new InterfoldResultSource(address(protocol), address(this));
        protocol.setRegistered(address(program), false);
        vm.expectRevert(InterfoldResultSource.InvalidProgram.selector);
        unbound.bindProgram(address(program));
    }

    function testBindingRejectsProgramWithoutCode() public {
        InterfoldResultSource unbound = new InterfoldResultSource(address(protocol), address(this));
        protocol.setRegistered(address(0x1234), true);
        vm.expectRevert(InterfoldResultSource.InvalidProgram.selector);
        unbound.bindProgram(address(0x1234));
    }

    function testBindingRejectsEscrowWithoutCode() public {
        InterfoldResultSource unbound = new InterfoldResultSource(address(protocol), address(this));
        program.setEscrow(address(0x1234));
        vm.expectRevert(InterfoldResultSource.InvalidProgram.selector);
        unbound.bindProgram(address(program));
    }

    function testBindingRejectsZeroEscrow() public {
        InterfoldResultSource unbound = new InterfoldResultSource(address(protocol), address(this));
        program.setEscrow(address(0));
        vm.expectRevert(InterfoldResultSource.InvalidProgram.selector);
        unbound.bindProgram(address(program));
    }

    function testUnboundSourceFailsClosed() public {
        InterfoldResultSource unbound = new InterfoldResultSource(address(protocol), address(this));
        require(!unbound.isReady(), "unbound ready");
        require(!escrow.validate(unbound, CONTEXT, ID, END), "unbound validation");
        _settlementStage();
        require(!escrow.verify(unbound, CONTEXT, ID, ROOT, 3, abi.encode(_ticks())), "unbound result");
    }

    function testRegisteredUnpausedSourceIsReady() public view {
        require(source.program() == address(program), "wrong pinned program");
        require(source.binder() == address(this), "wrong binder");
        require(source.isReady(), "registered unpaused source not ready");
    }

    function testPausedSourceRejectsOpening() public {
        protocol.setPaused(true);
        require(!source.isReady(), "paused ready");
        require(!_validate(), "paused validation");
    }

    function testUnregisteredSourceRejectsOpening() public {
        protocol.setRegistered(address(program), false);
        require(!source.isReady(), "unregistered ready");
        require(!_validate(), "unregistered validation");
    }

    function testValidKeyPublishedAuction() public view {
        require(_validate(), "valid key-published auction rejected");
    }

    function testValidationRequiresExactlyKeyPublishedStage() public {
        for (uint8 stage; stage <= 6; ++stage) {
            if (stage == 3) continue;
            protocol.setStage(ID, stage);
            require(!_validate(), "accepted wrong opening stage");
        }
    }

    function testValidationRejectsWrongEscrowCaller() public {
        ResultSourceMockEscrow otherEscrow = new ResultSourceMockEscrow(SELLER, END);
        require(!otherEscrow.validate(source, CONTEXT, ID, END), "accepted another escrow");
    }

    function testValidationRejectsWrongProgramContext() public {
        program.setContext(ID, OTHER);
        require(!_validate(), "accepted wrong program context");
    }

    function testValidationRejectsWrongRequestedContext() public view {
        require(!escrow.validate(source, OTHER, ID, END), "accepted requested context mismatch");
    }

    function testValidationRejectsWrongProgram() public {
        IInterfoldRead.E3 memory value = _validE3();
        value.e3Program = address(0x1234);
        protocol.setE3(ID, value);
        require(!_validate(), "accepted wrong E3 program");
    }

    function testValidationRejectsWrongParameterSet() public {
        IInterfoldRead.E3 memory value = _validE3();
        value.paramSet = 1;
        protocol.setE3(ID, value);
        require(!_validate(), "accepted wrong parameter set");
    }

    function testValidationRejectsWrongEncryptionScheme() public {
        IInterfoldRead.E3 memory value = _validE3();
        value.encryptionSchemeId = OTHER;
        protocol.setE3(ID, value);
        require(!_validate(), "accepted wrong encryption scheme");
    }

    function testValidationRejectsMissingCommitteeKey() public {
        IInterfoldRead.E3 memory value = _validE3();
        value.committeePublicKey = bytes32(0);
        protocol.setE3(ID, value);
        require(!_validate(), "accepted missing committee key");
    }

    function testValidationRejectsWrongRequester() public {
        IInterfoldRead.E3 memory value = _validE3();
        value.requester = address(0x1234);
        protocol.setE3(ID, value);
        require(!_validate(), "accepted wrong requester");
    }

    function testValidationRejectsWindowStartingInFuture() public {
        IInterfoldRead.E3 memory value = _validE3();
        value.inputWindow[0] = block.timestamp + 1;
        protocol.setE3(ID, value);
        require(!_validate(), "accepted future input window");
    }

    function testValidationAcceptsWindowStartingNow() public {
        IInterfoldRead.E3 memory value = _validE3();
        value.inputWindow[0] = block.timestamp;
        protocol.setE3(ID, value);
        require(_validate(), "rejected exact window start");
    }

    function testValidationRejectsWrongWindowEnd() public {
        IInterfoldRead.E3 memory value = _validE3();
        value.inputWindow[1] = END + 1;
        protocol.setE3(ID, value);
        require(!_validate(), "accepted wrong input window end");
    }

    function testValidationRejectsWrongCustomParams() public {
        IInterfoldRead.E3 memory value = _validE3();
        value.customParams = abi.encode(OTHER);
        protocol.setE3(ID, value);
        require(!_validate(), "accepted wrong custom context");
    }

    function testValidationRejectsCustomParamsWithTrailingData() public {
        IInterfoldRead.E3 memory value = _validE3();
        value.customParams = abi.encode(CONTEXT, uint256(0));
        protocol.setE3(ID, value);
        require(!_validate(), "accepted noncanonical custom context");
    }

    function testValidSettlementDecodesFiftyLittleEndianU64s() public {
        _settlementStage();
        require(_verify(), "valid little-endian result rejected");
    }

    function testSettlementRequiresExactlyPlaintextPublishedStage() public {
        for (uint8 stage; stage <= 6; ++stage) {
            if (stage == 5) continue;
            protocol.setStage(ID, stage);
            require(!_verify(), "accepted wrong settlement stage");
        }
    }

    function testSettlementRejectsWrongEscrowCaller() public {
        _settlementStage();
        ResultSourceMockEscrow otherEscrow = new ResultSourceMockEscrow(SELLER, END);
        require(!otherEscrow.verify(source, CONTEXT, ID, ROOT, 3, abi.encode(_ticks())), "accepted another escrow");
    }

    function testSettlementRejectsWrongProgramContext() public {
        _settlementStage();
        program.setContext(ID, OTHER);
        require(!_verify(), "accepted wrong program context");
    }

    function testSettlementRejectsWrongRequestedContext() public {
        _settlementStage();
        require(!escrow.verify(source, OTHER, ID, ROOT, 3, abi.encode(_ticks())), "accepted requested context mismatch");
    }

    function testSettlementRejectsStaleProgramInputRoot() public {
        _settlementStage();
        program.setRoot(ID, OTHER);
        require(!_verify(), "accepted stale program root");
    }

    function testSettlementRejectsWrongRequestedInputRoot() public {
        _settlementStage();
        require(!escrow.verify(source, CONTEXT, ID, OTHER, 3, abi.encode(_ticks())), "accepted wrong requested root");
    }

    function testSettlementRejectsStaleProgramBidCount() public {
        _settlementStage();
        program.setCount(ID, 2);
        require(!_verify(), "accepted stale program count");
    }

    function testSettlementRejectsWrongProgram() public {
        _settlementStage();
        IInterfoldRead.E3 memory value = _validE3();
        value.e3Program = address(0x1234);
        protocol.setE3(ID, value);
        require(!_verify(), "accepted wrong E3 program");
    }

    function testSettlementRejectsWrongParameterSet() public {
        _settlementStage();
        IInterfoldRead.E3 memory value = _validE3();
        value.paramSet = 1;
        protocol.setE3(ID, value);
        require(!_verify(), "accepted wrong parameter set");
    }

    function testSettlementRejectsWrongEncryptionScheme() public {
        _settlementStage();
        IInterfoldRead.E3 memory value = _validE3();
        value.encryptionSchemeId = OTHER;
        protocol.setE3(ID, value);
        require(!_verify(), "accepted wrong encryption scheme");
    }

    function testSettlementRejectsMissingCommitteeKey() public {
        _settlementStage();
        IInterfoldRead.E3 memory value = _validE3();
        value.committeePublicKey = bytes32(0);
        protocol.setE3(ID, value);
        require(!_verify(), "accepted missing committee key");
    }

    function testSettlementRejectsMissingCiphertextOutputHash() public {
        _settlementStage();
        IInterfoldRead.E3 memory value = _validE3();
        value.ciphertextOutput = bytes32(0);
        protocol.setE3(ID, value);
        require(!_verify(), "accepted missing ciphertext output hash");
    }

    function testSettlementRejectsWrongRequester() public {
        _settlementStage();
        IInterfoldRead.E3 memory value = _validE3();
        value.requester = address(0x1234);
        protocol.setE3(ID, value);
        require(!_verify(), "accepted wrong requester");
    }

    function testSettlementRejectsWrongWindowEnd() public {
        _settlementStage();
        IInterfoldRead.E3 memory value = _validE3();
        value.inputWindow[1] = END + 1;
        protocol.setE3(ID, value);
        require(!_verify(), "accepted wrong input window end");
    }

    function testSettlementRejectsWrongCustomParams() public {
        _settlementStage();
        IInterfoldRead.E3 memory value = _validE3();
        value.customParams = abi.encode(OTHER);
        protocol.setE3(ID, value);
        require(!_verify(), "accepted wrong custom context");
    }

    function testSettlementRejectsWrongTicks() public {
        _settlementStage();
        uint256[] memory ticks = _ticks();
        ticks[0] += 1;
        require(!escrow.verify(source, CONTEXT, ID, ROOT, 3, abi.encode(ticks)), "accepted modified tick");
    }

    function testSettlementRejectsTickLargerThanU64() public {
        _settlementStage();
        uint256[] memory ticks = _ticks();
        ticks[2] += uint256(1) << 64;
        require(!escrow.verify(source, CONTEXT, ID, ROOT, 3, abi.encode(ticks)), "accepted truncated oversized tick");
    }

    function testSettlementRejectsBigEndianCoefficients() public {
        _settlementStage();
        IInterfoldRead.E3 memory value = _validE3();
        uint256[] memory ticks = _ticks();
        for (uint256 i; i < ticks.length; ++i) {
            for (uint256 j; j < 8; ++j) {
                value.plaintextOutput[i * 8 + j] = bytes1(uint8(ticks[i] >> ((7 - j) * 8)));
            }
        }
        protocol.setE3(ID, value);
        require(!_verify(), "accepted big-endian coefficients");
    }

    function testSettlementRejectsNonzeroFirstUnusedCoefficient() public {
        _settlementStage();
        IInterfoldRead.E3 memory value = _validE3();
        value.plaintextOutput[3 * 8] = 0x01;
        protocol.setE3(ID, value);
        require(!_verify(), "accepted nonzero unused coefficient");
    }

    function testSettlementRejectsNonzeroLastUnusedCoefficient() public {
        _settlementStage();
        IInterfoldRead.E3 memory value = _validE3();
        value.plaintextOutput[399] = 0x80;
        protocol.setE3(ID, value);
        require(!_verify(), "ignored final padding byte");
    }

    function testSettlementRejectsTruncatedPlaintext() public {
        _settlementStage();
        IInterfoldRead.E3 memory value = _validE3();
        bytes memory truncated = new bytes(399);
        for (uint256 i; i < 399; ++i) {
            truncated[i] = value.plaintextOutput[i];
        }
        value.plaintextOutput = truncated;
        protocol.setE3(ID, value);
        require(!_verify(), "accepted truncated plaintext");
    }

    function testSettlementRejectsOverlongPlaintext() public {
        _settlementStage();
        IInterfoldRead.E3 memory value = _validE3();
        value.plaintextOutput = bytes.concat(value.plaintextOutput, hex"00");
        protocol.setE3(ID, value);
        require(!_verify(), "accepted overlong plaintext");
    }

    function testSettlementRejectsEmptyPlaintext() public {
        _settlementStage();
        IInterfoldRead.E3 memory value = _validE3();
        value.plaintextOutput = hex"";
        protocol.setE3(ID, value);
        require(!_verify(), "accepted empty plaintext");
    }

    function testSettlementRejectsWrongTickArrayLength() public {
        _settlementStage();
        uint256[] memory ticks = new uint256[](2);
        ticks[0] = 9;
        require(!escrow.verify(source, CONTEXT, ID, ROOT, 3, abi.encode(ticks)), "accepted short tick array");
    }

    function testSettlementRejectsMalformedResultABI() public {
        _settlementStage();
        (bool ok, bytes memory output) =
            address(escrow).staticcall(abi.encodeCall(escrow.verify, (source, CONTEXT, ID, ROOT, 3, hex"01")));
        require(!ok || (output.length == 32 && !abi.decode(output, (bool))), "accepted malformed result ABI");
    }

    function testSettlementRejectsTruncatedResultABI() public {
        _settlementStage();
        bytes memory encoded = abi.encode(_ticks());
        bytes memory truncated = new bytes(encoded.length - 1);
        for (uint256 i; i < truncated.length; ++i) {
            truncated[i] = encoded[i];
        }
        (bool ok, bytes memory output) =
            address(escrow).staticcall(abi.encodeCall(escrow.verify, (source, CONTEXT, ID, ROOT, 3, truncated)));
        require(!ok || (output.length == 32 && !abi.decode(output, (bool))), "accepted truncated result ABI");
    }

    function testSettlementRejectsMoreThan32Bids() public {
        _settlementStage();
        uint256[] memory ticks = new uint256[](33);
        IInterfoldRead.E3 memory value = _validE3();
        value.plaintextOutput = _littleEndian(ticks);
        protocol.setE3(ID, value);
        program.setCount(ID, 33);
        require(!escrow.verify(source, CONTEXT, ID, ROOT, 33, abi.encode(ticks)), "accepted 33 bids");
    }

    function testSettlementAccepts32Bids() public {
        _settlementStage();
        uint256[] memory ticks = new uint256[](32);
        for (uint256 i; i < 32; ++i) {
            ticks[i] = i + 1;
        }
        IInterfoldRead.E3 memory value = _validE3();
        value.plaintextOutput = _littleEndian(ticks);
        protocol.setE3(ID, value);
        program.setCount(ID, 32);
        require(escrow.verify(source, CONTEXT, ID, ROOT, 32, abi.encode(ticks)), "rejected 32 bids");
    }

    function testSettlementAcceptsEmptyAuctionWithZeroOutput() public {
        _settlementStage();
        uint256[] memory ticks = new uint256[](0);
        IInterfoldRead.E3 memory value = _validE3();
        value.plaintextOutput = new bytes(400);
        protocol.setE3(ID, value);
        program.setCount(ID, 0);
        require(escrow.verify(source, CONTEXT, ID, ROOT, 0, abi.encode(ticks)), "rejected zero output");
    }
}
