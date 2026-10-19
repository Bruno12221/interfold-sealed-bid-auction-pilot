// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SealedBidAuction, IAuctionResultSource, IAuctionNFT} from "../src/SealedBidAuction.sol";
import {DemoNFT} from "../src/DemoNFT.sol";

interface VmAuction {
    function warp(uint256 timestamp) external;
    function prank(address sender) external;
    function deal(address account, uint256 newBalance) external;
    function expectRevert(bytes4 selector) external;
    function expectRevert() external;
}

/// @dev Test-only source: never deployed by the pilot deployment scripts.
contract MockAuctionResultSource is IAuctionResultSource {
    bool public ready = true;
    bool public validAuction = true;
    bool public rejectEnvelope;
    bytes32 public acceptedTuple;
    error InvalidEnvelope();

    function setReady(bool value) external {
        ready = value;
    }

    function setValidAuction(bool value) external {
        validAuction = value;
    }

    function setRejectEnvelope(bool value) external {
        rejectEnvelope = value;
    }

    function isReady() external view returns (bool) {
        return ready;
    }

    function validateAuction(bytes32, uint256, uint64) external view returns (bool) {
        return validAuction;
    }

    function publishBid(bytes32, uint256, uint32, address, bytes calldata, bytes32, bytes32) external view {
        if (rejectEnvelope) revert InvalidEnvelope();
    }

    function accept(SealedBidAuction auction, bytes memory result) external {
        acceptedTuple = keccak256(
            abi.encode(auction.auctionContext(), auction.e3Id(), auction.inputRoot(), auction.bidCount(), result)
        );
    }

    function verifyResult(bytes32 context, uint256 id, bytes32 root, uint256 count, bytes calldata result)
        external
        view
        returns (bool)
    {
        return acceptedTuple == keccak256(abi.encode(context, id, root, count, result));
    }
}

contract ToggleAuctionNFT is IAuctionNFT {
    address private owner;
    bool public rejectTransfers;
    bool public ignoreTransfers;
    error Rejected();

    constructor(address owner_) {
        owner = owner_;
    }

    function setReject(bool value) external {
        rejectTransfers = value;
    }

    function setIgnore(bool value) external {
        ignoreTransfers = value;
    }

    function ownerOf(uint256) external view returns (address) {
        return owner;
    }

    function transferFrom(address from, address to, uint256) external {
        if (rejectTransfers) revert Rejected();
        require(from == owner, "wrong owner");
        if (!ignoreTransfers) owner = to;
    }
}

contract AuctionRefundReceiver {
    SealedBidAuction public immutable auction;
    bool public rejectEther;
    bool public attemptReentry;
    bool public reentrySucceeded;
    uint256 public receiveCount;

    constructor(SealedBidAuction auction_) {
        auction = auction_;
    }

    function bid() external payable {
        auction.submitBid{value: msg.value}(uint32(auction.bidCount()), hex"010203", bytes32(uint256(7)));
    }

    function configure(bool reject_, bool reenter_) external {
        rejectEther = reject_;
        attemptReentry = reenter_;
    }

    function withdrawTo(address payable recipient) external {
        auction.withdraw(recipient);
    }

    receive() external payable {
        require(!rejectEther, "reject");
        receiveCount += 1;
        if (attemptReentry) {
            (reentrySucceeded,) = address(auction).call(abi.encodeCall(auction.withdraw, (payable(address(this)))));
        }
    }
}

contract SealedBidAuctionTest {
    VmAuction private constant vm = VmAuction(address(uint160(uint256(keccak256("hevm cheat code")))));
    address private constant SELLER = address(0x5151);
    address private constant ALICE = address(0xA11CE);
    address private constant BOB = address(0xB0B);
    address private constant CAROL = address(0xCA201);
    uint256 private constant COLLATERAL = 0.01 ether;
    uint256 private constant TICK = 0.001 ether;
    uint64 private constant ENDS = 1_100;
    uint64 private constant DEADLINE = 1_200;
    uint256 private constant E3_ID = 7;
    DemoNFT private nft;
    MockAuctionResultSource private source;
    SealedBidAuction private auction;
    uint256 private tokenId;

    function setUp() public {
        vm.warp(1_000);
        vm.deal(address(this), 1 ether);
        vm.deal(SELLER, 1 ether);
        vm.deal(ALICE, 1 ether);
        vm.deal(BOB, 1 ether);
        vm.deal(CAROL, 1 ether);
        nft = new DemoNFT();
        vm.prank(SELLER);
        tokenId = nft.mint();
        source = new MockAuctionResultSource();
        auction = _deploy(address(nft));
        vm.prank(SELLER);
        nft.approve(address(auction), tokenId);
    }

    function testOpenEscrowsAssetAndBindsExactContext() public {
        _open();
        require(nft.ownerOf(tokenId) == address(auction), "NFT not escrowed");
        bytes32 expected = keccak256(
            abi.encode(
                block.chainid,
                address(auction),
                SELLER,
                address(nft),
                tokenId,
                COLLATERAL,
                TICK,
                uint16(10),
                uint32(32),
                E3_ID,
                ENDS,
                DEADLINE
            )
        );
        require(auction.auctionContext() == expected, "context mismatch");
        require(auction.inputRoot() == expected, "root domain mismatch");
        require(auction.state() == SealedBidAuction.State.Bidding, "not bidding");
    }

    function testOnlySellerCanOpen() public {
        vm.prank(ALICE);
        vm.expectRevert(SealedBidAuction.OnlySeller.selector);
        auction.open(E3_ID, ENDS, DEADLINE);
    }

    function testCannotOpenWhenSourceNotReady() public {
        source.setReady(false);
        vm.prank(SELLER);
        vm.expectRevert(SealedBidAuction.ResultSourceNotReady.selector);
        auction.open(E3_ID, ENDS, DEADLINE);
        require(nft.ownerOf(tokenId) == SELLER, "token moved");
    }

    function testInvalidComputationRollsBackAllOpenFields() public {
        source.setValidAuction(false);
        vm.prank(SELLER);
        vm.expectRevert(SealedBidAuction.InvalidComputation.selector);
        auction.open(E3_ID, ENDS, DEADLINE);
        require(auction.e3Id() == 0 && auction.biddingEnds() == 0, "fields persisted");
        require(auction.state() == SealedBidAuction.State.Created, "state persisted");
        require(nft.ownerOf(tokenId) == SELLER, "token moved");
    }

    function testDeadlinesMustBeOrderedAndInFuture() public {
        vm.prank(SELLER);
        vm.expectRevert(SealedBidAuction.InvalidDeadlines.selector);
        auction.open(E3_ID, 1_000, DEADLINE);
        vm.prank(SELLER);
        vm.expectRevert(SealedBidAuction.InvalidDeadlines.selector);
        auction.open(E3_ID, ENDS, ENDS);
    }

    function testAuctionCanOnlyOpenOnce() public {
        _open();
        vm.prank(SELLER);
        vm.expectRevert(SealedBidAuction.InvalidState.selector);
        auction.open(E3_ID, ENDS, DEADLINE);
    }

    function testBidRootIncludesIndexBidderCiphertextAndCommitment() public {
        _open();
        bytes32 root = auction.inputRoot();
        bytes memory ciphertext = hex"010203";
        bytes32 commitment = keccak256("alice salt+bid");
        vm.prank(ALICE);
        auction.submitBid{value: COLLATERAL}(0, ciphertext, commitment);
        root = keccak256(abi.encode(root, uint256(0), ALICE, keccak256(ciphertext), commitment));
        require(auction.inputRoot() == root, "first append mismatch");
        (address bidder, bytes32 ciphertextHash, bytes32 storedCommitment) = auction.bids(0);
        require(bidder == ALICE && ciphertextHash == keccak256(ciphertext), "bid metadata mismatch");
        require(storedCommitment == commitment, "commitment mismatch");
        vm.prank(BOB);
        auction.submitBid{value: COLLATERAL}(1, ciphertext, commitment);
        root = keccak256(abi.encode(root, uint256(1), BOB, keccak256(ciphertext), commitment));
        require(auction.inputRoot() == root && auction.bidCount() == 2, "second append mismatch");
    }

    function testUniformCollateralExactAmountRequired() public {
        _open();
        vm.prank(ALICE);
        vm.expectRevert(SealedBidAuction.WrongCollateral.selector);
        auction.submitBid{value: COLLATERAL - 1}(0, hex"01", bytes32(0));
        vm.prank(ALICE);
        vm.expectRevert(SealedBidAuction.WrongCollateral.selector);
        auction.submitBid{value: COLLATERAL + 1}(0, hex"01", bytes32(0));
        require(auction.bidCount() == 0 && address(auction).balance == 0, "invalid deposit retained");
    }

    function testOneBidPerAccount() public {
        _open();
        _bid(ALICE);
        vm.prank(ALICE);
        vm.expectRevert(SealedBidAuction.DuplicateBid.selector);
        auction.submitBid{value: COLLATERAL}(1, hex"02", bytes32(0));
    }

    function testStaleOrFutureBidIndexRejectsWithoutAcceptingCollateral() public {
        _open();
        vm.prank(BOB);
        vm.expectRevert(SealedBidAuction.BidIndexChanged.selector);
        auction.submitBid{value: COLLATERAL}(1, hex"01", bytes32(0));
        _bid(ALICE);
        bytes32 priorRoot = auction.inputRoot();
        vm.prank(BOB);
        vm.expectRevert(SealedBidAuction.BidIndexChanged.selector);
        auction.submitBid{value: COLLATERAL}(0, hex"02", bytes32(0));
        require(auction.bidCount() == 1 && !auction.hasBid(BOB), "stale bid accepted");
        require(auction.inputRoot() == priorRoot && address(auction).balance == COLLATERAL, "stale bid changed escrow");
        require(BOB.balance == 1 ether, "stale bid took collateral");
        vm.prank(BOB);
        auction.submitBid{value: COLLATERAL}(1, hex"0304", bytes32(uint256(1)));
        require(auction.bidCount() == 2 && auction.hasBid(BOB), "updated-slot retry failed");
    }

    function testRejectedEnvelopeRollsBackDepositRootAndBidAdmission() public {
        _open();
        _bid(ALICE);
        bytes32 priorRoot = auction.inputRoot();
        source.setRejectEnvelope(true);
        vm.prank(BOB);
        vm.expectRevert(MockAuctionResultSource.InvalidEnvelope.selector);
        auction.submitBid{value: COLLATERAL}(1, hex"01", bytes32(uint256(1)));
        require(auction.bidCount() == 1 && !auction.hasBid(BOB), "rejected envelope admitted");
        require(auction.inputRoot() == priorRoot, "rejected envelope changed root");
        require(address(auction).balance == COLLATERAL && BOB.balance == 1 ether, "rejected deposit retained");
        require(auction.totalCredits() == 0, "rejected envelope changed credits");
        source.setRejectEnvelope(false);
        _bid(BOB);
        require(auction.bidCount() == 2 && auction.hasBid(BOB), "valid retry not admitted");
    }

    function testEmptyAndOversizedCiphertextsRejected() public {
        _open();
        vm.prank(ALICE);
        vm.expectRevert(SealedBidAuction.InvalidCiphertext.selector);
        auction.submitBid{value: COLLATERAL}(0, "", bytes32(0));
        bytes memory oversized = new bytes(auction.MAX_CIPHERTEXT_BYTES() + 1);
        vm.prank(ALICE);
        vm.expectRevert(SealedBidAuction.InvalidCiphertext.selector);
        auction.submitBid{value: COLLATERAL}(0, oversized, bytes32(0));
    }

    function testBidAtCloseRejectedAndSettlementAtCloseAllowed() public {
        _open();
        _bid(ALICE);
        vm.warp(ENDS);
        vm.prank(BOB);
        vm.expectRevert(SealedBidAuction.BiddingClosed.selector);
        auction.submitBid{value: COLLATERAL}(1, hex"02", bytes32(0));
        _settle(_one(4));
        require(auction.winner() == ALICE, "close settlement failed");
    }

    function testSettlementCannotRunBeforeClose() public {
        _open();
        _bid(ALICE);
        bytes memory result = _one(4);
        source.accept(auction, result);
        vm.expectRevert(SealedBidAuction.BiddingStillOpen.selector);
        auction.settle(result);
    }

    function testUnverifiedResultRejected() public {
        _open();
        _bid(ALICE);
        vm.warp(ENDS);
        vm.expectRevert(SealedBidAuction.UnauthenticatedResult.selector);
        auction.settle(_one(9));
        require(auction.state() == SealedBidAuction.State.Bidding, "state changed");
        require(auction.totalCredits() == 0, "unverified payout");
    }

    function testSourceAuthenticationBindsFinalInputRootAndOutput() public {
        _open();
        _bid(ALICE);
        bytes memory result = _one(7);
        source.accept(auction, result);
        _bid(BOB);
        vm.warp(ENDS);
        vm.expectRevert(SealedBidAuction.UnauthenticatedResult.selector);
        auction.settle(result);
        source.accept(auction, _two(7, 3));
        vm.expectRevert(SealedBidAuction.UnauthenticatedResult.selector);
        auction.settle(_two(3, 7));
    }

    function testSecondPriceSettlementAndFullLedgerConservation() public {
        _open();
        _bid(ALICE);
        _bid(BOB);
        vm.warp(ENDS);
        bytes memory result = _two(3, 7);
        source.accept(auction, result);
        vm.prank(CAROL);
        auction.settle(result);
        require(auction.winner() == BOB && nft.ownerOf(tokenId) == BOB, "wrong winner");
        require(auction.winningBid() == 7 * TICK, "wrong highest bid");
        require(auction.winningPrice() == 3 * TICK, "wrong second price");
        require(auction.credits(ALICE) == COLLATERAL, "loser not refunded");
        require(auction.credits(BOB) == COLLATERAL - 3 * TICK, "winner refund wrong");
        require(auction.credits(SELLER) == 3 * TICK, "seller payment wrong");
        require(auction.totalCredits() == 2 * COLLATERAL, "ledger not conserved");
        require(address(auction).balance == 2 * COLLATERAL, "ETH not conserved");

        vm.prank(ALICE);
        auction.withdraw(payable(ALICE));
        vm.prank(BOB);
        auction.withdraw(payable(BOB));
        vm.prank(SELLER);
        auction.withdraw(payable(SELLER));
        require(address(auction).balance == 0 && auction.totalCredits() == 0, "funds stranded");
        require(ALICE.balance == 1 ether, "loser balance wrong");
        require(BOB.balance == 1 ether - 3 * TICK, "winner balance wrong");
        require(SELLER.balance == 1 ether + 3 * TICK, "seller balance wrong");
    }

    function testHighestTieGoesToEarliestBid() public {
        _open();
        _bid(ALICE);
        _bid(BOB);
        vm.warp(ENDS);
        _settle(_two(9, 9));
        require(auction.winner() == ALICE && auction.winningPrice() == 9 * TICK, "tie rule wrong");
    }

    function testSolePositiveBidWinsAndPaysZeroWithoutReserve() public {
        _open();
        _bid(ALICE);
        _bid(BOB);
        vm.warp(ENDS);
        _settle(_two(0, 7));
        require(auction.winner() == BOB && nft.ownerOf(tokenId) == BOB, "sole positive bidder lost");
        require(auction.winningBid() == 7 * TICK && auction.winningPrice() == 0, "sole positive bid paid");
        require(auction.credits(BOB) == COLLATERAL && auction.credits(SELLER) == 0, "zero-price ledger wrong");
    }

    function testSingleBidderWinsAndPaysZeroWithoutReserve() public {
        _open();
        _bid(ALICE);
        vm.warp(ENDS);
        _settle(_one(9));
        require(auction.winner() == ALICE && auction.winningPrice() == 0, "single bidder price wrong");
        require(auction.credits(ALICE) == COLLATERAL, "single bidder refund wrong");
    }

    function testThreeBids10070And40Charge70ToHighestBidder() public {
        uint256 fineTick = 0.0001 ether;
        auction = new SealedBidAuction(SELLER, address(nft), tokenId, COLLATERAL, fineTick, 101, 32, address(source));
        vm.prank(SELLER);
        nft.approve(address(auction), tokenId);
        _open();
        _bid(ALICE);
        _bid(BOB);
        _bid(CAROL);
        uint256[] memory ticks = new uint256[](3);
        ticks[0] = 100;
        ticks[1] = 70;
        ticks[2] = 40;
        vm.warp(ENDS);
        _settle(abi.encode(ticks));
        require(auction.winner() == ALICE, "highest bidder lost");
        require(auction.winningBid() == 100 * fineTick && auction.winningPrice() == 70 * fineTick, "wrong second price");
        require(auction.credits(ALICE) == COLLATERAL - 70 * fineTick, "winner refund wrong");
        require(auction.credits(SELLER) == 70 * fineTick, "seller price wrong");
    }

    function testZeroTicksAbstainAndReturnAssetToSeller() public {
        _open();
        _bid(ALICE);
        _bid(BOB);
        vm.warp(ENDS);
        _settle(_two(0, 0));
        require(auction.winner() == address(0) && auction.winningPrice() == 0, "abstention won");
        require(nft.ownerOf(tokenId) == SELLER, "asset not returned");
        require(auction.credits(ALICE) == COLLATERAL && auction.credits(BOB) == COLLATERAL, "refund wrong");
    }

    function testResultLengthAndTickRangeValidated() public {
        _open();
        _bid(ALICE);
        vm.warp(ENDS);
        bytes memory result = _two(2, 3);
        source.accept(auction, result);
        vm.expectRevert(SealedBidAuction.InvalidResult.selector);
        auction.settle(result);
        result = _one(10);
        source.accept(auction, result);
        vm.expectRevert(SealedBidAuction.InvalidResult.selector);
        auction.settle(result);
        require(auction.totalCredits() == 0 && nft.ownerOf(tokenId) == address(auction), "partial settlement");
    }

    function testMalformedAuthenticatedBytesRevertWithoutEffects() public {
        _open();
        _bid(ALICE);
        vm.warp(ENDS);
        bytes memory malformed = hex"0102";
        source.accept(auction, malformed);
        vm.expectRevert();
        auction.settle(malformed);
        require(auction.state() == SealedBidAuction.State.Bidding, "malformed result changed state");
    }

    function testSettlementAtDeadlineRejectedAndCancellationAllowed() public {
        _open();
        _bid(ALICE);
        bytes memory result = _one(9);
        source.accept(auction, result);
        vm.warp(DEADLINE);
        vm.expectRevert(SealedBidAuction.SettlementExpired.selector);
        auction.settle(result);
        vm.prank(CAROL);
        auction.cancel();
        require(nft.ownerOf(tokenId) == SELLER, "seller NFT missing");
        require(auction.credits(ALICE) == COLLATERAL, "timeout refund wrong");
        require(auction.totalCredits() == address(auction).balance, "timeout ledger wrong");
    }

    function testCancellationWaitsForDeadlineWhenBidsExist() public {
        _open();
        _bid(ALICE);
        vm.expectRevert(SealedBidAuction.BiddingStillOpen.selector);
        auction.cancel();
        vm.warp(ENDS);
        vm.expectRevert(SealedBidAuction.SettlementStillAvailable.selector);
        auction.cancel();
        vm.warp(DEADLINE - 1);
        vm.expectRevert(SealedBidAuction.SettlementStillAvailable.selector);
        auction.cancel();
    }

    function testNoBidAuctionCanCancelAtBiddingClose() public {
        _open();
        vm.warp(ENDS);
        auction.cancel();
        require(auction.state() == SealedBidAuction.State.Cancelled, "not cancelled");
        require(nft.ownerOf(tokenId) == SELLER && auction.totalCredits() == 0, "no-bid cancellation wrong");
    }

    function testSettledAuctionCannotSettleOrCancelAgain() public {
        _open();
        _bid(ALICE);
        vm.warp(ENDS);
        bytes memory result = _one(4);
        _settle(result);
        vm.expectRevert(SealedBidAuction.InvalidState.selector);
        auction.settle(result);
        vm.expectRevert(SealedBidAuction.InvalidState.selector);
        auction.cancel();
    }

    function testBidLimitIsEnforced() public {
        SealedBidAuction small =
            new SealedBidAuction(SELLER, address(nft), tokenId, COLLATERAL, TICK, 10, 1, address(source));
        vm.prank(SELLER);
        nft.approve(address(small), tokenId);
        vm.prank(SELLER);
        small.open(E3_ID, ENDS, DEADLINE);
        vm.prank(ALICE);
        small.submitBid{value: COLLATERAL}(0, hex"01", bytes32(0));
        vm.prank(BOB);
        vm.expectRevert(SealedBidAuction.AuctionFull.selector);
        small.submitBid{value: COLLATERAL}(1, hex"02", bytes32(0));
    }

    function testFull32BidderAuctionSettlesAndConservesLedger() public {
        _open();
        uint256[] memory ticks = new uint256[](32);
        for (uint256 i; i < 32; ++i) {
            address bidder = address(uint160(0x10000 + i));
            vm.deal(bidder, COLLATERAL);
            vm.prank(bidder);
            auction.submitBid{value: COLLATERAL}(uint32(i), hex"010203", keccak256(abi.encode(i)));
            ticks[i] = i + 1 == 32 ? 9 : 1;
        }
        vm.prank(ALICE);
        vm.expectRevert(SealedBidAuction.AuctionFull.selector);
        auction.submitBid{value: COLLATERAL}(32, hex"04", bytes32(0));
        vm.warp(ENDS);
        _settle(abi.encode(ticks));
        require(auction.winner() == address(uint160(0x10000 + 31)), "last bidder ignored");
        require(auction.winningPrice() == TICK && auction.winningBid() == 9 * TICK, "maximum second price wrong");
        require(auction.totalCredits() == 32 * COLLATERAL, "maximum ledger mismatch");
        require(address(auction).balance == 32 * COLLATERAL, "maximum ETH mismatch");
    }

    function testSellerMayBidWithoutLosingRefundAccounting() public {
        _open();
        _bid(SELLER);
        _bid(ALICE);
        vm.warp(ENDS);
        _settle(_two(9, 3));
        require(auction.winner() == SELLER && nft.ownerOf(tokenId) == SELLER, "seller bid result wrong");
        require(auction.credits(SELLER) == COLLATERAL, "seller credits not combined");
        require(auction.credits(ALICE) == COLLATERAL, "loser credit wrong");
        require(auction.totalCredits() == 2 * COLLATERAL, "seller bid ledger mismatch");
    }

    function testRejectedOpenNFTTransferRollsBackState() public {
        ToggleAuctionNFT badNFT = new ToggleAuctionNFT(SELLER);
        SealedBidAuction other = _deploy(address(badNFT));
        badNFT.setReject(true);
        vm.prank(SELLER);
        vm.expectRevert(ToggleAuctionNFT.Rejected.selector);
        other.open(E3_ID, ENDS, DEADLINE);
        require(other.state() == SealedBidAuction.State.Created && other.e3Id() == 0, "open not rolled back");
    }

    function testNFTNoOpTransferCannotPretendEscrow() public {
        ToggleAuctionNFT badNFT = new ToggleAuctionNFT(SELLER);
        SealedBidAuction other = _deploy(address(badNFT));
        badNFT.setIgnore(true);
        vm.prank(SELLER);
        vm.expectRevert(SealedBidAuction.NFTTransferFailed.selector);
        other.open(E3_ID, ENDS, DEADLINE);
    }

    function testRejectedSettlementNFTTransferRollsBackCreditsAndWinner() public {
        ToggleAuctionNFT badNFT = new ToggleAuctionNFT(SELLER);
        SealedBidAuction other = _deploy(address(badNFT));
        vm.prank(SELLER);
        other.open(E3_ID, ENDS, DEADLINE);
        vm.prank(ALICE);
        other.submitBid{value: COLLATERAL}(0, hex"01", bytes32(0));
        bytes memory result = _one(4);
        source.accept(other, result);
        badNFT.setReject(true);
        vm.warp(ENDS);
        vm.expectRevert(ToggleAuctionNFT.Rejected.selector);
        other.settle(result);
        require(other.state() == SealedBidAuction.State.Bidding, "state not rolled back");
        require(other.winner() == address(0) && other.totalCredits() == 0, "payout not rolled back");
        require(address(other).balance == COLLATERAL, "collateral lost");
    }

    function testWithdrawCanChooseRecipientAndCannotRepeat() public {
        _open();
        _bid(ALICE);
        vm.warp(DEADLINE);
        auction.cancel();
        uint256 beforeBalance = CAROL.balance;
        vm.prank(ALICE);
        auction.withdraw(payable(CAROL));
        require(CAROL.balance == beforeBalance + COLLATERAL && auction.credits(ALICE) == 0, "recipient refund wrong");
        vm.prank(ALICE);
        vm.expectRevert(SealedBidAuction.NothingToWithdraw.selector);
        auction.withdraw(payable(ALICE));
    }

    function testRejectedWithdrawalRestoresCreditAndCanReroute() public {
        _open();
        AuctionRefundReceiver receiver = new AuctionRefundReceiver(auction);
        receiver.bid{value: COLLATERAL}();
        vm.warp(DEADLINE);
        auction.cancel();
        receiver.configure(true, false);
        vm.expectRevert(SealedBidAuction.TransferFailed.selector);
        receiver.withdrawTo(payable(address(receiver)));
        require(auction.credits(address(receiver)) == COLLATERAL, "credit erased");
        require(auction.totalCredits() == COLLATERAL, "ledger erased");
        receiver.withdrawTo(payable(ALICE));
        require(auction.totalCredits() == 0, "reroute failed");
    }

    function testReentrantWithdrawalCannotDoubleSpend() public {
        _open();
        AuctionRefundReceiver receiver = new AuctionRefundReceiver(auction);
        receiver.bid{value: COLLATERAL}();
        vm.warp(DEADLINE);
        auction.cancel();
        receiver.configure(false, true);
        receiver.withdrawTo(payable(address(receiver)));
        require(!receiver.reentrySucceeded() && receiver.receiveCount() == 1, "reentry succeeded");
        require(address(receiver).balance == COLLATERAL, "paid twice");
        require(auction.totalCredits() == 0 && address(auction).balance == 0, "ledger mismatch");
    }

    function testZeroWithdrawalRecipientRejectedWithoutLosingCredit() public {
        _open();
        _bid(ALICE);
        vm.warp(DEADLINE);
        auction.cancel();
        vm.prank(ALICE);
        vm.expectRevert(SealedBidAuction.TransferFailed.selector);
        auction.withdraw(payable(address(0)));
        require(auction.credits(ALICE) == COLLATERAL, "credit lost");
    }

    function testInvalidConfigurationRejected() public {
        vm.expectRevert(SealedBidAuction.InvalidConfiguration.selector);
        new SealedBidAuction(address(0), address(nft), tokenId, COLLATERAL, TICK, 10, 32, address(source));
        vm.expectRevert(SealedBidAuction.InvalidConfiguration.selector);
        new SealedBidAuction(SELLER, address(nft), tokenId, COLLATERAL, TICK, 10, 33, address(source));
        vm.expectRevert(SealedBidAuction.InvalidConfiguration.selector);
        new SealedBidAuction(SELLER, address(nft), tokenId, COLLATERAL, COLLATERAL, 10, 32, address(source));
        vm.expectRevert(SealedBidAuction.InvalidConfiguration.selector);
        new SealedBidAuction(SELLER, address(nft), tokenId, 0, TICK, 10, 32, address(source));
        vm.expectRevert(SealedBidAuction.InvalidConfiguration.selector);
        new SealedBidAuction(SELLER, ALICE, tokenId, COLLATERAL, TICK, 10, 32, address(source));
    }

    function testFuzzCreditsConserved(uint8 aliceTick, uint8 bobTick) public {
        aliceTick %= 10;
        bobTick %= 10;
        _open();
        _bid(ALICE);
        _bid(BOB);
        vm.warp(ENDS);
        _settle(_two(aliceTick, bobTick));
        require(
            auction.credits(ALICE) + auction.credits(BOB) + auction.credits(SELLER) == 2 * COLLATERAL,
            "credits not conserved"
        );
        require(auction.totalCredits() == address(auction).balance, "ETH not conserved");
        address expectedWinner = aliceTick == 0 && bobTick == 0 ? address(0) : aliceTick >= bobTick ? ALICE : BOB;
        require(auction.winner() == expectedWinner, "argmax mismatch");
        require(auction.winningPrice() == (aliceTick < bobTick ? aliceTick : bobTick) * TICK, "second price mismatch");
        require(auction.winningBid() == (aliceTick > bobTick ? aliceTick : bobTick) * TICK, "winning bid mismatch");
    }

    function _deploy(address nft_) private returns (SealedBidAuction) {
        return new SealedBidAuction(SELLER, nft_, tokenId, COLLATERAL, TICK, 10, 32, address(source));
    }

    function _open() private {
        vm.prank(SELLER);
        auction.open(E3_ID, ENDS, DEADLINE);
    }

    function _bid(address account) private {
        uint32 index = uint32(auction.bidCount());
        vm.prank(account);
        auction.submitBid{value: COLLATERAL}(index, hex"010203", keccak256(abi.encode(account)));
    }

    function _settle(bytes memory result) private {
        source.accept(auction, result);
        auction.settle(result);
    }

    function _one(uint256 a) private pure returns (bytes memory) {
        uint256[] memory ticks = new uint256[](1);
        ticks[0] = a;
        return abi.encode(ticks);
    }

    function _two(uint256 a, uint256 b) private pure returns (bytes memory) {
        uint256[] memory ticks = new uint256[](2);
        ticks[0] = a;
        ticks[1] = b;
        return abi.encode(ticks);
    }

    receive() external payable {}
}
