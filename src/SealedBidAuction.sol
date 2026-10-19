// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice The deployment-specific bridge to an authenticated Interfold result.
/// @dev A production implementation must authenticate the complete tuple below;
/// accepting an unverified plaintext result would destroy the sealed-bid property.
interface IAuctionResultSource {
    function isReady() external view returns (bool);

    function validateAuction(bytes32 auctionContext, uint256 e3Id, uint64 biddingEnds) external view returns (bool);

    function publishBid(
        bytes32 auctionContext,
        uint256 e3Id,
        uint32 index,
        address bidder,
        bytes calldata envelope,
        bytes32 commitment,
        bytes32 nextInputRoot
    ) external;

    function verifyResult(
        bytes32 auctionContext,
        uint256 e3Id,
        bytes32 inputRoot,
        uint256 bidCount,
        bytes calldata result
    ) external view returns (bool);
}

interface IAuctionNFT {
    function ownerOf(uint256 tokenId) external view returns (address);
    function transferFrom(address from, address to, uint256 tokenId) external;
}

/// @notice One collateralized, second-price, sealed-bid ERC721 auction.
/// @dev Bids are opaque ciphertext until an authenticated result is available.
/// Every bidder deposits the same collateral. Settlement publishes every bid's
/// tick value, picks the highest positive bid, and resolves ties by input order.
/// The winner pays the second-highest tick, including an equal highest bid;
/// a sole positive bidder pays zero because this pilot has no reserve price.
/// No administrator can withdraw collateral or replace the result source.
contract SealedBidAuction {
    enum State {
        Created,
        Bidding,
        Settled,
        Cancelled
    }

    struct Bid {
        address bidder;
        bytes32 ciphertextHash;
        bytes32 commitment;
    }

    uint256 public constant MAX_CIPHERTEXT_BYTES = 16_384;
    uint32 public constant HARD_MAX_BIDDERS = 32;

    address public immutable seller;
    IAuctionNFT public immutable nft;
    uint256 public immutable tokenId;
    uint256 public immutable collateralWei;
    uint256 public immutable tickWei;
    uint16 public immutable priceLevels;
    uint32 public immutable maxBidders;
    IAuctionResultSource public immutable resultSource;

    State public state;
    uint256 public e3Id;
    uint64 public biddingEnds;
    uint64 public settlementDeadline;
    bytes32 public inputRoot;
    address public winner;
    uint256 public winningBid;
    /// @notice The actual second-price payment, denominated in wei.
    uint256 public winningPrice;
    Bid[] public bids;
    mapping(address => bool) public hasBid;
    mapping(address => uint256) public credits;
    uint256 public totalCredits;
    bool private entered;

    error InvalidConfiguration();
    error OnlySeller();
    error InvalidState();
    error ResultSourceNotReady();
    error InvalidComputation();
    error InvalidDeadlines();
    error BiddingClosed();
    error BiddingStillOpen();
    error SettlementExpired();
    error SettlementStillAvailable();
    error WrongCollateral();
    error DuplicateBid();
    error BidIndexChanged();
    error AuctionFull();
    error InvalidCiphertext();
    error UnauthenticatedResult();
    error InvalidResult();
    error NothingToWithdraw();
    error TransferFailed();
    error NFTTransferFailed();
    error Reentrancy();

    event AuctionOpened(uint256 indexed e3Id, uint64 biddingEnds, uint64 settlementDeadline, bytes32 auctionContext);
    event BidSubmitted(
        uint256 indexed index, address indexed bidder, bytes ciphertext, bytes32 commitment, bytes32 inputRoot
    );
    event AuctionSettled(address indexed winner, uint256 winningPrice, bytes result);
    event AuctionCancelled();
    event Withdrawal(address indexed account, address indexed recipient, uint256 amount);

    modifier nonReentrant() {
        if (entered) revert Reentrancy();
        entered = true;
        _;
        entered = false;
    }

    constructor(
        address seller_,
        address nft_,
        uint256 tokenId_,
        uint256 collateralWei_,
        uint256 tickWei_,
        uint16 priceLevels_,
        uint32 maxBidders_,
        address resultSource_
    ) {
        if (
            seller_ == address(0) || nft_.code.length == 0 || resultSource_.code.length == 0 || collateralWei_ == 0
                || tickWei_ == 0 || priceLevels_ < 2 || maxBidders_ == 0 || maxBidders_ > HARD_MAX_BIDDERS
                || tickWei_ > collateralWei_ / (priceLevels_ - 1)
        ) revert InvalidConfiguration();
        seller = seller_;
        nft = IAuctionNFT(nft_);
        tokenId = tokenId_;
        collateralWei = collateralWei_;
        tickWei = tickWei_;
        priceLevels = priceLevels_;
        maxBidders = maxBidders_;
        resultSource = IAuctionResultSource(resultSource_);
    }

    /// @notice Fix the computation and deadlines, and escrow the seller's token.
    function open(uint256 e3Id_, uint64 biddingEnds_, uint64 settlementDeadline_) external nonReentrant {
        if (msg.sender != seller) revert OnlySeller();
        if (state != State.Created) revert InvalidState();
        if (!resultSource.isReady()) revert ResultSourceNotReady();
        if (biddingEnds_ <= block.timestamp || settlementDeadline_ <= biddingEnds_) revert InvalidDeadlines();

        e3Id = e3Id_;
        biddingEnds = biddingEnds_;
        settlementDeadline = settlementDeadline_;
        state = State.Bidding;
        inputRoot = auctionContext();
        if (!resultSource.validateAuction(inputRoot, e3Id_, biddingEnds_)) revert InvalidComputation();
        nft.transferFrom(seller, address(this), tokenId);
        if (nft.ownerOf(tokenId) != address(this)) revert NFTTransferFailed();
        emit AuctionOpened(e3Id_, biddingEnds_, settlementDeadline_, inputRoot);
    }

    /// @notice Domain separator for this exact deployment, asset and computation.
    /// @dev The canonical encoding is abi.encode(chainid, auction address, seller,
    /// nft address, tokenId, collateralWei, tickWei, priceLevels, maxBidders,
    /// e3Id, biddingEnds, settlementDeadline), then keccak256.
    function auctionContext() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                block.chainid,
                address(this),
                seller,
                address(nft),
                tokenId,
                collateralWei,
                tickWei,
                priceLevels,
                maxBidders,
                e3Id,
                biddingEnds,
                settlementDeadline
            )
        );
    }

    function bidCount() external view returns (uint256) {
        return bids.length;
    }

    /// @notice Submit one serialized ciphertext/proof envelope and uniform collateral.
    /// @dev The result source synchronously admits the envelope through the pinned
    /// E3 program, which must enforce ciphertext validity, slot/range and
    /// bid/commitment binding. A rejected envelope rolls back the deposit and bid.
    /// This bounded envelope may reference encrypted input on Avail; a full
    /// secure8192 ciphertext is not expected to fit in an inline transaction.
    /// The program must also verify availability and bind the referenced data.
    /// The canonical append operation is
    /// keccak256(abi.encode(previousRoot, zeroBasedIndex, bidder,
    /// keccak256(ciphertext), commitment)). The verifier must bind this root.
    /// Read bidCount before encrypting for the corresponding coefficient. If
    /// another bidder arrives first, retry with newly encrypted input for the
    /// updated index; an envelope for the previous slot must not be reused.
    function submitBid(uint32 expectedIndex, bytes calldata ciphertext, bytes32 commitment)
        external
        payable
        nonReentrant
    {
        if (state != State.Bidding) revert InvalidState();
        if (block.timestamp >= biddingEnds) revert BiddingClosed();
        if (msg.value != collateralWei) revert WrongCollateral();
        if (hasBid[msg.sender]) revert DuplicateBid();
        if (uint256(expectedIndex) != bids.length) revert BidIndexChanged();
        if (bids.length >= maxBidders) revert AuctionFull();
        if (ciphertext.length == 0 || ciphertext.length > MAX_CIPHERTEXT_BYTES) revert InvalidCiphertext();

        uint256 index = bids.length;
        bytes32 ciphertextHash = keccak256(ciphertext);
        bids.push(Bid(msg.sender, ciphertextHash, commitment));
        hasBid[msg.sender] = true;
        inputRoot = keccak256(abi.encode(inputRoot, index, msg.sender, ciphertextHash, commitment));
        resultSource.publishBid(auctionContext(), e3Id, expectedIndex, msg.sender, ciphertext, commitment, inputRoot);
        emit BidSubmitted(index, msg.sender, ciphertext, commitment, inputRoot);
    }

    /// @notice Settle an authenticated abi.encode(uint256[] bidTicks) result.
    /// @dev Tick zero means abstention. All plaintext ticks become public here.
    /// The source must verify result provenance and its binding to all inputs.
    function settle(bytes calldata result) external nonReentrant {
        if (state != State.Bidding) revert InvalidState();
        if (block.timestamp < biddingEnds) revert BiddingStillOpen();
        if (block.timestamp >= settlementDeadline) revert SettlementExpired();
        uint256 count = bids.length;
        if (!resultSource.verifyResult(auctionContext(), e3Id, inputRoot, count, result)) {
            revert UnauthenticatedResult();
        }
        uint256[] memory ticks = abi.decode(result, (uint256[]));
        if (ticks.length != count) revert InvalidResult();

        uint256 highest;
        uint256 secondHighest;
        address selected;
        for (uint256 i; i < count; ++i) {
            uint256 tick = ticks[i];
            if (tick >= priceLevels) revert InvalidResult();
            if (tick > highest) {
                secondHighest = highest;
                highest = tick;
                selected = bids[i].bidder;
            } else if (tick > secondHighest) {
                secondHighest = tick;
            }
        }

        uint256 price = secondHighest * tickWei;
        if (price > collateralWei) revert InvalidResult();
        state = State.Settled;
        winner = selected;
        winningBid = highest * tickWei;
        winningPrice = price;
        for (uint256 i; i < count; ++i) {
            address bidder = bids[i].bidder;
            _credit(bidder, bidder == selected ? collateralWei - price : collateralWei);
        }
        _credit(seller, price);
        nft.transferFrom(address(this), selected == address(0) ? seller : selected, tokenId);
        if (nft.ownerOf(tokenId) != (selected == address(0) ? seller : selected)) revert NFTTransferFailed();
        emit AuctionSettled(selected, price, result);
    }

    /// @notice Refund everyone if the authenticated computation does not arrive.
    /// No-bid auctions can be cancelled immediately once bidding ends.
    function cancel() external nonReentrant {
        if (state != State.Bidding) revert InvalidState();
        if (block.timestamp < biddingEnds) revert BiddingStillOpen();
        if (bids.length != 0 && block.timestamp < settlementDeadline) revert SettlementStillAvailable();

        state = State.Cancelled;
        for (uint256 i; i < bids.length; ++i) {
            _credit(bids[i].bidder, collateralWei);
        }
        nft.transferFrom(address(this), seller, tokenId);
        if (nft.ownerOf(tokenId) != seller) revert NFTTransferFailed();
        emit AuctionCancelled();
    }

    /// @notice Withdraw your credit to a recipient you control.
    /// @dev Choosing a recipient permits refunds to contracts that reject ETH.
    function withdraw(address payable recipient) external nonReentrant {
        if (recipient == address(0)) revert TransferFailed();
        uint256 amount = credits[msg.sender];
        if (amount == 0) revert NothingToWithdraw();
        credits[msg.sender] = 0;
        totalCredits -= amount;
        (bool success,) = recipient.call{value: amount}("");
        if (!success) revert TransferFailed();
        emit Withdrawal(msg.sender, recipient, amount);
    }

    function _credit(address account, uint256 amount) private {
        credits[account] += amount;
        totalCredits += amount;
    }
}
