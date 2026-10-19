// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import {AuctionInputVerifier} from "../src/AuctionInputVerifier.sol";
import {IAuctionInputVerifier} from "../src/interfaces/IAuctionProofs.sol";

// Explicit TEST DOUBLES: validate composition, not the cryptographic proof systems.
contract CompositionNoirDouble {
    bytes32 public expectedInputs;
    bool public reject;
    function configure(bytes32 value, bool reject_) external { expectedInputs = value; reject = reject_; }
    function verify(bytes calldata proof, bytes32[] calldata inputs) external view returns (bool) {
        return !reject && keccak256(proof) == keccak256(hex"aabb") && keccak256(abi.encode(inputs)) == expectedInputs;
    }
}
contract CompositionReceiptDouble {
    bytes32 public constant imageId = keccak256("TEST ONLY binding image");
    bytes32 public expectedDigest;
    function configure(bytes32 value) external { expectedDigest = value; }
    function verify(bytes calldata seal, bytes32 image, bytes32 digest) external view {
        require(keccak256(seal) == keccak256(hex"ccdd") && image == imageId && digest == expectedDigest);
    }
}
contract AuctionInputVerifierCompositionTest {
    AuctionInputVerifier private verifier;
    CompositionNoirDouble private noir;
    CompositionReceiptDouble private receipt;
    IAuctionInputVerifier.Statement private s;
    function setUp() public {
        noir = new CompositionNoirDouble(); receipt = new CompositionReceiptDouble();
        verifier = new AuctionInputVerifier(address(noir), address(receipt), keccak256("TEST ACIR"), receipt.imageId());
        s = IAuctionInputVerifier.Statement({chainId:11155111, program:address(1), interfold:address(2), auction:address(3),
            context:bytes32(type(uint256).max), e3Id:type(uint256).max - 1,
            committeePublicKey:bytes32(uint256(7)), paramsHash:0x1b2620f6a5919d5ee19a51f34026369816f479efd0404b56585ad37d31c52317,
            slot:31, bidder:address(4), maxTick:100, ciphertextHash:bytes32(type(uint256).max - 2), ciphertextCommitment:bytes32(uint256(8))});
        bind();
    }
    function bind() private {
        bytes memory encoded = abi.encode(s);
        bytes32[] memory inputs = new bytes32[](26);
        for (uint256 i; i < 13; ++i) {
            uint256 value;
            assembly ("memory-safe") { value := mload(add(add(encoded,32),mul(i,32))) }
            inputs[i*2] = bytes32(value >> 128);
            inputs[i*2+1] = bytes32(uint256(uint128(value)));
        }
        noir.configure(keccak256(abi.encode(inputs)), false);
        receipt.configure(sha256(encoded));
    }
    function proof() private pure returns(bytes memory) { return abi.encode(hex"aabb",hex"ccdd"); }
    function testBothProofsAuthenticateSameFullWidthStatement() public view { require(verifier.verify(proof(),s)); }
    function testNoirRejectionCannotBeReplacedByBindingReceipt() public {
        noir.configure(bytes32(0),true); require(!verifier.verify(proof(),s));
    }
    function testBindingRejectionCannotBeReplacedByEncryptionProof() public {
        receipt.configure(bytes32(0)); require(!verifier.verify(proof(),s));
    }
    function testEveryStatementWordAndBothHighLowLimbsAreBound() public view {
        bytes memory original = abi.encode(s);
        for(uint256 i; i<26; ++i) {
            bytes memory altered = bytes.concat(original);
            // Touch both high and low limbs; address high limbs must remain canonical.
            uint256 wordIndex=i/2;
            bool addressWord=wordIndex==1 || wordIndex==2 || wordIndex==3 || wordIndex==9;
            if(addressWord && i%2==0) continue;
            altered[(i/2)*32 + (i%2==0 ? 15 : 31)] ^= 0x01;
            IAuctionInputVerifier.Statement memory changed=abi.decode(altered,(IAuctionInputVerifier.Statement));
            require(!verifier.verify(proof(),changed));
        }
    }
    function testRejectsTamperedProofs() public view {
        require(!verifier.verify(abi.encode(hex"aa00",hex"ccdd"),s));
        require(!verifier.verify(abi.encode(hex"aabb",hex"cc00"),s));
        require(!verifier.verify(abi.encode(hex"",hex"ccdd"),s));
    }
    function testRejectsFieldAliasesBeforeNoirVerification() public {
        s.committeePublicKey=bytes32(uint256(21888242871839275222246405745257275088548364400416034343698204186575808495617)+7);
        bind(); require(!verifier.verify(proof(),s));
    }
    function testRejectsTrailingProofData() public view {
        (bool success,) = address(verifier).staticcall(abi.encodeCall(verifier.verify,(bytes.concat(proof(),hex"00"),s)));
        require(!success);
    }
}
