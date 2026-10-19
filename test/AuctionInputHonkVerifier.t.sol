// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {HonkVerifier} from "../src/generated/AuctionInputHonkVerifier.sol";
import {AuctionInputVerifier} from "../src/AuctionInputVerifier.sol";
import {IAuctionInputVerifier, IAuctionOpenVmVerifier} from "../src/interfaces/IAuctionProofs.sol";

interface VmInputFixture {
    function readFileBinary(string calldata path) external view returns (bytes memory);
}

/// @dev Explicit receipt test double. These tests use the REAL Noir proof and
/// generated verifier; they do not claim to verify an actual OpenVM receipt.
contract BindingReceiptDoubleForRealNoir is IAuctionOpenVmVerifier {
    bytes32 public constant imageId = keccak256("test-double-input-binding-image");
    bytes32 public expectedDigest;

    function configure(bytes32 digest) external {
        expectedDigest = digest;
    }

    function verify(bytes calldata seal, bytes32 image, bytes32 digest) external view {
        require(keccak256(seal) == keccak256(hex"1234"), "test double seal");
        require(image == imageId && digest == expectedDigest, "test double statement");
    }
}

contract AuctionInputHonkVerifierTest {
    VmInputFixture private constant vm =
        VmInputFixture(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 private constant ACIR_SHA256 = 0xeb4c1699b4f25cf4bf86709095cb51c06d31acbf6cee16d6b7ce304770319eb6;
    HonkVerifier private honk;
    BindingReceiptDoubleForRealNoir private binding;
    AuctionInputVerifier private composed;
    IAuctionInputVerifier.Statement private statement;
    bytes private proof;
    bytes32[] private publicInputs;

    event log_named_uint(string key, uint256 value);

    function setUp() public {
        honk = new HonkVerifier();
        binding = new BindingReceiptDoubleForRealNoir();
        composed = new AuctionInputVerifier(address(honk), address(binding), ACIR_SHA256, binding.imageId());
        proof = vm.readFileBinary("test/fixtures/auction-input/proof.bin");
        bytes memory raw = vm.readFileBinary("test/fixtures/auction-input/public-inputs.bin");
        require(raw.length == 26 * 32, "fixture public input count");
        for (uint256 i; i < 26; ++i) {
            bytes32 limb;
            assembly ("memory-safe") {
                limb := mload(add(add(raw, 32), mul(i, 32)))
            }
            publicInputs.push(limb);
        }
        statement = abi.decode(
            vm.readFileBinary("test/fixtures/auction-input/statement.bin"), (IAuctionInputVerifier.Statement)
        );
        binding.configure(sha256(abi.encode(statement)));
    }

    function testRealEvmZkProofVerifies() public {
        uint256 beforeGas = gasleft();
        require(honk.verify(proof, publicInputs), "real proof rejected");
        emit log_named_uint("real encryption verification gas", beforeGas - gasleft());
    }

    function testRealProofRejectsChangedContext() public {
        publicInputs[8] = bytes32(uint256(publicInputs[8]) ^ 1);
        require(!accepts(proof, publicInputs), "changed public statement accepted");
    }

    function testRealProofRejectsTamperedSumcheckScalar() public {
        // Preserve every curve point and change the first sumcheck scalar's low
        // bit in the pinned bb5.2.0 EVM ZK layout. This tests relation failure.
        proof[959] = bytes1(uint8(proof[959]) ^ 1);
        require(!accepts(proof, publicInputs), "tampered proof accepted");
    }

    function testComposedAdapterUsesRealEncryptionProof() public view {
        require(composed.verify(abi.encode(proof, hex"1234"), statement), "composition rejected");
    }

    function testComposedAdapterCannotReuseProofForDifferentBidder() public {
        statement.bidder = address(0x4444);
        // Let the receipt double authenticate the changed statement. The actual
        // Noir proof must still reject reuse for a different bidder.
        binding.configure(sha256(abi.encode(statement)));
        require(!composed.verify(abi.encode(proof, hex"1234"), statement), "bidder substitution accepted");
    }

    function testComposedAdapterRejectsWrongBindingSeal() public view {
        require(!composed.verify(abi.encode(proof, hex"1235"), statement), "wrong receipt accepted");
    }

    function accepts(bytes memory candidate, bytes32[] memory inputs) private view returns (bool) {
        (bool ok, bytes memory result) =
            address(honk).staticcall(abi.encodeCall(honk.verify, (candidate, inputs)));
        return ok && result.length == 32 && abi.decode(result, (bool));
    }
}
