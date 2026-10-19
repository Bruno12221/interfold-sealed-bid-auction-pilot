// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {
    OpenVmReceiptVerifier,
    IOpenVmHalo2Verifier
} from "../src/vendor/interfold-openvm/verifiers/OpenVmReceiptVerifier.sol";
import {HonkVerifier} from "../src/generated/AuctionInputHonkVerifier.sol";
import {AuctionInputVerifier} from "../src/AuctionInputVerifier.sol";
import {IAuctionInputVerifier} from "../src/interfaces/IAuctionProofs.sol";

interface RealReceiptVm {
    function readFile(string calldata path) external view returns (string memory);
    function readFileBinary(string calldata path) external view returns (bytes memory);
    function parseJsonString(string calldata json, string calldata key) external pure returns (string memory);
    function parseBytes(string calldata value) external pure returns (bytes memory);
    function expectRevert() external;
    function expectRevert(bytes4 selector) external;
}

/// @notice Actual returned Halo2 receipts, the pinned generated Halo2 verifier,
/// upstream receipt adapters and the generated Noir encryption verifier.
/// @dev These are independent public synthetic fixtures. No protocol, threshold
/// network, availability service, live bid or complete auction is exercised here.
contract RealOpenVmReceiptsTest {
    RealReceiptVm private constant vm = RealReceiptVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 private constant VM_COMMIT = 0x009034802c4d22df352e22772fc613453a77e387b95479ef296bbef78edc588a;
    bytes32 private constant BINDING_EXECUTABLE = 0x004ab89ac541e865a9e923b17383576c96451d9e3f2cba48c268265e780be415;
    bytes32 private constant COMPUTE_EXECUTABLE = 0x003e89acda47eb25b207e4284781fa9f0f900201af2457c47f7a41c5f4fdfede;
    bytes32 private constant BINDING_DIGEST = 0x639f28c18424c45b4c298c3d19aeb5b11a5c3ff9a7e984426e301bf32056ec13;
    bytes32 private constant COMPUTE_DIGEST = 0x950c64bc9fc6a964720484dc6ba682752acfba2ac79d4a97538f7895b6fe4f78;
    bytes32 private constant VERIFIER_ARTIFACT_SHA256 =
        0x6f2dac7ec5dd42fbff0d5a1e5ba99e3b53c005d94dc699b5dc4c50b0bd891b99;
    bytes32 private constant ACIR_SHA256 = 0xeb4c1699b4f25cf4bf86709095cb51c06d31acbf6cee16d6b7ce304770319eb6;

    IOpenVmHalo2Verifier private halo2;
    OpenVmReceiptVerifier private binding;
    OpenVmReceiptVerifier private compute;
    bytes32 private bindingImage;
    bytes32 private computeImage;
    bytes private bindingSeal;
    bytes private computeSeal;
    bytes private bindingJournal;
    AuctionInputVerifier private composed;
    IAuctionInputVerifier.Statement private statement;
    bytes private encryptionProof;

    event log_named_uint(string key, uint256 value);

    function setUp() public {
        string memory artifact = vm.readFile("test/fixtures/openvm-receipts/verifier.bytecode.json");
        require(sha256(bytes(artifact)) == VERIFIER_ARTIFACT_SHA256, "generated verifier artifact differs");
        // Deploy the exact OpenVM-generated solc 0.8.19 creation bytecode. The
        // generated verifier is not recompiled or replaced by a Solidity double.
        bytes memory creation = vm.parseBytes(string.concat("0x", vm.parseJsonString(artifact, ".bytecode")));
        require(creation.length == 19_781, "generated verifier creation length differs");
        address deployed;
        assembly ("memory-safe") {
            deployed := create(0, add(creation, 32), mload(creation))
        }
        require(deployed != address(0) && deployed.code.length != 0, "generated verifier deployment failed");
        halo2 = IOpenVmHalo2Verifier(deployed);
        binding = new OpenVmReceiptVerifier(halo2, BINDING_EXECUTABLE, VM_COMMIT);
        compute = new OpenVmReceiptVerifier(halo2, COMPUTE_EXECUTABLE, VM_COMMIT);
        bindingImage = binding.imageId();
        computeImage = compute.imageId();
        require(bindingImage != computeImage, "application receipt identities collided");

        bindingSeal = vm.readFileBinary("test/fixtures/openvm-receipts/binding.seal.bin");
        computeSeal = vm.readFileBinary("test/fixtures/openvm-receipts/compute.seal.bin");
        bindingJournal = vm.readFileBinary("test/fixtures/openvm-receipts/binding.journal.bin");
        bytes memory computeJournal = vm.readFileBinary("test/fixtures/openvm-receipts/compute.journal.bin");
        require(bindingJournal.length == 416 && sha256(bindingJournal) == BINDING_DIGEST, "binding journal differs");
        require(computeJournal.length == 288 && sha256(computeJournal) == COMPUTE_DIGEST, "compute journal differs");
        require(
            bindingSeal.length == 1856
                && sha256(bindingSeal) == 0x7e0edca80f2f682deb45a9f4113ace9daa252e84568199e66d2156b8d1f1374d,
            "binding seal differs"
        );
        require(
            computeSeal.length == 1856
                && sha256(computeSeal) == 0x4bb590a02ba5179a668c6a9ceab84fac8115b1da58556f28a7b6ce3f450ffe10,
            "compute seal differs"
        );

        HonkVerifier honk = new HonkVerifier();
        composed = new AuctionInputVerifier(address(honk), address(binding), ACIR_SHA256, bindingImage);
        encryptionProof = vm.readFileBinary("test/fixtures/auction-input/proof.bin");
        bytes memory existingStatement = vm.readFileBinary("test/fixtures/auction-input/statement.bin");
        require(keccak256(existingStatement) == keccak256(bindingJournal), "Noir and binding statements differ");
        statement = abi.decode(existingStatement, (IAuctionInputVerifier.Statement));
    }

    function testReturnedBindingReceiptVerifiesWithActualGeneratedHalo2Verifier() public {
        uint256 beforeGas = gasleft();
        binding.verify(bindingSeal, bindingImage, BINDING_DIGEST);
        emit log_named_uint("real binding receipt adapter verification gas", beforeGas - gasleft());
    }

    function testReturnedComputeReceiptVerifiesWithActualGeneratedHalo2Verifier() public {
        uint256 beforeGas = gasleft();
        compute.verify(computeSeal, computeImage, COMPUTE_DIGEST);
        emit log_named_uint("real compute receipt adapter verification gas", beforeGas - gasleft());
    }

    function testActualHalo2RejectsMutatedBindingProofScalar() public {
        bytes memory changed = _mutatedSeal(bindingSeal);
        vm.expectRevert();
        binding.verify(changed, bindingImage, BINDING_DIGEST);
    }

    function testActualHalo2RejectsMutatedComputeProofScalar() public {
        bytes memory changed = _mutatedSeal(computeSeal);
        vm.expectRevert();
        compute.verify(changed, computeImage, COMPUTE_DIGEST);
    }

    function testActualHalo2RejectsWrongBindingJournalDigest() public {
        vm.expectRevert();
        binding.verify(bindingSeal, bindingImage, bytes32(uint256(BINDING_DIGEST) ^ 1));
    }

    function testActualHalo2RejectsWrongComputeJournalDigest() public {
        vm.expectRevert();
        compute.verify(computeSeal, computeImage, bytes32(uint256(COMPUTE_DIGEST) ^ 1));
    }

    function testActualHalo2RejectsComputeSealForBindingApplication() public {
        vm.expectRevert();
        binding.verify(computeSeal, bindingImage, COMPUTE_DIGEST);
    }

    function testActualHalo2RejectsBindingSealForComputeApplication() public {
        vm.expectRevert();
        compute.verify(bindingSeal, computeImage, BINDING_DIGEST);
    }

    function testReceiptRejectsOtherApplicationImageBeforeProofVerification() public {
        vm.expectRevert(OpenVmReceiptVerifier.WrongImageId.selector);
        binding.verify(bindingSeal, computeImage, BINDING_DIGEST);
    }

    function testActualHalo2RejectsChangedExecutableCommitment() public {
        OpenVmReceiptVerifier changed =
            new OpenVmReceiptVerifier(halo2, bytes32(uint256(BINDING_EXECUTABLE) ^ 1), VM_COMMIT);
        bytes32 changedImage = changed.imageId();
        vm.expectRevert();
        changed.verify(bindingSeal, changedImage, BINDING_DIGEST);
    }

    function testActualHalo2RejectsChangedVmCommitment() public {
        OpenVmReceiptVerifier changed =
            new OpenVmReceiptVerifier(halo2, BINDING_EXECUTABLE, bytes32(uint256(VM_COMMIT) ^ 1));
        bytes32 changedImage = changed.imageId();
        vm.expectRevert();
        changed.verify(bindingSeal, changedImage, BINDING_DIGEST);
    }

    function testRealNoirProofAndReturnedBindingReceiptVerifyTogether() public {
        uint256 beforeGas = gasleft();
        require(composed.verify(abi.encode(encryptionProof, bindingSeal), statement), "real proof composition rejected");
        emit log_named_uint("real composed encryption and byte-binding verification gas", beforeGas - gasleft());
    }

    function testRealCompositionRejectsMutatedNoirProofWithValidBindingReceipt() public view {
        bytes memory changed = bytes.concat(encryptionProof);
        changed[959] = bytes1(uint8(changed[959]) ^ 1);
        require(!composed.verify(abi.encode(changed, bindingSeal), statement), "mutated encryption proof accepted");
    }

    function testRealCompositionRejectsMutatedBindingReceiptWithValidNoirProof() public view {
        require(
            !composed.verify(abi.encode(encryptionProof, _mutatedSeal(bindingSeal)), statement),
            "mutated binding receipt accepted"
        );
    }

    function testRealCompositionRejectsComputeReceiptAsBindingReceipt() public view {
        require(
            !composed.verify(abi.encode(encryptionProof, computeSeal), statement), "wrong application receipt accepted"
        );
    }

    function testRealCompositionRejectsDifferentBidderStatement() public {
        statement.bidder = address(0x4444);
        require(!composed.verify(abi.encode(encryptionProof, bindingSeal), statement), "different bidder accepted");
    }

    function testRealCompositionRejectsDifferentAuctionContext() public {
        statement.context = bytes32(uint256(statement.context) ^ 1);
        require(!composed.verify(abi.encode(encryptionProof, bindingSeal), statement), "different context accepted");
    }

    function _mutatedSeal(bytes memory original) private pure returns (bytes memory) {
        (uint8 version, bytes memory proofData) = abi.decode(original, (uint8, bytes));
        // The pinned verifier reads its first relation scalar at full-proof
        // offset 0x840. Removing the inserted 34 public words puts that word at
        // proofData offset 0x400. Change its low bit, preserving all curve points.
        proofData[0x41f] = bytes1(uint8(proofData[0x41f]) ^ 1);
        return abi.encode(version, proofData);
    }
}
