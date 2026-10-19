// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {
    OpenVmReceiptVerifier,
    IOpenVmHalo2Verifier
} from "../src/vendor/interfold-openvm/verifiers/OpenVmReceiptVerifier.sol";

interface OpenVmReceiptTestVm {
    function expectRevert(bytes4 selector) external;
    function expectRevert() external;
}

/// @dev Explicit Halo2 TEST DOUBLE. It checks exact forwarding and can propagate a rejection;
/// it performs no cryptographic proof verification. No real EVM receipt is exercised here.
contract ReceiptHalo2TestDouble is IOpenVmHalo2Verifier {
    bytes32 private immutable expectedPublicValues;
    bytes32 private immutable expectedProof;
    bytes32 private immutable expectedExecutable;
    bytes32 private immutable expectedVm;
    bool private immutable reject;

    error WrongForwardedInputs();
    error Halo2ProofRejected();

    constructor(bytes32 digest, bytes memory proof, bytes32 executable, bytes32 vmCommit, bool reject_) {
        expectedPublicValues = keccak256(abi.encodePacked(digest));
        expectedProof = keccak256(proof);
        expectedExecutable = executable;
        expectedVm = vmCommit;
        reject = reject_;
    }

    function verify(bytes calldata publicValues, bytes calldata proofData, bytes32 executable, bytes32 vmCommit)
        external
        view
    {
        if (
            publicValues.length != 32 || keccak256(publicValues) != expectedPublicValues
                || keccak256(proofData) != expectedProof || executable != expectedExecutable || vmCommit != expectedVm
        ) revert WrongForwardedInputs();
        if (reject) revert Halo2ProofRejected();
    }
}

/// @dev Tests the exact pinned upstream adapter with a Halo2 DOUBLE. These tests do not prove
/// a BFV input, auction computation, or the correctness of the actual Halo2 verifier artifact.
contract OpenVmReceiptVerifierTest {
    OpenVmReceiptTestVm private constant vm =
        OpenVmReceiptTestVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 private constant SCALAR_MODULUS = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    bytes32 private constant EXECUTABLE = bytes32(uint256(0x123456));
    bytes32 private constant VM_COMMIT = bytes32(uint256(0x789ABC));
    bytes32 private constant DIGEST = keccak256("synthetic public journal");
    OpenVmReceiptVerifier private receipt;
    ReceiptHalo2TestDouble private halo2;
    bytes private proofData;
    bytes32 private expectedImageId;

    function setUp() public {
        proofData = new bytes(1760);
        for (uint256 i; i < proofData.length; ++i) {
            proofData[i] = bytes1(uint8(i % 251));
        }
        halo2 = new ReceiptHalo2TestDouble(DIGEST, proofData, EXECUTABLE, VM_COMMIT, false);
        receipt = new OpenVmReceiptVerifier(halo2, EXECUTABLE, VM_COMMIT);
        expectedImageId = receipt.imageId();
    }

    function _seal() private view returns (bytes memory) {
        return abi.encode(uint8(1), proofData);
    }

    function testImageIdentityBindsDomainVerifierExecutableAndVm() public view {
        bytes32 domain = keccak256("INTERFOLD_OPENVM_RECEIPT_V1");
        require(receipt.IMAGE_DOMAIN() == domain);
        require(receipt.imageId() == keccak256(abi.encode(domain, address(halo2), EXECUTABLE, VM_COMMIT)));
        require(address(receipt.verifier()) == address(halo2));
        require(receipt.appExeCommit() == EXECUTABLE);
        require(receipt.appVmCommit() == VM_COMMIT);
    }

    function testImageChangesForVerifierExecutableAndVm() public {
        ReceiptHalo2TestDouble other = new ReceiptHalo2TestDouble(DIGEST, proofData, EXECUTABLE, VM_COMMIT, false);
        require(new OpenVmReceiptVerifier(other, EXECUTABLE, VM_COMMIT).imageId() != receipt.imageId());
        require(
            new OpenVmReceiptVerifier(halo2, bytes32(uint256(EXECUTABLE) + 1), VM_COMMIT).imageId() != receipt.imageId()
        );
        require(
            new OpenVmReceiptVerifier(halo2, EXECUTABLE, bytes32(uint256(VM_COMMIT) + 1)).imageId() != receipt.imageId()
        );
    }

    function testCanonicalSealForwardsExactDigestProofAndCommitments() public view {
        bytes memory seal = _seal();
        require(seal.length == 1856);
        receipt.verify(seal, expectedImageId, DIGEST);
    }

    function testWrongImageRejectedBeforeDecodingSeal() public {
        vm.expectRevert(OpenVmReceiptVerifier.WrongImageId.selector);
        receipt.verify(hex"01", bytes32(uint256(1)), DIGEST);
    }

    function testWrongDigestReachesAndIsRejectedByHalo2Double() public {
        vm.expectRevert(ReceiptHalo2TestDouble.WrongForwardedInputs.selector);
        receipt.verify(_seal(), expectedImageId, bytes32(uint256(DIGEST) ^ 1));
    }

    function testChangedProofReachesAndIsRejectedByHalo2Double() public {
        bytes memory changed = proofData;
        changed[0] = bytes1(uint8(changed[0]) ^ 1);
        vm.expectRevert(ReceiptHalo2TestDouble.WrongForwardedInputs.selector);
        receipt.verify(abi.encode(uint8(1), changed), expectedImageId, DIGEST);
    }

    function testUnderlyingHalo2RevertPropagates() public {
        ReceiptHalo2TestDouble rejecting = new ReceiptHalo2TestDouble(DIGEST, proofData, EXECUTABLE, VM_COMMIT, true);
        OpenVmReceiptVerifier rejectingReceipt = new OpenVmReceiptVerifier(rejecting, EXECUTABLE, VM_COMMIT);
        bytes32 rejectingImage = rejectingReceipt.imageId();
        vm.expectRevert(ReceiptHalo2TestDouble.Halo2ProofRejected.selector);
        rejectingReceipt.verify(_seal(), rejectingImage, DIGEST);
    }

    function testVersionZeroRejected() public {
        vm.expectRevert(OpenVmReceiptVerifier.InvalidSealVersion.selector);
        receipt.verify(abi.encode(uint8(0), proofData), expectedImageId, DIGEST);
    }

    function testUnsupportedVersionRejected() public {
        vm.expectRevert(OpenVmReceiptVerifier.InvalidSealVersion.selector);
        receipt.verify(abi.encode(uint8(2), proofData), expectedImageId, DIGEST);
    }

    function testTruncatedAbiRejected() public {
        vm.expectRevert();
        receipt.verify(hex"01", expectedImageId, DIGEST);
    }

    function testNoncanonicalVersionWordRejected() public {
        vm.expectRevert();
        receipt.verify(abi.encode(uint256(257), proofData), expectedImageId, DIGEST);
    }

    function testTrailingBytesRejectedAsNoncanonical() public {
        vm.expectRevert(OpenVmReceiptVerifier.InvalidSealEncoding.selector);
        receipt.verify(bytes.concat(_seal(), bytes32(0)), expectedImageId, DIGEST);
    }

    function testAlternateDynamicOffsetRejectedAsNoncanonical() public {
        bytes memory alternative = bytes.concat(
            abi.encode(uint8(1), uint256(96), bytes32(0)), abi.encode(uint256(proofData.length)), proofData
        );
        vm.expectRevert(OpenVmReceiptVerifier.InvalidSealEncoding.selector);
        receipt.verify(alternative, expectedImageId, DIGEST);
    }

    function testEmptyProofDataRejected() public {
        vm.expectRevert(OpenVmReceiptVerifier.InvalidProofDataLength.selector);
        receipt.verify(abi.encode(uint8(1), new bytes(0)), expectedImageId, DIGEST);
    }

    function testShortProofDataRejected() public {
        vm.expectRevert(OpenVmReceiptVerifier.InvalidProofDataLength.selector);
        receipt.verify(abi.encode(uint8(1), new bytes(1759)), expectedImageId, DIGEST);
    }

    function testLongProofDataRejected() public {
        vm.expectRevert(OpenVmReceiptVerifier.InvalidProofDataLength.selector);
        receipt.verify(abi.encode(uint8(1), new bytes(1761)), expectedImageId, DIGEST);
    }

    function testNoCodeVerifierRejected() public {
        vm.expectRevert(OpenVmReceiptVerifier.InvalidVerifier.selector);
        new OpenVmReceiptVerifier(IOpenVmHalo2Verifier(address(0x1234)), EXECUTABLE, VM_COMMIT);
    }

    function testZeroExecutableRejected() public {
        vm.expectRevert(OpenVmReceiptVerifier.InvalidAppCommitment.selector);
        new OpenVmReceiptVerifier(halo2, bytes32(0), VM_COMMIT);
    }

    function testZeroVmRejected() public {
        vm.expectRevert(OpenVmReceiptVerifier.InvalidAppCommitment.selector);
        new OpenVmReceiptVerifier(halo2, EXECUTABLE, bytes32(0));
    }

    function testExecutableAtScalarModulusRejected() public {
        vm.expectRevert(OpenVmReceiptVerifier.InvalidAppCommitment.selector);
        new OpenVmReceiptVerifier(halo2, bytes32(SCALAR_MODULUS), VM_COMMIT);
    }

    function testVmAtScalarModulusRejected() public {
        vm.expectRevert(OpenVmReceiptVerifier.InvalidAppCommitment.selector);
        new OpenVmReceiptVerifier(halo2, EXECUTABLE, bytes32(SCALAR_MODULUS));
    }

    function testOutOfFieldExecutableRejected() public {
        vm.expectRevert(OpenVmReceiptVerifier.InvalidAppCommitment.selector);
        new OpenVmReceiptVerifier(halo2, bytes32(type(uint256).max), VM_COMMIT);
    }

    function testOutOfFieldVmRejected() public {
        vm.expectRevert(OpenVmReceiptVerifier.InvalidAppCommitment.selector);
        new OpenVmReceiptVerifier(halo2, EXECUTABLE, bytes32(type(uint256).max));
    }

    function testMaximumCanonicalCommitmentsAccepted() public {
        bytes32 largest = bytes32(SCALAR_MODULUS - 1);
        OpenVmReceiptVerifier largestReceipt = new OpenVmReceiptVerifier(halo2, largest, largest);
        require(largestReceipt.appExeCommit() == largest);
        require(largestReceipt.appVmCommit() == largest);
    }
}
