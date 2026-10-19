# Auction E3 admission and compute gate

`AuctionE3Program` now implements the on-chain application boundary required by the existing `InterfoldResultSource` and `SealedBidAuction`. It has **not been deployed, registered or bound to the Sepolia result source**. The real secure input and application-specific OpenVM verifier stack is now deployed and passes genuine synthetic known-answer and tamper-rejection checks. Actual program release and network operation remain pending; see [deployment evidence](VERIFIER-DEPLOYMENT.md).

The Solidity tests exercise real auction, result-source, program, NFT and Poseidon contracts together. The main integration suite uses explicit protocol/DA/proof doubles; dedicated real-receipt tests separately use the pinned Halo2 bytecode, actual input proof and both genuine receipts. These tests establish integration and rejection behavior, not proof soundness, committee participation or a completed encrypted auction.

## Immutable configuration

One program instance serves one auction and one E3. Its constructor fixes:

- Interfold, auction escrow and result-source addresses;
- exact bidding end and settlement deadlines;
- secure BFV parameter serialization hash;
- input-circuit verifier, expected circuit identity, OpenVM receipt verifier and guest image identity;
- external availability verifier and Poseidon implementation.

The constructor requires deployed code, matching circuit/image identifiers and the escrow's actual result-source address. It records dependency runtime code hashes and rechecks them and circuit/image identifiers at admission and output verification. There are no dependency setters, authorized-input bypasses or plaintext setters.

**A code hash or nonzero circuit identity does not establish soundness.** A permissive verifier can implement the same interface. Binding this program therefore still requires review of the complete compiled circuits, generated verifiers, guest image, serialization and deployed dependencies. Avoid upgradeable verifier proxies: their proxy code hash does not pin the implementation or privileged configuration. The code-hash checks do not address that problem.

## Request and initialization

The program implements Interfold v0.19.0 `IE3Program` and `IE3ProgramDataAvailability` function signatures and advertises their exact ERC165 interface identifiers. Its `validate` hook accepts calls only from the immutable protocol and only once.

Interfold stores a provisional E3 before calling this hook. The hook checks the request's program, seller/requester, secure parameter set `2`, expected end time, parameter bytes and custom parameters. It recomputes the existing escrow's canonical context:

```text
keccak256(abi.encode(
  chainId, auction, seller, nft, tokenId,
  collateralWei, tickWei, priceLevels, maxBidders,
  e3Id, biddingEnds, settlementDeadline
))
```

`customParams` must be exactly `abi.encode(context)`. The initial rolling input root equals that context. The constructor fixes the deadlines, so request preparation must use those same values. A predicted `e3Id` that changes before the request lands invalidates its context and must be prepared again.

The protocol's owner must register the reviewed program before requesting the E3. Registration alone does not establish correctness. Once registered, the existing result source can bind that program through its one-time operational trust decision. Do not bind an instance using any test double.

## Canonical encrypted input envelope

The escrow's 16,384-byte limit applies to the envelope, not the raw secure-8192 ciphertext. A measured ciphertext is about 368,666 bytes and belongs on DA. Version 1 uses the **flat tuple** below; `abi.encode(EnvelopeStruct)` adds another ABI offset and is a different encoding:

```solidity
abi.encode(
    uint8(1),
    bytes32 ciphertextHash, // keccak256(exact serialized raw ciphertext)
    bytes inputProof,
    bytes availabilityProof
)
```

The escrow's separate `commitment` argument is the BFV SAFE ciphertext commitment. Both proofs must be nonempty. Unknown versions, extra trailing bytes, noncanonical ABI encodings, zero ciphertext hashes and non-field/zero commitments are rejected.

Only the immutable result source can call `publishInput`. It provides the context, expected slot, actual bidder, envelope and SAFE commitment during the escrow's collateral transaction. The program checks the E3's published-key stage, exact context, window, index, limit and unique bidder. It verifies the input proof and DA receipt **before** advancing either root. Any failure rolls back the entire escrow deposit, escrow bid and program ledger.

Admission currently requires an already finalized availability receipt. A bidder must therefore publish ciphertext and obtain the Avail/VectorX proof before its bid transaction. This adds latency and exposes the slot race: if another bid is admitted first, the old coefficient assignment and proof must be regenerated. Serialize participants for the first pilot. Reservations or an attested publication/finalization tail are separate future changes.

## Required secure input proof relation

`AuctionInputVerifier` implements `IAuctionInputVerifier` by composing the generated Noir encryption/sparse-bid proof and the OpenVM exact-byte binding receipt. The immutable Sepolia instance is deployed and fixture-validated; this does not constitute an independent security audit. Its public statement binds chain ID, program, protocol, auction, context, E3 ID, committee public-key commitment, parameter hash, ordered slot, bidder, maximum tick, exact serialized ciphertext Keccak hash and SAFE commitment.

The generated circuit and adapter must prove all of the following:

1. Correct BFV encryption under the E3's actual threshold public key and the exact secure-8192 parameters, including all noise/randomness bounds needed by Interfold's proof/decryption system.
2. A private integer bid in `[0, maxTick]`; for the current deployment, `[0, 100]`.
3. Exactly that coefficient is allowed at the authenticated ordered slot. Every other one of the **8,192** coefficients is zero, including those beyond the 50 publicly decrypted output coefficients.
4. The same ciphertext reproduces the published SAFE commitment **and** the Keccak hash of the exact canonical serialized bytes referenced by DA. Merely proving a valid commitment while admitting unrelated serialized ciphertext permits denial of service and does not satisfy this interface's security requirement.
5. Every public statement value is constrained. An adapter must encode 256-bit digests as suitable limbs without truncating or reducing their identity to a single smaller proof field.

Do not publish a deterministic commitment to a bid or its scaled coefficient: the 101 possible values can be enumerated. The statement's SAFE commitment is to the full randomized ciphertext. No plaintext bid, encryption randomness or complete secret key belongs in submission metadata or logs.

The generated Noir proof covers encryption and all sparse-coefficient constraints; the separate OpenVM guest authenticates canonical ciphertext serialization. Both must name the same full statement. Neither half alone suffices. Actual E3/key/context proofs must be generated anew.

## Two roots over the same admitted records

The escrow's original rolling root remains unchanged:

```text
rolling[0] = context
rolling[i+1] = keccak256(abi.encode(
  rolling[i], uint256(i), bidder[i], keccak256(envelope[i]), commitment[i]
))
```

For OpenVM, each record additionally supplies this application-specific leaf:

```text
leaf[i] = uint256(keccak256(abi.encode(
  context, uint256(i), bidder[i], keccak256(envelope[i]), commitment[i]
))) % BN254_SCALAR_FIELD
```

The binary tree uses Circom BN254 Poseidon2, zero padding and minimal depth `max(1, ceil(log2(count)))`, matching upstream's `MerkleTreeBuilder`. For example, three leaves produce `Poseidon(Poseidon(L0,L1), Poseidon(L2,0))`. With at most 32 leaves the contract rebuilds this bounded tree on admission. An empty auction does not start encrypted computation and can use the escrow's existing no-bid cancellation.

The custom native process uses the exact metadata `abi.encode(context, uint256(slot), bidder, envelope, commitment)`. Its policy must authenticate the ordered position, parse the canonical envelope, recompute the actual ciphertext hash and SAFE commitment and consume every admitted input. The standard commitment-only template is insufficient for this application.

`testSolidityTranscriptMatchesNativeSecureProcessFixture` checks Solidity's leaf, rolling root and actual Poseidon tree against a public fixture produced by the Rust secure-8192 process. Its empty proof fields are format fixtures and are deliberately inadmissible as real bids. Native ciphertext aggregation is a useful correctness check; it is not an OpenVM receipt.

## Output proof and DA

After closing, only Interfold can call `verify`. The hook rejects an empty auction, premature/expired computation, wrong stage, zero/non-field output commitments and a proof naming different parameters or input root.

It reconstructs Interfold's exact nine-word journal:

```text
sha256(abi.encode(
  bytes32(chainId), bytes32(uint160(interfold)), bytes32(e3Id),
  encryptionSchemeId, committeePublicKey,
  outputCiphertextHash, outputSAFECommitment,
  paramsHash, applicationPoseidonInputRoot
))
```

The immutable application-specific receipt verifier must authenticate the seal and image identity against this digest. The guest recreates the complete admitted input tree from ciphertexts and canonical metadata, verifies serialization/commitments and sums the sparse encrypted vectors. It must not accept a host-supplied root as authority or drop malformed inputs and continue. The custom guest now builds and executes in OpenVM with a matching journal digest. Both final synthetic EVM receipts are generated and verified; the actual closed auction requires its own new receipt.

The program uses the **same immutable external DA verifier** for inputs and aggregate output. It checks the returned content hash and rejects block number zero, so the template's local `mock_http`/zero-coordinate path is unusable. Nonzero coordinates alone do not authenticate Avail; the configured verifier must actually check the finalized bridge proof. Interfold independently verifies the aggregate-output DA receipt before publishing it.

After verified threshold decryption, the unchanged result source authenticates the E3 and its complete ordered input ledger and checks the 400-byte plaintext. The unchanged auction selects the highest positive bid and charges the second-highest, preserving its existing tie, abstention and refund rules.

## Remaining prerequisites for a real Sepolia run

The following remain required; the repository does not mark the existing deployment ready:

- Complete the actual-program release known answer using the deployed secure-8192 input verifier. Generate fresh live proofs after the real committee key and E3 are available; synthetic fixtures cannot admit bids.
- Prove the actual finalized input transcript with the pinned application-specific OpenVM identity and deployed immutable verifier. Both synthetic receipts already pass; the public protocol's permissive ciphertext wrapper is not a substitute for a new real receipt.
- Authorized real Avail publication service and fresh bridge/VectorX proofs through the existing reviewed Sepolia verifier, with clarified accounting and measured finality/transaction sizes.
- Protocol-owner program registration, then a reviewed deployment manifest and one-time result-source binding. Protocol-owner registration is an external authorization requirement.
- An E3 request with fees, committee DKG, authenticated key retrieval, three client proofs/DA receipts, worker output publication, threshold decryption and successful on-chain asset/refund checks before timeout.

No broadcaster, funds transfer, deployment, protocol request or binding occurs in these tests.

## Pinned implementation references

- [Interfold v0.19.0 program interface](https://github.com/theinterfold/interfold/blob/c65722fcab24b3b5ffc7ccaf4544bd1d6ef8826a/packages/interfold-contracts/contracts/interfaces/IE3Program.sol).
- [Exact OpenVM compute journal](https://github.com/theinterfold/interfold/blob/c65722fcab24b3b5ffc7ccaf4544bd1d6ef8826a/packages/interfold-contracts/contracts/lib/OpenVmComputeProof.sol).
- [Input policy and authenticated metadata requirements](https://github.com/theinterfold/interfold/blob/c65722fcab24b3b5ffc7ccaf4544bd1d6ef8826a/crates/compute-provider/src/policy.rs).
- [Native tree depth and hashing](https://github.com/theinterfold/interfold/blob/c65722fcab24b3b5ffc7ccaf4544bd1d6ef8826a/crates/compute-provider/src/merkle_tree_builder.rs).

`src/vendor/PoseidonT3.sol` comes from MIT-licensed `poseidon-solidity@0.0.5`, the exact dependency version pinned by upstream's contracts package. The only modification changes `hash` visibility from `public` to `internal`, allowing `AuctionPoseidon` to inline it without a linked replaceable library. Original source SHA-256: `08a7493be37838166954af6c77d583d797cc17d37673196498fc70cbf557831c`. npm archive integrity: `sha512-NzrvSwHzvZgT4hvg2GyGqeR+UOU/eLSEt4wAoXEua+VaR7NTKKwx1X9bPlh1VMBEVEno+IWvkRBbidFGzTeAqQ==`. Source attribution and SPDX identifier are retained.
