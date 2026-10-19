# Real OpenVM receipt fixtures

These are public synthetic proofs returned from CPU compression of the already
verified binding and computation root checkpoints. They contain no private input,
encryption witness, root/application proof, logs or host configuration.

`verifier.bytecode.json` is the exact unmodified OpenVM v2.0.2 setup artifact used
to verify the receipts. Tests hash the JSON and deploy its recorded solc 0.8.19
creation bytecode directly in the local EVM. They compile the vendored upstream
`OpenVmReceiptVerifier` adapter with the repository's solc 0.8.28 configuration.
The generated Halo2 verifier is never recompiled or substituted by a test double.

Each `*.seal.bin` is canonical `abi.encode(uint8(1), bytes proofData)`, 1,856 bytes
including 1,760 bytes of proof data. The actual Halo2 verifier authenticates the
executable/VM commitments and SHA-256 of its corresponding `*.journal.bin`.
The binding journal is byte-identical to the existing real Noir encryption
fixture's `../auction-input/statement.bin`. This permits a composition test with
both real proofs and no additional proof generation.

The two journals are independent fixtures, not one live auction. Binding uses a
synthetic program, context and bidder at slot 1. Computation uses E3 ID 0 and a
different fixture committee key and three-input tree. These receipts cannot be
reused as live bids or live computation results. No transaction, availability
publication, threshold decryption or complete auction is exercised by these tests.

Public file hashes, source revisions and application commitments are recorded in
`provenance.json`. The upstream adapter's license and provenance are retained in
`../../../src/vendor/interfold-openvm/`. The generated Halo2 verifier's upstream
OpenVM MIT notice is retained in `LICENSE-OpenVM-MIT.txt`.
