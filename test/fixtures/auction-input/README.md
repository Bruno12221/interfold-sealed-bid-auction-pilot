# Synthetic secure8192 EVM ZK fixture

`proof.bin` is an actual Barretenberg 5.2.0 **EVM ZK** proof of the composed
secure8192 encryption and sparse bid circuit. `public-inputs.bin` contains its
26 canonical u128 limbs as 32-byte words. `statement.bin` is the same statement
as thirteen ABI words; `statement.json` is its readable equivalent.

All addresses/context in this fixture are public synthetic test values. The
committee key and ciphertext SAFE commitments identify a local demonstration.
No bid, encryption randomness, plaintext polynomial, ACVM witness, wallet key,
or funding-linkage file is included. Public proof data is safe to commit.

The original real-proof tests verify the generated Solidity verifier, changed statement
and changed proof rejection; their isolated composition checks retain an explicit receipt
test double. `RealOpenVmReceipts.t.sol` additionally verifies this Noir proof together with
the [actual returned serialized-byte binding receipt](../openvm-receipts/README.md), using
the pinned generated Halo2 verifier and upstream receipt adapter. Both proof halves are real
in those tests. These synthetic domain values do not establish a live auction or deployed release.
