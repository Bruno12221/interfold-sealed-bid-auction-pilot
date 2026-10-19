# Private secure8192 auction encryption proof

This circuit composes Interfold's pinned secure8192 ct0 and ct1 encryption
relations with the auction's private bid range and sparse polynomial relation.
The real randomized encryption witness produced by `encrypt-for-proof` executes
successfully. It uses the secure preset explicitly, independently of Interfold's
default preset.

The only public inputs are **26 unsigned 128-bit limbs**: high128 then low128 for
each of the thirteen `IAuctionInputVerifier.Statement` ABI words, in struct order.
The SAFE key and ciphertext commitments are checked against canonical BN254 field
encodings, preventing a different 256-bit word from reducing to the same field.
The bid, encryption randomness, error polynomials, and deterministic `k1`
commitment remain private. Both encryption legs use the same private `u`.

An encryption proof **does not establish the serialized ciphertext hash**. The
complete admission verifier must also verify the public OpenVM serialization
binding receipt against the exact same statement. That receipt checks serialized
BFV ciphertext bytes, their SAFE commitment, and the ciphertext Keccak hash. The
Noir relation already binds the committee key SAFE commitment to the encryption
key coefficients; the E3/auction statement binds it to the generated DKG key. The
Noir proof and receipt must never be accepted independently as a complete input
proof. Availability still requires a separate genuine DA inclusion proof.

## Running

The expected tools are Nargo `1.0.0-beta.26` at `.tools/noir/nargo` and
Barretenberg `5.2.0` at `.tools/barretenberg/5.2.0/bb`. The latter's official
Apple Silicon archive SHA256, pinned by Interfold's `crates/zk-prover/versions.json`,
is `54be7645c83ac762a38a696cfe0c1495223a4f931b82720bc9e2e47f9a43bf86`.

From the repository root:

```sh
node circuits/auction-input/setup.mjs
node circuits/auction-input/prove.mjs \
  .pilot/my-private-bid/bid.private.json \
  .pilot/my-public-statement.json \
  .pilot/new-private-proof-directory
```

The proof destination must be new, inside this repository's ignored `.pilot/`,
and must not traverse symlinks. Preparation also checks Git's ignore rules before
writing private inputs. The source checkout is pinned to Interfold
commit `c65722fcab24b3b5ffc7ccaf4544bd1d6ef8826a`. Nargo beta.26 accepts only git
tags, so the setup uses a validated, ignored sparse checkout instead of a tag
dependency. `v0.19.0` currently resolves to a different commit; substituting that
tag would change the reviewed source.

The Python preparation step preserves large JSON coefficients exactly; JavaScript
`JSON.parse` would round numeric coefficients above 2^53. Inputs, raw ACVM
witnesses, and logs remain in an owner-only directory with owner-only files.
The raw ACVM witness is sensitive and must never be published. The runner uses
Barretenberg's **`evm` ZK target**, verifies the proof, checks all 26 public inputs
against the original statement, rejects changed proof/statement inputs, and writes
the generated Solidity verifier. The `evm-no-zk` target is unsuitable here.

The initial compiled circuit has 2,598,826 EVM gates and 883,720 ACIR opcodes.
Compilation and witness execution alone are not proof generation. `validation.json`
is written only after actual proof generation and negative verification checks;
its `composedInputProofReady` remains false until the companion receipt is
verified and both parts are checked by the admission adapter.

The generated verifier ABI is `verify(bytes proof, bytes32[] publicInputs)`.
Supply the 26 limbs as separate canonical 32-byte ABI words, not the original
thirteen 256-bit words. The adapter must pin this circuit's generated verifier
and the companion guest's exact OpenVM image.
