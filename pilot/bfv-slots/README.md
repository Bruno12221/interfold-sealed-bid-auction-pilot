# Secure BFV client and slot-packing reference

This crate uses Interfold 0.19.0's **SECURE_THRESHOLD_8192** tuple and the exact `fhe.rs` commit `873dc69c07eae251f88c4b5cacf6c4453e2c365a` recorded in Cargo.lock. It replaces the initial insecure-512 example, whose plaintext modulus of 100 could not encode the pilot's maximum bid of 100.

```sh
cargo test --locked --manifest-path pilot/bfv-slots/Cargo.toml
cargo run --locked --manifest-path pilot/bfv-slots/Cargo.toml > pilot/bfv-slots/result.json
```

The executable encrypts public synthetic bids `[31, 77, 42]` in three distinct polynomial coefficients, validates the public key and ciphertext SAFE commitments with the pinned upstream implementation, and sums ciphertexts through upstream `SecureProcess` using the auction's custom input policy. It decrypts with a throwaway local key, checks all 8192 coefficients, and emits the exact 400-byte public output expected by `BfvDecryptionVerifier`. The winner is slot 1, with bid 77 and a second-price payment of 42 ticks. Each serialized ciphertext and aggregate is 368,666 bytes; the public key is 184,371 bytes.

No secret key is serialized or written to disk. The one process holds the complete key, so this is **single-party decryption of a synthetic fixture**. This is not an Interfold committee run, an input proof, an OpenVM receipt, an availability proof, or authenticated Ethereum settlement. The demo's empty proof fields deliberately cannot pass live auction admission. `result.json` is ignored by Git.

The library also provides reusable secure-key validation, sparse plaintext construction, canonical ABI envelopes, transcript roots, input policies, native aggregation, and public result decoding. `sparse_plaintext` creates all 8192 coefficients, limits slots to 0–31 and bids to 0–100, and sets only the assigned coefficient. These native witness checks must also be enforced by the application's input ZK circuit; a compute provider cannot see whether an encrypted plaintext is sparse.

The field-reduced leaf is:

```text
keccak256(abi.encode(context, uint256(slot), bidder,
                    keccak256(envelope), SAFEcommitment)) mod BN254_FIELD
```

The rolling escrow root uses the same ABI words, with the preceding root in place of `context`. The initial root is `context`. Upstream's Poseidon tree uses the field-reduced leaves, a minimum depth of 1, and dynamic depth `ceil(log2(count))`.

See the native worker CLI and proof-toolchain boundary in `../auction-compute/README.md`.
