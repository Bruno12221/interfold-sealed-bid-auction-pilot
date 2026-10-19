# Sparse auction witness constraints

This Noir library implements and tests the auction's secure-8192 plaintext constraints. It is **a component, not a complete auction input proof**. Run `nargo test` with Noir **1.0.0-beta.26**, the version pinned by Interfold v0.19.0.

Interfold's encryption witness `k1` is not the raw plaintext. It is `(13178113 * amount) mod 17000000`, and the circuit polynomial order is reversed from the BFV client's ascending coefficient order. The library checks all 8192 coefficients, including those beyond the 50 coefficients revealed by the decryption verifier. Only the assigned slot may contain its scaled bid; all other slots must be zero. It accepts 0–100 ticks and slots 0–31.

Compose this constraint with Interfold's secure ct0/ct1 encryption checks in the **same verified witness**, or verify those inner proofs recursively and bind their private k1 opening inside a zero-knowledge outer proof. Two independent proofs without a common constrained witness are insufficient. The final verifier must also bind the committee key, auction domain, bidder, slot, parameter set, ciphertext SAFE commitment, exact serialized ciphertext hash and authenticated DA reference. No generated wrapper verifier exists in this repository yet.

Do not expose the bid, k1, a deterministic k1 commitment, witness files or non-ZK proof internals. A public k1 commitment would reveal a bid by enumerating this pilot's 101 possible amounts. Inner recursive proof material must remain private to a final proof generated with a zero-knowledge target.

The upstream encoding is pinned to [the threshold encryption witness computation](https://github.com/theinterfold/interfold/blob/c65722fcab24b3b5ffc7ccaf4544bd1d6ef8826a/crates/zk-helpers/src/circuits/threshold/user_data_encryption/computation.rs) and [secure parameter constants](https://github.com/theinterfold/interfold/blob/c65722fcab24b3b5ffc7ccaf4544bd1d6ef8826a/circuits/lib/src/configs/secure/threshold.nr). This code needs cryptographic review before deployment.
