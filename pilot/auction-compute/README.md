# Auction client, native worker, and OpenVM guest

These tools prepare the reveal-after-close auction's real secure-8192 ciphertexts and reference computation. They do not submit transactions. **No native output is accepted as an Interfold proof.** The missing application input circuit, real OpenVM receipt verifier/artifacts, and verified Avail path still gate live admission and settlement.

All commands use the checked-in lockfile and Rust 1.91.1 or later:

```sh
cargo run --locked --manifest-path pilot/auction-compute/Cargo.toml -- COMMAND
```

## Client encryption

`encrypt PUBLIC_KEY_HEX_FILE EXPECTED_SAFE_KEY_COMMITMENT` reads a private JSON object from stdin: `{"slot":0,"bid":31,"maxTick":100}`. The key file contains the actual committee public key's lowercase `0x` bytes; its expected SAFE commitment must come from the intended E3. The command checks that commitment before encryption. Its output contains slot, randomized ciphertext bytes/hash, SAFE ciphertext commitment, committee key commitment, and `inputProofGenerated:false`. It excludes the bid and encryption randomness. It does not generate an encryption proof witness; the input circuit/prover must eventually share the exact encryption operation rather than encrypting again.

For an actual private bid, use a private input source instead of putting the value in a shell command or public JSON file. The public bid artifact is insufficient to prove sparse-vector validity.

`encrypt-for-proof PUBLIC_KEY_HEX_FILE EXPECTED_SAFE_KEY_COMMITMENT NEW_PRIVATE_DIRECTORY` reads the same private stdin object and uses upstream's **verifiable encryption** operation. It emits only the public ciphertext artifact on stdout and saves the exact private ct0/ct1/u/error/k1 witnesses for that ciphertext to `NEW_PRIVATE_DIRECTORY/bid.private.json`. The new directory has mode 0700 and the file has mode 0600; existing destinations are refused. The filename is excluded by the root Git rules. Put the directory under ignored `.pilot/` as well. No complete input proof is generated: these witnesses still need the composed sparse/encryption/serialization/domain proof system. They must never be uploaded to a public compute worker.

The synthetic witness smoke test checked all 8192 k1 coefficients, the exact same public artifact, file permissions and absence of private fields on stdout. An independent native test decrypts the same witness-derived ciphertext at maximum bid 100/slot 31 and checks every other plaintext coefficient is zero.

## Frozen public manifest

`compute-native MANIFEST_JSON INDEPENDENT_CHAIN_ANCHOR_JSON` validates the manifest against a separately obtained on-chain snapshot and computes the exact ciphertext sum. A manifest's own claimed root does not authenticate it.

```json
{
  "schemaVersion": 1,
  "anchor": {
    "chainId": "11155111",
    "auction": "0x<20 lowercase bytes>",
    "e3Id": "0",
    "context": "0x<32 bytes>",
    "committeePublicKey": "0x<32-byte SAFE key commitment>",
    "inputRoot": "0x<32-byte rolling escrow root>",
    "bidCount": 3
  },
  "publicKey": "0x<serialized committee public key>",
  "inputs": [{
    "slot": 0,
    "bidder": "0x<20 lowercase bytes>",
    "ciphertext": "0x<raw serialized BFV ciphertext>",
    "envelope": "0x<canonical ABI envelope>",
    "commitment": "0x<32-byte SAFE ciphertext commitment>"
  }]
}
```

The example abbreviates three actual inputs. No private bid, decryption key, encryption randomness, or prover witness belongs in this public manifest. The independent anchor file contains exactly the `anchor` object. Read its fields from the intended Sepolia escrow and E3 at a finalized block; the CLI's native validation does not perform an RPC request or establish that finality.

Each envelope is exactly `abi.encode(uint8(1), bytes32(ciphertextHash), bytes(inputProof), bytes(availabilityProof))`, limited to 16,384 bytes. Ciphertexts live in DA rather than this calldata envelope. Every slot must be its zero-based authenticated position. Distinct nonzero bidder addresses match the escrow's identity rules. Native checks bind every ciphertext's bytes to the envelope hash and independently recomputed SAFE commitment. The rolling root must match the anchor. The upstream `SecureProcess` recomputes all field-reduced leaves and the actual Poseidon root from those same consumed inputs, then computes the sum and its SAFE commitment. No input is silently omitted.

The native output explicitly keeps `openvmReceiptGenerated`, `inputProofsVerified`, and `availabilityVerified` false. Parsing nonempty proof bytes is not proof verification. Input ZK validity and DA availability must come from successful admission through the real configured application verifiers.

## OpenVM input preparation

`prepare-openvm MANIFEST_JSON INDEPENDENT_CHAIN_ANCHOR_JSON PROTOCOL_ADDRESS NEW_OUTPUT_DIRECTORY` runs the same validation and native Secure Process, then writes only public data:

- `input.bin`: upstream item framing: header, all ciphertexts, then all selected ciphertexts.
- `journal.bin`: the exact nine ABI words, 288 bytes, that the guest's SHA-256 digest reveals.
- `aggregate.bin`: the exact serialized aggregate ciphertext.
- `bundle.json`: byte lengths, Keccak/SHA-256 artifact hashes, roots, and explicit false proof flags.

The protocol address must be the intended Interfold contract, not the E3 application address. The output directory must be new to prevent accidental artifact replacement. Put generated artifacts under `pilot/auction-compute/artifacts/`, which is ignored by Git. No deployment accepts these files directly.

`guest/` contains the matching OpenVM guest source at OpenVM 2.0.2. It requires the exact secure parameter hash, 1–32 consecutive positions, bound metadata for every input, and the same custom policy used natively. The guest derives the Poseidon root and output from the ciphertexts consumed in its checked two-pass stream. Sparse plaintext/range validity remains the application's input-proof obligation. The guest proves the linear computation, not those hidden inputs.

The guest has now been built with isolated OpenVM 2.0.2 and nightly 2026-01-18 tools and executed in the actual VM against a three-input secure-8192 fixture. Its revealed 32-byte digest matches SHA-256 of the exact 288-byte journal. This verifies guest execution, not an EVM-verifiable receipt. Tools, setup files and generated artifacts are ignored. Reproduce the build/execution from the repository root:

```sh
npm run pilot:openvm -- /absolute/path/to/prepared-bundle
# Optional CPU application STARK proving and verification:
npm run pilot:openvm -- /absolute/path/to/prepared-bundle --prove-app
```

The tool uses `CARGO_OPENVM_BIN` or the isolated local install, and uses the isolated nightly when present. Other machines need the pinned tools installed. Application proofs still need recursive aggregation/Halo2 wrapping and the correct immutable on-chain receipt verifier. Follow the pinned upstream `templates/default/.interfold/support/openvm/compile` workflow, using `cargo-openvm`2.0.2, `cargo openvm setup --evm`, and the matching CPU/CUDA `e3-openvm-prover`. Generate the application/aggregation keys, run worker `prepare`, pin its actual application/verifier identity in the auction program, then:

```text
<worker> execute <prover-config.json> input.bin journal.bin
<worker> prove <prover-config.json> input.bin journal.bin <new-seal-file>
```

Only successful execution followed by proof generation and receipt verification demonstrates this path. Sepolia's protocol mock receipt verifier must not replace the application's real pinned receipt verifier.

The measured three-input secure-8192 guest executed 1,508,859,842 VM instructions (estimated 65,947,763,206 cells), with the upstream SAFE modular acceleration enabled. A single-core CPU application-proving trial was stopped after about 19 minutes without a proof artifact. This is a performance bottleneck to address with profiling and a suitable proving worker; there is no measured successful proving latency or EVM receipt yet. `--prove-app` can be expensive and does not produce the final Halo2 receipt by itself.

## Other commands and validation

`transcript MANIFEST_JSON` emits tiny public ABI/leaf/rolling-root vectors for cross-language checks; it does not validate ciphertexts or proofs. `hash-artifact FILE` reports exact-byte length and Keccak-256/SHA-256 digests. `reveal PUBLIC_OUTPUT_HEX_FILE BID_COUNT MAX_TICK` decodes exactly 50 little-endian u64s (400 bytes), enforces 0–100 tick bounds and zero unused output slots, and returns bids in admitted order. Read the authoritative plaintext from the completed E3; this decoder does not authenticate an arbitrary file.

The native tests cover malformed ABI offsets/padding/version, cross-slot and hidden-tail witnesses, max bid 100, ordered root/metadata binding, changed bytes/commitments, independent-anchor mismatch, output width/endianness/ranges, and unknown public-manifest fields. The real local demo exercises full secure encryption, actual SAFE commitments, upstream Secure Process, Poseidon root, linear sum, and single-party reveal. Cargo.lock pins `alloy-sol-type-parser` 1.4.1 to match the pinned upstream ABI crate; updating only that transitive package to 1.7.x produces an incompatible `winnow` API.
