# Ciphertext byte binding for the composed auction input proof

This OpenVM guest reads only a canonical 416-byte public input statement and
the serialized ciphertext. It recomputes the exact ciphertext Keccak hash and
the upstream secure8192 SAFE ciphertext commitment, then reveals the 32 bytes
of `SHA256(statement)`. No bid, randomness or secret key is read.

The companion Noir proof establishes encryption of a bounded sparse bid under
the committee key and binds the same ciphertext SAFE commitment. Its public
inputs are the exact same statement as 26 high/low u128 limbs. The composed
`AuctionInputVerifier` verifies both proofs. Neither component alone is a
complete admission proof.

The Noir proof already checks its public-key polynomials against the committee
SAFE key commitment anchored by the DKG. Serialized public-key bytes are not
an admitted object, so verifying them again in this guest is redundant. The
client still validates any public-key bytes it consumes before encryption.

From the repository root:

```sh
node scripts/prepare-input-binding.mjs STATEMENT_JSON PUBLIC_ENCRYPTED_BID_JSON .pilot/new-binding-bundle

OPENVM_BUILD_LOCKED=1 \
RUSTUP_HOME="$PWD/pilot/auction-compute/.tools/rustup" \
RUSTFLAGS='--cfg crisp_openvm --cfg crisp_fhe_optimized' \
pilot/auction-compute/.tools/openvm-parallel/bin/cargo-openvm openvm build \
  --manifest-path pilot/auction-input-binding/guest/Cargo.toml \
  --config pilot/auction-input-binding/guest/openvm.toml \
  --target-dir "$PWD/pilot/auction-compute/.tools/guest-target" \
  --output-dir "$PWD/.pilot/new-binding-build"
```

Generate application keys with `openvm keygen --app-only`, then use
`scripts/openvm-application-proof.mjs` with the bundle's `cli-input.json` and
`statement.bin`. That runner derives the executable commitment before proving
and verifies both that identity and the exact authenticated public digest.
Saved status records distinguish a running, failed, or completed proof.
An application STARK proof is not the recursively aggregated Halo2 receipt
accepted on Sepolia; that final receipt and exact image identity remain required.

The application runner defaults to a 2 GiB continuation-segmentation threshold.
For a smaller trace working set, set `OPENVM_SEGMENT_MAX_MEMORY_BYTES=1073741824`
before invoking it, or pass `segmentMaxMemoryBytes: 1073741824` to `proveApplication`.
The supported range is 256 MiB to 2 GiB. The runner records the selected value
and still verifies the exact executable and public journal. This threshold
controls where the VM divides execution; it is not a whole-process RAM limit.
Smaller segments may require more application and recursive proofs. Keep a
separate RSS guard and measure runtime rather than assuming a speed improvement.

The current guest executed the real synthetic encrypted bid successfully in
the VM and matched the statement digest. It used 886,384,037 instructions and
36,513,418,671 estimated cells. These are execution measurements, not a
generated EVM receipt or a throughput claim.

The synthetic fixture has since completed application/recursive/root proving and Halo2
compression. Its returned 1,856-byte seal independently verifies in a local EVM and through the
actual receipt adapter, together with the real Noir encryption proof. See the
[public fixtures](../../test/fixtures/openvm-receipts/README.md). The statement contains synthetic
domain values; fresh live bids still require fresh proofs for their own E3/key/bidder/slot.
