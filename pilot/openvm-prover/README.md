# Portable OpenVM EVM receipt worker

This worker completes the pinned upstream pipeline: application STARK, recursive aggregation,
root proof, Halo2 compression, EVM verification, and a 1,856-byte seal. It handles either the
auction computation's 288-byte journal or the input-binding guest's 416-byte journal. Both guests
reveal exactly SHA-256 of the complete journal as 32 public bytes. The two guests need separate
application keys, prepared identities and worker configurations.

Public synthetic fixture receipts pass the pinned verifier and actual Solidity receipt-adapter/Noir composition tests, including tamper rejection. See [receipt fixtures](../../test/fixtures/openvm-receipts/README.md) for their separate synthetic domains and limitations. Application STARK verification from `../openvm-tools` is an earlier stage and is not a final EVM receipt. See [NOTICE.md](NOTICE.md) for pinned source and local changes.

## Build and test

From the repository root, on a CPU host with a compatible Rust toolchain:

```sh
CARGO_TARGET_DIR=pilot/auction-compute/.tools/host-target \
  cargo build --locked --release --manifest-path pilot/openvm-prover/Cargo.toml
CARGO_TARGET_DIR=pilot/auction-compute/.tools/host-target \
  cargo test --locked --release --manifest-path pilot/openvm-prover/Cargo.toml
```

The executable is `pilot/auction-compute/.tools/host-target/release/interfold-openvm-prover`.
When preserving a previously measured worker, use a separate new `CARGO_TARGET_DIR` and record
the new executable's SHA-256; rebuilding in its old target directory replaces that binary.
An optional `--features cuda` build requires NVIDIA CUDA and its toolkit; use a separate target
directory. The CPU build deliberately rejects the `probe` command, so it cannot be mistaken for
an available GPU.

## Host resources and setup

The public v2.0.2 Halo2 key is **10,217,007,290 bytes**. The k=24 KZG SRS is
**2,147,483,908 bytes**; both sizes were confirmed with HTTP HEAD on 2026-10-16. The CLI's
setup downloads SRS sizes k=10 through k=24, approximately 4.30 GB combined, before other keys,
build products and proofs. Budget at least 15 GB just for those setup files and substantially
more free disk for builds and proof artifacts.

These disk sizes are not a RAM bound. The SDK decodes and retains the full Halo2 key, both SRS
objects and graph state. Proving also allocates polynomial and MSM work buffers. Its source does
not establish a measured minimum or peak RSS for this auction. A host with 64 GiB RAM is a
reasonable initial working target, with actual peak RSS and runtime to be measured; it is not a
verified minimum. Successful application proving does not establish that final Halo2 compression fits the same host. Measure memory and runtime for the intended workload.

The upstream CLI's `setup --evm --download` additionally buffers each entire download in memory
(`resp.body.collect()`), including the 10.2 GB key. Use a stronger host, or stream public files to
disk with a downloader instead of using that buffered route. Keep setup under a dedicated
directory and pass it to `write-config`; do not change `HOME` to redirect OpenVM's defaults.

The standard setup layout is:

```text
SETUP/
  halo2.pk
  params/kzg_bn254_10.srs ... kzg_bn254_24.srs
  halo2/src/v2.0-base/verifier.bytecode.json
```

The versioned public key is available at
[`v2.0.2/halo2.pk`](https://openvm-public-artifacts-us-east-1.s3.us-east-1.amazonaws.com/v2.0.2/halo2.pk);
KZG files are under
[`challenge_0085`](https://axiom-crypto.s3.us-east-1.amazonaws.com/challenge_0085/kzg_bn254_24.srs).
Use the v2.0.2 CLI's setup implementation for the exact verifier artifact paths. Record SHA-256
digests and source URLs for all downloaded artifacts, and verify the expected verifier digest
before deployment. An S3 multipart ETag is not a SHA-256 checksum.

Resource analysis comes from the pinned OpenVM source:
[download buffering](https://github.com/openvm-org/openvm/blob/59a69b8b/crates/cli/src/commands/setup.rs),
[key decoding](https://github.com/openvm-org/openvm/blob/59a69b8b/crates/static-verifier/src/codec.rs),
[SRS caching](https://github.com/openvm-org/openvm/blob/59a69b8b/crates/sdk/src/halo2_params.rs), and
[eager Halo2 state loading](https://github.com/openvm-org/openvm/blob/59a69b8b/crates/sdk/src/prover/halo2.rs).

## Prepare and run on the stronger host

Copy the selected guest's public input bundle, application key, executable and expected journal.
The compute bundle contains public ciphertexts, without a decryption key. Keep encryption
witnesses and wallet material on the bidder's machine.

Use absolute paths below. `PREPARED` must be a new directory; `SEAL` must be a new file.
Choose one worker per job and a segment limit that leaves room for recursive proving and Halo2.
The segment limit bounds application segmentation only; it does not cap the whole process RSS.

```sh
interfold-openvm-prover prepare APP_PK GUEST_VMEXE PREPARED
interfold-openvm-prover write-config CONFIG APP_PK GUEST_VMEXE PREPARED SETUP 2147483648
interfold-openvm-prover check CONFIG
interfold-openvm-prover execute CONFIG INPUT_BIN JOURNAL_BIN
interfold-openvm-prover prove CONFIG INPUT_BIN JOURNAL_BIN SEAL
```

To continue from a saved application STARK instead of redoing application proving, use:

```sh
interfold-openvm-prover aggregate-app CONFIG APPLICATION_APP_PROOF JOURNAL_BIN SEAL
```

Before aggregation, this action derives the expected executable and VM commitments from the
application key and executable, checks the configured identity, verifies every application STARK
segment, authenticates its public values against final memory, and requires exactly the expected
journal's SHA-256 digest as 32 byte-valued field elements. It then follows the same aggregation,
root, Halo2 and final EVM verification path as `prove`. An ignored test exercises this admission
step with the independently generated real fixture used by `../openvm-tools`, including wrong
executable, wrong journal and changed public-value rejections:

```sh
OPENVM_TOOLS_FIXTURE=/absolute/path/to/fixture RAYON_NUM_THREADS=2 \
  cargo test --locked --release --manifest-path pilot/openvm-prover/Cargo.toml -- --include-ignored
```

For long runs, use the separate stages instead. This saves application and recursive work before the final
Halo2 allocation, and lets another host continue from a verified checkpoint without repeating the
application proof or previous stages:

```sh
interfold-openvm-prover prove-app CONFIG INPUT_BIN JOURNAL_BIN NEW_APPLICATION_APP_PROOF
interfold-openvm-prover aggregate-stark CONFIG NEW_APPLICATION_APP_PROOF JOURNAL_BIN NEW_STARK_DIR
interfold-openvm-prover prove-root CONFIG NEW_STARK_DIR JOURNAL_BIN NEW_ROOT_DIR
interfold-openvm-prover compress-root CONFIG NEW_ROOT_DIR JOURNAL_BIN NEW_SEAL
```

`prove-app` authenticates the configured executable and VM identity from the actual application
and aggregation keys, releases recursive setup state, and generates only the application STARK.
It natively verifies every segment and the exact journal digest before saving. The file is the
pinned SDK's **bitcode serialization of `ContinuationVmProof<SC>`**, written with
`openvm_sdk::fs::write_object_to_file` and read back with `read_object_from_file` for a second
native verification. It is directly compatible with the existing `aggregate-stark` and
`aggregate-app` actions. It is not JSON, the root proof's codec format, or an Ethereum seal.
No Halo2 key or KZG parameter file is opened, and no recursive proof is generated by this action.

The new application output, `NEW_APPLICATION_APP_PROOF.manifest.json`, and
`NEW_APPLICATION_APP_PROOF.partial` must all be absent. The parent directory must already exist.
Existing files, directories and dangling symlinks are rejected before expensive work. After input
framing is checked, an exclusive private staging directory is reserved. Proof serialization occurs
there; synchronized proof and manifest files are published through atomic, non-replacing hard
links, with the manifest last. The sidecar records OpenVM version/revision, executable/VM identity,
proof format, size and SHA-256, plus hashes of the exact config file, framed input, journal,
application key, executable, aggregation key and verifier artifact. Those source hashes are
rechecked around proving and serialization. On interruption or write failure, retain any staging
directory or incomplete output for diagnosis and choose a new path; never overwrite previous work.
The later aggregation stage independently verifies the application proof again rather than
treating its manifest or filename as proof validity.

`aggregate-stark` verifies every saved application segment and its exact executable/journal,
then proves and independently verifies the recursive VM STARK. It saves `aggregate.json`,
`metadata.bin`, and `manifest.json`. `prove-root` checks that checkpoint, verifies its recursive
STARK and exact journal again, then generates and natively verifies a root STARK. It saves
`root.bin` and `manifest.json`. Neither stage opens the Halo2 key or KZG parameter files.

`compress-root` checks and natively verifies the saved root STARK against independently derived
root verification material. It requires the root's authenticated public values to contain the
configured executable and VM commitments and exactly the expected journal's SHA-256 digest.
It drops recursive prover state before opening the Halo2 key. Final compression still requires
the large key, SRS and proving buffers described above; checkpointing does not establish that it
fits on a 16 GiB host. The final EVM verification must pass for the exact identity and journal
before a seal is written.

Each manifest pins the OpenVM format version and complete v2.0.2 Git revision, stage, application
identity, journal size/digest, and SHA-256 hashes of its files plus the application key, executable,
aggregation key and verifier artifact. Paths may change when moving hosts; the artifact bytes
must match. Files are created without replacement, synchronized to disk, and a complete manifest
is atomically published last. An interrupted run can leave an incomplete output directory;
preserve it for diagnosis and use a new path for a retry. A missing or invalid manifest is never
accepted as a checkpoint. Input checkpoints are read only.

The worker logs the number of application segments and leaf aggregation nodes, then start/end
events and durations for leaf nodes, internal nodes and aggregation layers. Those events show
which recursive stage is active without printing inputs or keys. They are not a percentage of the
whole EVM pipeline or a reliable remaining-time estimate. Keep the external stage supervisor's
wall-clock and peak-RSS measurements with each checkpoint.

`prepare` creates the application-specific aggregation key and `identity.json`. `write-config`
pins both executable and VM commitments plus the verifier artifact SHA-256. `check` eagerly loads
every key and both KZG parameter sets. Do not use it as a lightweight preflight on a constrained
host; the staged STARK/root actions perform their own identity and artifact checks without
loading Halo2. `prove` verifies the final EVM proof against the pinned application identity and
exact expected journal before writing the seal.
There is no mock proof mode. Preserve the journal, identities, artifact digests, logs and resource
measurements with the output. The current commands write the verified ABI seal, without a separate
EVM proof JSON file.

The receipt contract must be deployed with this exact identity and verifier. The auction input
adapter and input circuit still need full composed proof integration before bidder admission can
use a ciphertext binding receipt. This worker alone does not enable bidding.
