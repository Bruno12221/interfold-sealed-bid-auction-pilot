# Continue verified OpenVM roots on another CPU host

The root-handoff packager copies an explicit allowlist of public proving artifacts: application key/executable, aggregation material, identity, exact public journal, verified root checkpoint/manifest, portable worker source, lockfile, license and setup-download instructions. It excludes wallet material, encryption witnesses, raw application inputs, local SDK databases and credentials.

The worker pins Interfold revision `c65722fcab24b3b5ffc7ccaf4544bd1d6ef8826a` and OpenVM v2.0.2 revision `59a69b8b0cbee7011ac978e4cc07707ee3681944`. Manifests record sizes and SHA-256 values; these establish byte equality, while the worker separately verifies the native root proof and final EVM receipt.

## Package and configure

From the repository root, after the required checkpoints exist locally:

```sh
node scripts/package-root-handoff.mjs .pilot/public-root-handoff
node --test test/root-handoff.test.mjs
```

The destination must be new. Review the manifest and transfer only the selected bundle to a compatible CPU host. From that bundle:

```sh
python3 configure.py --bundle-only
python3 worker/fetch-setup.py setup
python3 configure.py
cargo build --locked --release --manifest-path worker/Cargo.toml --target-dir target
```

An existing exact setup can be selected with `python3 configure.py --setup /absolute/path/to/setup`. Verify all recorded artifact sizes and hashes. Configuration writes host-local absolute paths and refuses to overwrite an existing config. Public setup is large: the Halo2 key alone is about 10.2 GB, and SRS/setup/build/proof artifacts require substantial additional storage and RAM. Setup sizes do not establish peak RAM or minimum hardware.

## Compress and verify

```sh
python3 run-compression.py binding --threads 4
python3 run-compression.py compute --threads 4
```

Each job verifies its checkpoint/config/journal hashes, exact executable/VM commitments and native root STARK before Halo2 compression. The pinned worker verifies the final proof in a local EVM before writing its seal. A completed root STARK alone is not an EVM receipt.

Success requires a successful worker exit, cryptographic verification and the expected canonical 1,856-byte seal. File length and ABI header words do not prove validity. Inspect result logs and timing reports; keep failed attempts separate rather than overwriting them. Thread count is not a memory cap.

Review returned results and logs before sharing, retain the manifest as public provenance, and independently verify the seal against the intended identity/journal. Compression requires no Ethereum or Avail signing key. A verified receipt does not provide program registration, DA authorization, threshold decryption or broadcaster availability.
