# Portable public input-binding proof job

The input-proof packager creates a new allowlisted job from public ciphertext bytes, a public statement/journal, application artifacts and pinned worker source. It excludes wallet keys, encryption witnesses and the private Noir proving directory. No old application/recursive/root proof is accepted as a shortcut for a new input.

A synthetic statement can name a conditionally predicted program address. That address depends on an unchanged deployer nonce. A changed program address requires a fresh Noir proof and binding receipt. A live bid additionally requires the actual E3, context, committee key, bidder and slot; synthetic domain values cannot admit a live bid.

## Package and run

From the repository root, with the required public inputs prepared locally:

```sh
node scripts/package-input-proof-job.mjs .pilot/public-input-proof-job
```

The packager refuses an existing destination. Inspect the bundle manifest and payload before transferring only the selected job folder to a compatible CPU host. Public setup files and pinned Cargo dependencies are downloaded separately. Full proving requires substantial RAM, disk and time; a segment limit does not bound whole-process RSS.

From the transferred job folder, use the generated launcher or manual workflow:

```sh
bash run-ubuntu.sh --setup /absolute/path/to/verified/openvm-setup
python3 run-proof.py status
```

The generated launcher installs/builds the pinned toolchain and runs application STARK, recursive aggregation, root proving and Halo2 compression sequentially. Each stage verifies its predecessor. Final success requires cryptographic verification against the exact executable/VM identity and public journal, followed by canonical 1,856-byte seal verification.

Resume uses matching source, worker, input, journal, config and completed-stage fingerprints, with fresh attempt paths. Incomplete attempts are retained for diagnosis and never treated as completed receipts. A live process or a correctly sized seal alone does not establish proof validity.

```sh
bash run-ubuntu.sh --resume
python3 run-proof.py archive
```

Review exported artifacts before sharing: they include public statements/proofs, identities, configuration and diagnostic logs, and exclude setup/build trees and encryption witnesses. Independently verify the returned seal against the intended local journal and identity before updating release evidence. This proving workflow does not perform a transaction, DA publication or contract binding.
