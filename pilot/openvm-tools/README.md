# OpenVM application proof identity checks

The pinned OpenVM SDK's application verifying key identifies the VM configuration. Verification
also needs the expected executable commitment and the expected public journal. This helper derives
the commitment before proving and requires both when verifying. It uses application-only APIs and
does not initialize recursive aggregation or Halo2 proving keys.

```sh
cargo build --locked --release --manifest-path pilot/openvm-tools/Cargo.toml
pilot/openvm-tools/target/release/interfold-auction-openvm-tools identity APP_PK EXE
pilot/openvm-tools/target/release/interfold-auction-openvm-tools verify-app APP_VK PROOF EXPECTED_EXECUTABLE_COMMITMENT JOURNAL
```

`identity` returns JSON with `applicationExecutableCommitment`, the SHA-256 hashes of its inputs,
and the required 32 public bytes. Supply that independently derived commitment to `verify-app`.
The verifier cryptographically verifies every application STARK segment against the exact expected
executable, authenticates public values against final memory, and requires exactly
`SHA256(JOURNAL)` as 32 byte-valued field elements. `JOURNAL` must contain exactly the nine ABI
words (288 bytes) used by the auction computation or the thirteen ABI words (416 bytes) used by
the ciphertext input-binding proof. The report identifies `journalScheme` and `journalBytes`.

The helper validates the application proof only. A successful report explicitly records
`evmReceiptGenerated: false`; it is not a receipt accepted by the Sepolia auction contracts.

The normal unit tests cover both journal lengths, exact digest length, byte-valued public fields
and canonical executable commitments. A separate ignored test uses an independently generated
real application STARK fixture. It verifies the valid proof and rejects a wrong executable
commitment, a wrong journal and a validly serialized proof with an authenticated public value
changed. Run it with the local fixture directory:

```sh
OPENVM_TOOLS_FIXTURE=/absolute/path/to/fixture RAYON_NUM_THREADS=2 \
  cargo test --locked --release --manifest-path pilot/openvm-tools/Cargo.toml -- --include-ignored
```

The fixture contains `keys/app.pk`, `keys/app.vk`, `build/proof-binding-fixture.vmexe`,
`fixture.app.proof`, `journal.bin` and `wrong-journal.bin`. Generated keys and proofs remain
outside git.

For a long proof, `scripts/openvm-application-proof.mjs` saves phase PIDs, process start
identities, immutable artifact fingerprints, and an atomic `status.json`. SIGINT or SIGTERM
records `interrupted`, forwards the signal only to that invocation's active child, and prevents
verification or any later phase from starting. If the child ignores the signal, the runner
terminates it after ten seconds. Restart interrupted application proving in a new output directory.

Inspect a run without modifying its files or sending termination signals:

```sh
node scripts/openvm-proof-status.mjs /absolute/path/to/run-directory
```

The read-only report separates the recorded status from observed process liveness. It identifies
an orphaned live child or a stopped supervisor without a final status, including after SIGKILL
or a machine restart. Process start identities detect PID reuse where `ps` is available; older
records without those identities are explicitly reported as unverified. Liveness never changes
the proof verification flags or establishes that a proof has completed.

For elapsed proof times across saved runs:

```sh
npm run pilot:proof-times
# Attach a timing recorder to jobs already running; no proof restart needed:
npm run pilot:proof-times -- --watch /absolute/path/to/compute-run /absolute/path/to/binding-run
```

The recorder samples every 30 seconds and exits after all selected jobs stop. Each run gets
`timing.json` (latest sample) and `timing.jsonl` (history), separate from the supervisor's
`status.json`. These generated files stay in the ignored run directory. Use one recorder per run.
New supervisors also save `timings` directly in `status.json`; the status command computes them
for older runs from their existing timestamps.

Durations include time before the recorder attached. Each phase has its own start, finish,
elapsed seconds and `HH:MM:SS`; the total includes identity setup, proving and verification.
Completed durations freeze at the supervisor's actual recorded finish time, rather than the
next sampling time. An unexpected stop without a finish record is marked unknown, with the
last observed live time and stop observation saved separately. Time elapsed never establishes
proof validity: `applicationProofVerified` remains a separate result.

These are wall-clock measurements for the current machine and concurrent workload. They are
useful benchmarks after completion, not estimates of remaining time: the current proof logs
do not expose a reliable completion percentage or ETA. Keep both runs' concurrency and host
resources in mind when using their times to plan a later run.
