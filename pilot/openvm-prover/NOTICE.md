# Source provenance

`src/main.rs` and the package manifest derive from Interfold's
[`crates/openvm-prover` at commit `c65722fcab24b3b5ffc7ccaf4544bd1d6ef8826a`](https://github.com/theinterfold/interfold/tree/c65722fcab24b3b5ffc7ccaf4544bd1d6ef8826a/crates/openvm-prover).
The upstream file's SPDX header and LGPL-3.0-only license are retained. `LICENSE.md` is the
upstream license text.

Local changes accept exactly the auction's 288-byte computation journal or 416-byte ciphertext
input-binding journal, with one shared length check and a regression test. A new `aggregate-app`
action resumes a saved application STARK only after verifying every segment, the independently
derived executable identity and the authenticated exact public journal digest. The subsequent
aggregation, Halo2 proof construction, EVM proof verification and receipt encoding are unchanged.
The `aggregate-stark`, `prove-root` and `compress-root` actions split those same stages at durable,
verified checkpoints. Manifests pin the upstream revision, application identity, journal and
artifact digests. Resuming re-verifies the native STARK and authenticated public values before
proceeding; compression releases recursive prover state before loading Halo2. Selected upstream
aggregation spans are logged with node indices and durations for progress reporting.
The direct `openvm-circuit` dependency disables its default allocator
feature to reuse the pilot's CPU build; parallel proving remains enabled through `openvm-sdk`.

The lockfile uses the pilot host helper's resolved dependencies, including the compatible
`alloy-sol-type-parser` 1.4.1. OpenVM is pinned to v2.0.2 (`59a69b8b`), its STARK backend to
v2.0.1 (`362c7ad8`). This source is unaudited.
