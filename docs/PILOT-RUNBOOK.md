# Local development and release prerequisites

This source snapshot supports local contract, codec, cryptography and synthetic-receipt review. It does not represent a completed threshold-network auction.

## Local checks

From the repository root:

```sh
npm ci
npm test
npm run test:bfv
python3 -m unittest circuits/auction-input/test_prepare_witness.py
```

Use Node.js 20+, Foundry/Solidity 0.8.28 and Rust 1.91.1+. Check the individual package READMEs for pinned Noir/OpenVM toolchains. Optional package checks use Node.js 22.15+:

```sh
(cd pilot/avail && npm ci && npm test)
(cd pilot/railgun && npm ci && npm test)
```

`npm run pilot:local` performs additional real local cryptography/integration work and writes synthetic artifacts under ignored `.pilot/`. It uses a local demonstration key, not network threshold decryption. Fresh application, recursive and Halo2 proving is separate from the checked-in receipt tests and may require substantial memory, disk and time.

## Live status

`npm run preflight` and `npm run pilot:status` query live Sepolia/service state without signing. Reports are observations at their recorded blocks and timestamps. Unpaused requests do not establish committee, computation, DA or broadcaster availability.

## Before a live demonstration

1. Review the immutable program configuration, proof identities, circuit/guest code and realistic deadlines.
2. Generate the address-bound actual-program release known answer and deploy `AuctionE3Program`.
3. Obtain protocol-owner registration and review the one-time result-source binding.
4. Establish an authorized Avail publisher, exact raw-ciphertext publication, VectorX bridge receipt verification and verified fee/accounting behavior.
5. Configure compatible operators/proving services, fund and request the E3, authenticate the committee key, and generate fresh context/bidder/slot-specific input proofs.
6. Verify the finalized input transcript, aggregate publication, threshold-decrypted result and on-chain settlement/refunds before timeout.

Optional RAILGUN funding additionally needs a usable independent broadcaster, synchronized spendable notes, PPOI and successful private withdrawal checks. It is prepared integration code, not a completed private-spend demonstration.

Keep all signing keys, mnemonic material, encryption randomness, witnesses, wallet databases and funding linkage in ignored local storage. Generate secrets locally; the public synthetic fixtures are not reusable live inputs. See [program design](E3-PROGRAM.md), [verifier records](VERIFIER-DEPLOYMENT.md), [Avail](../pilot/avail/README.md) and [RAILGUN](../pilot/railgun/README.md).
