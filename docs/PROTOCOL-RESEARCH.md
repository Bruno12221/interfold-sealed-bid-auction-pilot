# Protocol integration scope

This implementation pins Interfold revision `c65722fcab24b3b5ffc7ccaf4544bd1d6ef8826a` and OpenVM v2.0.2 revision `59a69b8b0cbee7011ac978e4cc07707ee3681944`. Dependency manifests, vendored notices and public fixture provenance record the relevant versions.

## Auction computation and disclosure

The secure8192 demo assigns each bidder one plaintext coefficient. Input proofs establish bounded bids and zero outside the assigned slot. Addition preserves the individual bid slots. Threshold decryption after bidding closes reveals the bids; Solidity performs deterministic winner and second-price selection. This is not private comparison/top-two computation, and losing bids do not remain confidential after decryption.

The result adapter authenticates the pinned E3 and complete ordered input ledger. It accepts exactly 50 little-endian uint64 coefficients (400 bytes), checks unused published slots are zero, and rejects caller-provided results that differ from the protocol's authenticated plaintext.

## Application and deployment boundary

The program checks auction context, E3 identity, committee-key commitment, ciphertext commitment, slot, bidder and DA receipt. Its compute proof must bind the finalized input tree and exact aggregate. Program-level real verification remains essential even where a testnet protocol component is permissive. Source verification and synthetic fixtures do not establish program registration, operator service availability or a completed auction.

`AuctionE3Program` remains undeployed. Its immutable deadlines/configuration and release evidence need review before deployment, protocol-owner registration and one-time source binding. Live requests need fees, DKG, authenticated committee-key retrieval, fresh proofs/publications, threshold decryption and settlement/refund checks.

## Data availability

The configured Sepolia DA verifier requires authenticated content hashes and nonzero publication coordinates. App ID 0 does not bypass Avail Turing publisher eligibility. The Avail tooling checks finalized eligibility, exact raw payload bytes, successful canonical publication and the bridge/VectorX receipt path. A publisher route and verified runtime fee/accounting policy remain required before new publication. Recheck current network state and operator access rather than treating stored observations as current authorization.

## Optional RAILGUN funding

The integration prepares shield/unshield transactions and gated bidder funding. It does not establish a completed private spend or an available independent Sepolia broadcaster. Funding and bidding are separate transactions; participation, public destinations, deposit ceilings, timing, revealed bids and NFT ownership remain visible.

See [program design](E3-PROGRAM.md), [Avail tooling](../pilot/avail/README.md), [RAILGUN tooling](../pilot/railgun/README.md), and [local checks](PILOT-RUNBOOK.md).
