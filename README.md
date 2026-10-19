# Interfold sealed-bid auction source

A source-review snapshot of an **addition-only secure8192 second-price NFT auction demo** for Ethereum Sepolia. Each encrypted bid occupies its assigned BFV coefficient. The encrypted computation adds those inputs; threshold decryption after bidding closes reveals every bid, and Solidity selects the winner and second-highest price. **Losing bids are public after decryption.**

The repository includes Solidity contracts, the secure8192 Noir encryption/bid circuit, Rust encryption and OpenVM guests, deployment tooling, tests, and public synthetic proof fixtures. Genuine Noir and final OpenVM receipts are included for local verifier/composition checks. **A live threshold-network encrypted auction has not completed.**

`AuctionE3Program` is **not deployed or registered**. The recorded result source is unbound. Deployment needs reviewed immutable configuration and deadlines, actual-program release evidence, protocol-owner registration and one-time source binding. A compatible operator/proving service, fresh auction-specific proofs, an authorized Avail publication route with authenticated Sepolia DA receipts, and threshold decryption are also required. The reusable eight-contract verifier stack is deployed. RAILGUN funding integration is prepared; a successful private spend and usable independent Sepolia broadcaster have not been demonstrated.

## Review entrypoints

| Area | Source |
| --- | --- |
| Auction, NFT escrow, payment and refunds | [SealedBidAuction.sol](src/SealedBidAuction.sol) |
| Authenticated decrypted result | [InterfoldResultSource.sol](src/InterfoldResultSource.sol) |
| Per-auction input and compute admission | [AuctionE3Program.sol](src/AuctionE3Program.sol), [design](docs/E3-PROGRAM.md) |
| Encryption proof plus public ciphertext binding | [AuctionInputVerifier.sol](src/AuctionInputVerifier.sol), [Noir circuit](circuits/auction-input/README.md), [binding guest](pilot/auction-input-binding/README.md) |
| Addition-only encrypted computation | [Rust worker and guest](pilot/auction-compute/README.md), [client encryption](pilot/bfv-slots/README.md) |
| Final OpenVM receipts | [Receipt worker](pilot/openvm-prover/README.md), [synthetic fixtures](test/fixtures/openvm-receipts/README.md) |
| Data availability and optional private funding | [Avail tooling](pilot/avail/README.md), [RAILGUN tooling](pilot/railgun/README.md) |

The demo uses bids 0–100 ticks, with zero representing abstention. The highest positive bid wins; the earliest accepted input wins ties. The winner pays the runner-up amount, including the tied amount on a tie; a sole positive bidder pays zero. The recorded auction allows 16 bidders, with a contract maximum of 32. Deposits are uniform, and refunds use withdrawals. The contract returns the NFT and refunds deposits after a failed settlement timeout.

## Reproduce local checks

Requires Node.js 20+, npm and Foundry with Solidity 0.8.28. Native cryptography requires Rust 1.91.1+; Noir checks require Nargo 1.0.0-beta.26. The optional RAILGUN and Avail packages require Node.js 22.15+ and their separate lockfiles.

```sh
npm ci
forge build
npm test
npm run test:bfv
```

The exact Foundry optimizer/EVM settings are in [foundry.toml](foundry.toml). Cargo and npm lockfiles pin dependencies; upstream Interfold/OpenVM revisions are recorded in manifests and fixture provenance. [Development checks](docs/PILOT-RUNBOOK.md) describe additional package checks. The checked-in proof fixtures require no new expensive proving job. Full local cryptography and fresh OpenVM proving are separate operations with substantial setup, memory and runtime requirements.

`npm run preflight` and `npm run pilot:status` query live network/services and write local reports; they do not send transactions. A status exit code of 2 reports unmet prerequisites. Deployment, funding and publication commands require separately configured testnet keys and passing release gates; they are not part of the local test commands above.

## Recorded Sepolia deployments

Chain ID **11155111**. The foundation and eight reusable verifier contracts have recorded exact Sourcify source matches. These records describe synthetic-fixture validation, not a completed live auction or release approval. Explorer verification status may change; independently compare creation/runtime bytecode and constructor arguments.

| Component | Sepolia address |
| --- | --- |
| Second-price auction | [0x63B12dda13bF51e0FF8BDEc4C9DaaF03786792C3](https://sepolia.etherscan.io/address/0x63B12dda13bF51e0FF8BDEc4C9DaaF03786792C3#code) |
| Interfold result source | [0x8A5465A0E50cd28c0D4f4370b644e90e042feF58](https://sepolia.etherscan.io/address/0x8A5465A0E50cd28c0D4f4370b644e90e042feF58#code) |
| Demo NFT | [0x2e584f69C14D0244E0d545faa679F215E6AeEd46](https://sepolia.etherscan.io/address/0x2e584f69C14D0244E0d545faa679F215E6AeEd46#code) |
| OpenVM Halo2 verifier | [0x025eBbBA94D479810cabd5ec01162EC4792DF8EE](https://sepolia.etherscan.io/address/0x025eBbBA94D479810cabd5ec01162EC4792DF8EE#code) |
| Input-binding receipt adapter | [0x4f6ea50BF0FBe573eeFD29cAc3902B7b732832F8](https://sepolia.etherscan.io/address/0x4f6ea50BF0FBe573eeFD29cAc3902B7b732832F8#code) |
| Computation receipt adapter | [0x9Bc72b09f28770d9F6Da71BAC26e8Cd47ACEaB83](https://sepolia.etherscan.io/address/0x9Bc72b09f28770d9F6Da71BAC26e8Cd47ACEaB83#code) |
| Noir RelationsLib | [0xDbeE2A075f2ef9E195f3b3F2805718E443A43009](https://sepolia.etherscan.io/address/0xDbeE2A075f2ef9E195f3b3F2805718E443A43009#code) |
| Noir ZKTranscriptLib | [0x2B3D50baCAc6A2F0C52898Febf21AA0cB50DD96E](https://sepolia.etherscan.io/address/0x2B3D50baCAc6A2F0C52898Febf21AA0cB50DD96E#code) |
| Noir HonkVerifier | [0x6E4F3087F0e4A735528fA224Dd5182aBFB86eCcc](https://sepolia.etherscan.io/address/0x6E4F3087F0e4A735528fA224Dd5182aBFB86eCcc#code) |
| Composed AuctionInputVerifier | [0xDe64B2bf17EcC3A933163952427b690eF65Af03D](https://sepolia.etherscan.io/address/0xDe64B2bf17EcC3A933163952427b690eF65Af03D#code) |
| AuctionPoseidon | [0x48624777D0b156caD8F1F67aAeDEa8b40D381369](https://sepolia.etherscan.io/address/0x48624777D0b156caD8F1F67aAeDEa8b40D381369#code) |

[Foundation deployment](deployments/sepolia.json), [verifier deployment](deployments/verifiers-sepolia.json), and [verification notes](docs/VERIFIER-DEPLOYMENT.md) retain public addresses, transaction identifiers, code hashes and proof identities. Sourcify source is accessible at `https://repo.sourcify.dev/11155111/CONTRACT_ADDRESS`.

## Fixture and disclosure scope

Files under `test/fixtures/auction-input/` and `test/fixtures/openvm-receipts/` are **public synthetic test fixtures**: proofs, public statements/journals, verifier bytecode and provenance. They do not include encryption witnesses, private bid inputs, wallet keys or live funding linkage. The two OpenVM receipt domains differ and cannot be reused as one live auction or as new auction proofs.

This source snapshot excludes private repository history, conversations, local research, wallet databases, runtime proof jobs and operator logs. Preserve the ignore rules when developing locally. Review metadata before publishing any new artifacts.

Use testnet assets and synthetic inputs. The code has tests and has not received an independent security audit. Retained SPDX headers, [vendor notices](src/vendor/NOTICE.md), [Interfold adapter license](src/vendor/interfold-openvm/LICENSE.md), [worker license](pilot/openvm-prover/LICENSE.md), and [OpenVM verifier notice](test/fixtures/openvm-receipts/LICENSE-OpenVM-MIT.txt) apply to their respective files.
