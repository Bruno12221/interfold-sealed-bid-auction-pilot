# Optional RAILGUN-funded Sepolia bidders

This package prepares test ETH shielding as WETH and official RAILGUN base-token withdrawals through an independent broadcaster to fresh Ethereum bidder accounts. Funding and bidding are separate transactions. Public destinations, participation, deposit ceilings, amounts, timing, later revealed bids and NFT/refund ownership remain visible.

**Integration is prepared; a successful private spend and usable independent Sepolia WETH broadcaster have not been demonstrated.** Auction funding is gated on the separate program release, registration and source binding. SDK initialization and unsigned transaction preparation do not establish private funding or a completed auction.

## Local checks and preparation

Use Node.js **22.15+**. The lockfile pins wallet 10.9.0, engine 9.6.0, shared-models 8.0.1 and Waku client 9.0.1 for the Sepolia V2 route.

```sh
cd pilot/railgun
npm ci
npm test
npm run wallet:init
npm run preflight
npm run sdk:smoke
npm run funding:plan
```

`wallet:init` creates local spending authority and fresh bidder keys once, then reuses the same secure local wallet. `.local/` is ignored; its directory is mode 0700 and wallet/report files are mode 0600. Keep a private backup before funding. No wallet file or funding-linkage report is part of this source snapshot.

`.env.example` documents optional configuration. The CLI does not automatically load `.env`; export variables or use Node's `--env-file=.env`. Supply the public funder address locally. The public deployment identities in source/configuration and deployment records are testnet account identifiers, not signing keys.

`preflight` reads current code/wiring, fees, indexer/PPOI health and broadcaster offers; it exits 2 while dependencies are unavailable. `--skip-broadcasters` leaves that dependency unverified. A configured RPC weight of 2 meets the SDK fallback-provider requirement but is still one RPC source.

`npm run shield:prepare` uses the configured public funder and live SDK to write an unsigned shield transaction under `.local/`. It neither signs nor broadcasts. Budgets are caps rather than live fee quotes. Fees use inclusive rounding so each planned withdrawal delivers its equal intended net ETH. Shield gas is paid separately by the funder.

## Sending requires a complete release

Sending commands are real testnet transaction operations. They require a reviewed `PILOT_RELEASE_MANIFEST`, ready bound/registered program, pinned verifier/guest/artifact identities, genuine known-answer/tampered-proof checks, live services and a usable independent WETH broadcaster. An incomplete release blocks funding before signing-key access.

`shield:send` re-prepares and checks the transaction, verifies the locally supplied key matches the public funder, signs once and persists its hash. It refuses duplicate shielding. A receipt alone does not establish note spendability.

`unshield:prepare -- INDEX` requires synchronized spendable notes, a live signed fee advertisement and PPOI, generates the actual Groth16 spend proof, simulates the populated withdrawal and saves it privately. `unshield:send -- INDEX` repeats preparation, broadcasts through the official SDK and verifies exact destination delivery. Process one bidder at a time because prepared proofs may consume the same notes. Fresh destinations must have no code and zero ETH balance. There is no public self-send fallback.

The official V2 route sets `ActionData.requireSuccess=false`. The tool preserves proof-bound calldata and checks fresh destinations, simulation, exact delivery and empty adapter balances. These detect unexpected failure but do not make the SDK multicall strictly atomic. A failure can leave public adapter funds; inspect the persisted receipt/events before recovery. No generic rescue path is implemented.

## Independent broadcaster configuration

```sh
node broadcaster-probe.mjs
RAILGUN_BROADCASTER_CONFIG=/absolute/path/operator-probe.json node broadcaster-probe.mjs
```

The optional **public** JSON affects the read-only probe/preflight only:

```json
{
  "schemaVersion": 1,
  "chainId": 11155111,
  "feeToken": "0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14",
  "useRelayAdapt": true,
  "broadcasterAllowlist": ["REPLACE_WITH_OPERATOR_PUBLIC_0zk_ADDRESS"]
}
```

Supply a valid public operator address. Optional verified ENR DNS discovery supplies messaging peers; it does not create a broadcaster or fee offer. The pinned client routes to `/waku/2/rs/1/1`. Direct-peer, topic/shard, signature, version and PPOI-policy substitutions are rejected. An allowlist or ordinary HTTP URL cannot replace a fresh signed fee advertisement.

Transaction-side restricted operator selection needs separate review. Discovery does not enable spending or establish operator independence. A broadcaster must advertise Sepolia WETH `0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14`, exact RelayAdapt `0x7e3d929EbD5bDC84d02Bd3205c777578f33A214D`, compatible PPOI and cluster/shard routing. Its gas wallet needs independent funding appropriate to the intended funding-origin privacy. The [pinned official broadcaster example](https://github.com/Railgun-Community/ppoi-safe-broadcaster-example/tree/ec49691533b4edc2dafefbd8cdb5f611290b2115) requires explicit Sepolia, token and Waku configuration; deployment or availability is not established here.

## Primary references

- [Official RAILGUN engine initialization](https://docs.railgun.org/developer-guide/wallet/getting-started/5.-start-the-railgun-privacy-engine)
- [Official base-token shielding](https://docs.railgun.org/developer-guide/wallet/transactions/shielding/shield-base-token)
- [Official base-token unshielding](https://docs.railgun.org/developer-guide/wallet/transactions/unshielding/unshield-base-token)
- [Official Waku broadcaster APIs](https://docs.railgun.org/developer-guide/wallet/broadcasters)
- [Pinned Sepolia network configuration](https://github.com/Railgun-Community/shared-models/blob/b37e643ef38e3df554deffa33f40530b20ce9065/src/models/network-config.ts)
- [Pinned pool inclusive fee logic](https://github.com/Railgun-Community/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/RailgunLogic.sol)
- [Pinned V2 base-token adapter SDK route](https://github.com/Railgun-Community/engine/blob/6e2614d53a106dd62abad91e7ce03ee4a3956138/src/contracts/relay-adapt/V2/relay-adapt-v2.ts)
