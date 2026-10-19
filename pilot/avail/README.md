# Avail Turing ciphertext publication tooling

This package creates a dedicated local Turing test account, checks finalized publisher eligibility, prepares an **unsigned** Avail `dataAvailability.submitData` call, records its nominal fee quote, and retrieves/verifies publications. It also has a policy-pinned `publish` command for **one exact synthetic ciphertext**. Publication fails closed on missing publisher eligibility or unverified runtime fee/accounting policy. Other network commands are read only. No command accepts a seed or requests faucet funds.

```sh
cd pilot/avail
npm ci
npm test
node cli.mjs wallet-init
node cli.mjs preflight
node cli.mjs eligibility
node cli.mjs eligibility PUBLIC_SS58_ADDRESS
node cli.mjs plan /absolute/path/ciphertext.bin --app-id 0 --publisher PUBLIC_SS58_ADDRESS
node cli.mjs proof /absolute/path/ciphertext.bin --block-hash 0xBLOCK_HASH --index EXTRINSIC_INDEX
```

Node 22.15 or newer is required. Dependencies are pinned to `avail-js-sdk@0.4.2`, `@polkadot/api@15.10.2`, and `ethers@6.15.0` in the lockfile.

`wallet-init` uses a fresh cryptographically random 24-word mnemonic and an sr25519 key. It never derives from the Sepolia or Railgun credentials. Only the public SS58 address/public key are printed. The mnemonic is written exclusively to ignored `.local/wallet.private.json`: directory mode `0700`, file mode `0600`, current owner, no symbolic links, exclusive creation, and file/directory sync before success. A secure existing wallet is checked and reused without replacement; insecure permissions, corrupt data, and mismatched public identity cause refusal. The wallet is dedicated by this project's policy to Avail Turing, though Substrate keys are technically usable on other compatible networks. No funds are requested or sent by initialization.

The file must contain the **raw serialized ciphertext bytes**, not JSON or a textual hex representation. The plan hashes exactly those bytes with Keccak-256, records SHA-256 separately, and enforces both the local one-MiB cap and the live chain limit. The submitted data is public ciphertext; private bid witnesses and encryption randomness must never be passed to this command.

The publisher argument is a public SS58 address or a 32-byte public key. Ethereum's 20-byte addresses and secret URIs are rejected. An App ID must be supplied explicitly: `0` is Avail's shared public default; an allocated nonzero ID gives an application namespace. The plan checks the chain's allocation counter but does not assert ownership or exclusivity. The nominal `paymentInfo` estimate includes the selected `CheckAppId` signed extension and uses Polkadot's internal fake signature only for estimation. The exported call remains unsigned. A nominal quote does not establish the actual debit or a funding requirement: observed cutover transactions emitted nonzero `TransactionFeePaid` amounts while their publishers' free balances did not decrease.

**App ID 0 does not bypass publisher eligibility.** It needs no dedicated application registration, but the live cutover runtime also requires the signer to appear in `dataAvailability.submitDataWhitelist`. The `eligibility` command defaults to the dedicated public account and can inspect another public address without reading any wallet file. It pins the whitelist query, runtime version, and runtime `:code` storage hash to one finalized block, records those coordinates, and fails closed on missing metadata, an undecodable entry, or an RPC error. Preflight and unsigned plans include this report.

Publisher access must be checked at a current finalized block. Sending native tokens cannot resolve an absent whitelist entry. Use an eligible Turing operator to publish the exact raw ciphertext or obtain approved publisher access, retaining the configured Sepolia bridge/VectorX receipt path. The [pinned official cutover source](https://github.com/availproject/avail/blob/9da074d9f5da7617e59ad9f12a41b8de6fc69d3c/runtime/src/impls.rs) changes call filtering and fee handling. A runtime version alone does not establish a verified zero-fee signing policy.

The default RPC is `https://turing-rpc.avail.so/rpc`. Genesis is pinned to `0xd3d2f3a3495dc597434a99d7d449ebad6616db45e4e4f178f31cc6fa14378b70`. The tool also checks AVAIL/18-decimal token properties, `submitData`, and the `CheckAppId` extension. `AVAIL_RPC_URL` may select another HTTP RPC for the same chain. `AVAIL_BRIDGE_API_URL` and `SEPOLIA_RPC_URL` override their respective public endpoints without changing chain or verifier pins.

After publication, the proof command:

1. Retrieves the selected finalized, canonical Avail block and decodes the exact `submitData` extrinsic with the pinned SDK.
2. Requires successful dispatch and byte-for-byte equality with the supplied ciphertext file.
3. Fetches the official bridge's `/v1/proof/11155111?block_hash=…&index=…` proof, binding its leaf and block to those bytes.
4. Verifies the inclusion proof with the existing Sepolia adapter `0x6D373da705B443EF76e37cb96275623818c50657`, checking pinned adapter/bridge/VectorX runtime hashes and wiring.
5. Requires the receipt to return the same content hash and Avail block, then confirms that changing only the proof or changing the content hash causes a revert.

The bridge may need time to cover a newly finalized block. A successful call plan is not a publication receipt. A proof API response alone is not accepted. An unavailable API, historical state, or unbridged range causes the command to fail; it never substitutes a mock proof.

Generated plans, verified proof bytes, valid/tampered verifier calldata, and recovered ciphertexts are saved under ignored `.local/`. A verified proof's `availabilityProof` can be used as the availability part of the auction envelope once the separate encrypted-input proof is ready. These artifacts concern data availability only.

## Pinned synthetic publication command

```sh
node cli.mjs publish
node cli.mjs publish-status
```

`publish` takes no payload, destination, amount, App ID, or seed arguments. It is pinned to publisher `5FNAKEHhsAXs3N4kJv7A5ddhCHyUMv2U86G8Cmm3xSR3iMcf`, App ID 0, and the 368,666-byte ciphertext in the root `.pilot/proof-public-bid.json` whose Keccak-256 is `0x1d167bffa8274622f5bd4df4dea74a7f2c3adea3f68c89e6ce87f49c98cf87f9`. It saves the exact raw bytes as ignored `.pilot/avail-authorized-ciphertext.bin`. It sends no ETH, token transfer, or other call.

Before reading wallet material, creating a signed intent, signing, or broadcasting, `publish` checks the dedicated publisher's finalized whitelist entry. An absent entry or unknown eligibility refuses immediately. An otherwise whitelisted account is then blocked by an explicit **unverified fee/accounting policy** gate. The observed runtime is identified by both spec version 57 and `:code` storage hash `0xa8c685d1049161bb6ccc61a0b85d0a9e2091b814f8d89c27b34dc62b68c103fc`; other runtime hashes remain unknown and blocked. Recognition records the accounting limitation and does not enable publication.

The existing conservative transaction guards remain for a future verified policy: pinned Turing genesis, secure local wallet, no pending nonce, a signed-transaction fee quote, a 25% quote reserve within a local 0.3 AVAIL budget, and four-block mortality, with balance/nonce/block rechecks. **The 0.3 AVAIL budget is a local gate, not a consensus-enforced max fee.** These guards do not establish that cutover transactions require funding. Whitelist and runtime identity are also rechecked before a prepared signed intent could be saved.

An exclusive execution lock prevents concurrent publication. The complete signed transaction, exact transaction hash, nonce, payload hash, expiry, quoted fee, budget, and pre-submission balance are written to owner-only `.local/publication-intent.json` and synced to disk **before** the single submission attempt. An existing intent blocks every later `publish` invocation. A timeout or RPC error preserves the intent and never triggers a retry. `publish-status` only observes that saved transaction; it does not sign or broadcast. A lock left by a killed process requires checking that process and its saved intent before manual recovery.

The existing receipt observer requires finalized canonical inclusion, successful dispatch, exact ciphertext bytes, and a nominal fee event matching the dedicated-wallet balance debit. Cutover observations contradict that last equality, so this accounting path must be updated and verified before the signing gate can be enabled. No automatic zero-fee exception has been added. Publication finality does not establish a bridge receipt: use `proof` with the returned block hash and extrinsic index after VectorX bridges the range.

Funding UI messages do not establish successful on-chain transfers. Verify canonical finalized dispatch/events independently. Publisher eligibility and runtime fee/accounting gates remain independent of balance.

Reference behavior was checked against the [official Avail SDK](https://github.com/availproject/avail-js), [Avail data submission documentation](https://docs.availproject.org/docs/da/build/interact), and [official bridge proof API documentation](https://docs.availproject.org/docs/da/api-reference/avail-bridge-api/merkle-proof). The deployed Interfold adapter ABI and bridge constants match the pinned Interfold v0.19.0 source used by the root pilot.
