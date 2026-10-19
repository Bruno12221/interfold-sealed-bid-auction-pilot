# Recorded verifier deployment and release boundary

The [Sepolia verifier record](../deployments/verifiers-sepolia.json) contains eight reusable deployed contracts: the pinned Halo2 verifier, input-binding and computation receipt adapters, Noir RelationsLib/ZKTranscriptLib/HonkVerifier, composed AuctionInputVerifier and AuctionPoseidon. Public transaction identifiers, constructor arguments, runtime hashes, application commitments and synthetic known-answer results are retained.

The contracts have recorded exact source matches on Sourcify. The generated OpenVM verifier uses its pinned Solidity 0.8.19 artifact; the application contracts use the Solidity 0.8.28 settings in `foundry.toml`. The linked Noir libraries must preserve the original metadata and explicit link references. The immutable receipt adapters bind distinct executable identities to the same pinned OpenVM verifier.

`AuctionE3Program` is not deployed, registered or bound. The synthetic receipts authenticate public fixture domains. Successful fixture checks do not establish a live release, committee participation, current operator availability or circuit security.

## Reproduce source and fixture checks

```sh
npm ci
forge build
npm test
```

Compare recorded creation transactions, constructor arguments and runtime code independently. The retained Sourcify scripts can regenerate verification inputs from local build artifacts; publication requires external service availability and does not change contract state. [The top-level source map](../README.md) lists all recorded addresses.

## Release prerequisites

The full release path additionally needs reviewed immutable program deadlines/configuration, address-bound input known answers, fresh actual-auction proofs, owner registration and one-time source binding. The DA route must authenticate exact raw ciphertext bytes through the configured Sepolia verifier. An eligible publisher, compatible computation/threshold operators and realistic proving/decryption time are independent requirements.

`npm run plan:program` is planning tooling. Review generated plans and live preflight output before any deployment or binding. A predicted address remains conditional on the deployer's transaction nonce. Neither a source match nor an unpaused protocol approves an application for live use.
