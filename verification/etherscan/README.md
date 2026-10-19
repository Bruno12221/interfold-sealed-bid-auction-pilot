# Sepolia contract source verification

The eleven Standard JSON inputs in this directory preserve the deployed contracts' original Solidity source bytes, source paths and compiler settings. `manifest.json` records each deployed address, compiler, fully qualified contract name, existing source license, constructor arguments, linked library addresses and the SHA-256 of its input file. Paths are relative to the repository root.

To reproduce source verification on Sepolia Etherscan:

1. Open the contract's `verificationFormUrl` from the manifest.
2. Choose **Solidity (Standard-Json-Input)**, the recorded compiler and existing source license.
3. Upload its `standardInputPath` file, select the recorded contract identifier if requested, and supply `encodedConstructorArguments` without an `0x` prefix if Etherscan requests constructor arguments.
4. For `encryptionVerifier`, use the recorded `RelationsLib` and `ZKTranscriptLib` addresses if requested. These contracts were linked after compilation; the input intentionally preserves the original compiler library settings.

All compiler settings are inside each input. Source verification is an off-chain publication step: it sends no Ethereum transaction and requires no wallet private key. An Etherscan API key is needed only when using their API instead of the browser form. Existing SPDX notices and bundled dependency licenses continue to apply.

The manifest records verification inputs, not a claim that every Etherscan submission succeeded. Consult the repository's deployment verification report and the explorer links for current results. `AuctionE3Program` is not included because it has not been deployed.
