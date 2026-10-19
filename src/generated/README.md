# Auction encryption verifier provenance

`AuctionInputHonkVerifier.sol` is unmodified Barretenberg 5.2.0 output for
`circuits/auction-input`, generated with the **`evm` ZK target**:

```sh
bb write_solidity_verifier -k PRIVATE_PROOF_DIRECTORY/evm-proof/vk \
  -o AuctionInputHonkVerifier.sol -t evm
```

The circuit uses Interfold commit
`c65722fcab24b3b5ffc7ccaf4544bd1d6ef8826a`, Nargo `1.0.0-beta.26`, and the
explicit secure8192 parameter preset. SHA256 of the decoded ACIR bytecode is
`eb4c1699b4f25cf4bf86709095cb51c06d31acbf6cee16d6b7ce304770319eb6`.
The generated VK hash is
`04174322bda40dd3591a7dbc955c75fb0bf1c566073d90ed889a20d2b438017c`.

The generated verifier expects **26 external public limbs**. Its internal
`NUMBER_OF_PUBLIC_INPUTS = 34` also includes eight pairing accumulator words
carried in the proof. Do not add these eight words to the public input array.

At solc 0.8.28, optimizer 200, Cancun, runtime sizes are 18,242 bytes for
`HonkVerifier`, 7,972 for the linked `RelationsLib`, and 6,151 for the linked
`ZKTranscriptLib`; all three must be deployed and linked. Real proof EVM
verification costs approximately 3.67 million gas. These are local measurements,
not Sepolia deployments.

The original generated source SHA256 is
`9e13de6a82e607a5b916ae663fa561eb83d7c8f01ef60b3346cf6584764a15cc`.
Do not hand-edit the verifier or substitute a non-ZK target. Recompile the
Noir circuit, regenerate the proof/VK/verifier, update provenance, and run the
actual cryptographic fixture tests when changing the circuit.
