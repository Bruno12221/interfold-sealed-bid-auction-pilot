# Pinned Interfold OpenVM receipt adapter

These files are copied byte for byte from
[`theinterfold/interfold` commit `c65722fcab24b3b5ffc7ccaf4544bd1d6ef8826a`](https://github.com/theinterfold/interfold/tree/c65722fcab24b3b5ffc7ccaf4544bd1d6ef8826a/packages/interfold-contracts/contracts):

| Local file | Upstream path below `contracts/` | SHA-256 |
| --- | --- | --- |
| `verifiers/OpenVmReceiptVerifier.sol` | `verifiers/OpenVmReceiptVerifier.sol` | `007970934607f06893608b6cf7fa8bf16646f6ad723f3833e8e32e4aecc5d066` |
| `interfaces/IOpenVmReceiptVerifier.sol` | `interfaces/IOpenVmReceiptVerifier.sol` | `c60e70b188e0bc6eba4a8f8e661462c13a9d25aaa102954b2a8a1b941ae2f80b` |

No source or import changes were needed. The original LGPL-3.0-only SPDX headers and disclaimer
are retained. `LICENSE.md` contains the upstream license text.

The adapter authenticates a canonical versioned ABI seal and delegates the actual Halo2 proof
verification to its immutable verifier contract. Its image identity binds that verifier's address,
the executable commitment and the VM commitment. Tests for this adapter use an explicit Halo2
test double and establish receipt codec and forwarding behavior only.

The official OpenVM v2.0.2 Halo2 verifier source requires Solidity 0.8.19. Its precompiled pinned
artifact is deployed separately; it is not vendored into this Solidity 0.8.28 source tree.
