import { FetchRequest, JsonRpcProvider } from 'ethers';

export const CHAIN_ID = 11155111;
export const DEPLOYER = '0xabF398A8e62CD68137987C4b99C0f24a5FDcd97a';
export const PROTOCOL = '0xBD5B6D1aDA9e0eB248B678469C9Cd6a63507E42b';
export const FEE_TOKEN = '0xE2e534F7Cb95777eD870CDCaCb80B1E9E2aD555B';
export const EXPLORER = 'https://sepolia.etherscan.io';
export const protocolAbi = [
  'function requestsPaused() view returns (bool)',
  'function owner() view returns (address)',
  'function feeToken() view returns (address)',
  'function e3Programs(address) view returns (bool)',
  'function getCiphertextVerifier(bytes32) view returns (address)',
];

export async function sepoliaProvider() {
  const rpc = process.env.SEPOLIA_RPC_URL || 'https://ethereum-sepolia.publicnode.com';
  const request = new FetchRequest(rpc);
  request.timeout = 30_000;
  const provider = new JsonRpcProvider(request);
  try {
    const network = await provider.getNetwork();
    if (network.chainId !== BigInt(CHAIN_ID)) throw new Error('Refusing RPC: expected Sepolia chain ID 11155111.');
    if (await provider.getCode(PROTOCOL) === '0x') throw new Error('No Interfold code at the pinned Sepolia address. Refresh the manifest.');
    return provider;
  } catch (error) { provider.destroy(); throw error; }
}
