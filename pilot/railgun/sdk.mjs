import fs from 'node:fs/promises';
import path from 'node:path';
import LevelDOWN from 'leveldown';
import { groth16 } from 'snarkjs';
import * as wallet from '@railgun-community/wallet';
import { NETWORK_CONFIG, NetworkName } from '@railgun-community/shared-models';
import { CHAIN_ID, CONTRACTS } from './config.mjs';
import { LOCAL, SECRET_FILE, privateDirectory, writePrivate } from './lib.mjs';

export const SDK = wallet;
export const NETWORK_NAME = NetworkName.EthereumSepolia;

export async function initializeSDK({ rpcUrl, poiUrls, shieldOnly = false }) {
  await privateDirectory();
  const artifactRoot = path.join(LOCAL, 'artifacts');
  await privateDirectory(artifactRoot);
  const artifactPath = requested => {
    const result = path.resolve(artifactRoot, requested);
    if (!result.startsWith(artifactRoot + path.sep)) throw new Error('Artifact path escapes local store');
    return result;
  };
  const artifactStore = new wallet.ArtifactStore(
    async requested => {
      try { return await fs.readFile(artifactPath(requested)); }
      catch (error) { if (error.code === 'ENOENT') return null; throw error; }
    },
    async (_directory, requested, data) => {
      const file = artifactPath(requested);
      await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
      await fs.writeFile(file, data, { mode: 0o600 });
    },
    async requested => {
      try { await fs.access(artifactPath(requested)); return true; }
      catch (error) { if (error.code === 'ENOENT') return false; throw error; }
    },
  );
  const network = NETWORK_CONFIG[NETWORK_NAME];
  if (network.chain.id !== CHAIN_ID || network.supportsV3 || network.proxyContract.toLowerCase() !== CONTRACTS.proxy.toLowerCase() || network.relayAdaptContract.toLowerCase() !== CONTRACTS.relayAdapt.toLowerCase()) throw new Error('Installed SDK network configuration differs from pinned Sepolia V2 deployment');
  await wallet.startRailgunEngine('interfold pilot', new LevelDOWN(path.join(LOCAL, 'engine.db')), false, artifactStore, false, shieldOnly, poiUrls, [], false);
  wallet.getProver().setSnarkJSGroth16(groth16);
  return { network, stop: async () => { await wallet.unloadProvider(NETWORK_NAME).catch(() => {}); await wallet.stopRailgunEngine(); } };
}

export async function loadSDKProvider(rpcUrl) {
  return wallet.loadProvider({ chainId: CHAIN_ID, providers: [{ provider: rpcUrl, priority: 1, weight: 2, maxLogsPerBatch: 5, stallTimeout: 2500 }] }, NETWORK_NAME, 15_000);
}

export async function createOrLoadWallet(state, creationBlock) {
  let info;
  if (state.railgun.id) {
    info = await wallet.loadWalletByID(state.railgun.encryptionKey, state.railgun.id, false);
  } else {
    info = await wallet.createRailgunWallet(state.railgun.encryptionKey, state.railgun.mnemonic, { [NETWORK_NAME]: creationBlock });
    state.railgun.id = info.id;
    state.railgun.address = info.railgunAddress;
    state.railgun.creationBlock = creationBlock;
    await writePrivate(SECRET_FILE, state);
  }
  return info;
}
