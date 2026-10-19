import { promisify } from 'node:util';
import { execFile } from 'node:child_process';
import { Interface } from 'ethers';
import path from 'node:path';
import { CHAIN_ID, CONTRACTS } from './config.mjs';
import { ROOT, LOCAL, json, rpc, requestJSON, writePrivate } from './lib.mjs';
const execute = promisify(execFile);
const iface = new Interface(['function shieldFee() view returns (uint120)', 'function unshieldFee() view returns (uint120)', 'function railgun() view returns (address)', 'function wBase() view returns (address)']);

export async function contractState(rpcUrl) {
  const chainId = Number(BigInt(await rpc(rpcUrl, 'eth_chainId')));
  if (chainId !== CHAIN_ID) throw new Error(`Wrong chain: ${chainId}`);
  const block = await rpc(rpcUrl, 'eth_blockNumber');
  const bytecodes = await Promise.all(Object.values(CONTRACTS).map(address => rpc(rpcUrl, 'eth_getCode', [address, 'latest'])));
  if (bytecodes.some(code => code === '0x')) throw new Error('A required Railgun contract has no code');
  const call = async (address, name) => iface.decodeFunctionResult(name, await rpc(rpcUrl, 'eth_call', [{ to: address, data: iface.encodeFunctionData(name) }, 'latest']))[0];
  const [shieldFeeBP, unshieldFeeBP, relayProxy, relayWeth] = await Promise.all([
    call(CONTRACTS.proxy, 'shieldFee'), call(CONTRACTS.proxy, 'unshieldFee'), call(CONTRACTS.relayAdapt, 'railgun'), call(CONTRACTS.relayAdapt, 'wBase'),
  ]);
  if (relayProxy.toLowerCase() !== CONTRACTS.proxy.toLowerCase() || relayWeth.toLowerCase() !== CONTRACTS.weth.toLowerCase()) throw new Error('RelayAdapt points to unexpected pool or WETH');
  return { chainId, blockNumber: Number(BigInt(block)), shieldFeeBP: String(shieldFeeBP), unshieldFeeBP: String(unshieldFeeBP), contracts: CONTRACTS, relayWiringVerified: true, contractReadBlockTag: 'latest' };
}

export async function preflight({ rpcUrl, poiUrls, graphqlUrl, includeBroadcasters = true }) {
  const capture = async fn => { try { return { ok: true, result: await fn() }; } catch (error) { return { ok: false, error: error.message }; } };
  const [contracts, graphql, poi, broadcasters] = await Promise.all([
    capture(() => contractState(rpcUrl)),
    capture(async () => {
      const result = await requestJSON(graphqlUrl, { query: '{ squidStatus { height } }' });
      if (typeof result.data?.squidStatus?.height !== 'number') throw new Error('Indexer did not return a synchronized height');
      return result.data;
    }),
    Promise.all(poiUrls.map(url => capture(async () => {
      const [health, validated] = await Promise.all([
        requestJSON(url, { jsonrpc: '2.0', id: 1, method: 'ppoi_health', params: {} }),
        requestJSON(url, { jsonrpc: '2.0', id: 2, method: 'ppoi_validated_txid', params: { chainType: '0', chainID: String(CHAIN_ID), txidVersion: 'V2_PoseidonMerkle' } }),
      ]);
      if (health.result !== 'OK') throw new Error('PPOI health is not OK');
      if (!Number.isSafeInteger(validated.result?.validatedTxidIndex) || validated.result.validatedTxidIndex < 0 || !/^(0x)?[0-9a-fA-F]{64}$/.test(validated.result?.validatedTxidMerkleroot)) throw new Error('PPOI returned no valid Sepolia TXID state');
      return { origin: new URL(url).origin, health: health.result, validated: validated.result };
    }))),
    includeBroadcasters ? capture(async () => {
      const { stdout } = await execute(process.execPath, [path.join(ROOT, 'broadcaster-probe.mjs')], { cwd: ROOT, timeout: 45_000, maxBuffer: 500_000 });
      const lines = stdout.trim().split('\n');
      return JSON.parse(lines.at(-1));
    }) : Promise.resolve({ ok: false, skipped: true, error: 'Broadcaster discovery skipped by explicit command option' }),
  ]);
  const report = {
    observedAt: new Date().toISOString(), readOnly: true, chainId: CHAIN_ID,
    contracts, graphql, poi, broadcasters,
    fundingReady: false,
    limitations: ['No shield/private spend, proof, or broadcast was executed.', 'Public endpoint health does not establish spendability or broadcaster transaction acceptance.', 'Private balances require complete scanning, valid PPOI and artifacts; fresh shield standby can delay spending.', 'The auction E3 program must be registered and bound before bid funding is useful.'],
  };
  if (contracts.ok && graphql.ok) {
    const lag = contracts.result.blockNumber - graphql.result.squidStatus.height;
    report.graphql.blockLag = lag;
    if (lag > 2000 || lag < -10) { report.graphql.ok = false; report.graphql.error = 'Indexer height differs materially from RPC head'; }
  }
  await writePrivate(path.join(LOCAL, 'preflight.json'), report);
  return report;
}
