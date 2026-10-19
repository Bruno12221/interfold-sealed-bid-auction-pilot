import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { RailgunEngine } from '@railgun-community/engine';
import { parseBroadcasterProbeConfig, loadBroadcasterProbeConfig, compatibleBroadcasterOffer } from '../broadcaster-config.mjs';
import { probeBroadcasters } from '../broadcaster-probe.mjs';
import { CHAIN_ID, CONTRACTS } from '../config.mjs';

// Synthetic public address encoding only; no mnemonic, private key or wallet.
const publicAddress = RailgunEngine.encodeAddress({ masterPublicKey: 1n, viewingPublicKey: new Uint8Array(32).fill(1) });
const otherAddress = RailgunEngine.encodeAddress({ masterPublicKey: 2n, viewingPublicKey: new Uint8Array(32).fill(2) });
const tree = `enrtree://${'A'.repeat(52)}@operator.example`;

test('default probe retains public discovery and manual allowlisting accepts only public Sepolia-compatible addresses', () => {
  const defaults = parseBroadcasterProbeConfig({ schemaVersion: 1 });
  assert.equal(defaults.chainId, CHAIN_ID); assert.equal(defaults.feeToken, CONTRACTS.weth);
  assert.deepEqual(defaults.sdkOptions, {}); assert.equal(defaults.broadcasterAllowlist, undefined);
  const selected = parseBroadcasterProbeConfig({ schemaVersion: 1, broadcasterAllowlist: [publicAddress],
    useDNSDiscovery: true, useCustomDNS: { onlyCustom: true, enrTreePeers: [tree] }, peerDiscoveryTimeout: 10_000 });
  assert.deepEqual(selected.broadcasterAllowlist, [publicAddress]);
  assert.deepEqual(selected.sdkOptions, { peerDiscoveryTimeout: 10_000, useDNSDiscovery: true,
    useCustomDNS: { onlyCustom: true, enrTreePeers: [tree] } });
  assert.equal(selected.probeOnly, true);
});

test('configuration rejects unsupported direct peers, public-key errors, chain/token changes and validation bypasses', () => {
  const otherChain = RailgunEngine.encodeAddress({ masterPublicKey: 1n, viewingPublicKey: new Uint8Array(32).fill(1), chain: { type: 0, id: 1 } });
  for (const override of [
    { additionalDirectPeers: [] }, { chainId: 1 }, { feeToken: '0x7b79995e5f793a07bc00c21412e50ecae098e7f9' },
    { useRelayAdapt: false }, { broadcasterAllowlist: [] }, { broadcasterAllowlist: [publicAddress, publicAddress] },
    { broadcasterAllowlist: ['0zk1badchecksum'] }, { broadcasterAllowlist: [otherChain] },
    { broadcasterAllowlist: ['one two three mnemonic words'] }, { useDNSDiscovery: true },
    { useCustomDNS: { onlyCustom: true, enrTreePeers: [tree] } },
    { useDNSDiscovery: true, useCustomDNS: { onlyCustom: true, enrTreePeers: ['https://operator.example'] } },
    { useDNSDiscovery: 'true' }, { peerDiscoveryTimeout: 35_001 }, { peerDiscoveryTimeout: 999 },
    { trustedFeeSigner: publicAddress }, { poiActiveListKeys: [] }, { broadcasterVersionRange: { minVersion: '0', maxVersion: '999' } },
    { pubSubTopic: '/waku/2/rs/0/1' }, { mnemonic: 'synthetic never-use mnemonic' },
  ]) assert.throws(() => parseBroadcasterProbeConfig({ schemaVersion: 1, ...override }));
  assert.throws(() => parseBroadcasterProbeConfig({ schemaVersion: 1, additionalDirectPeers: [] }), /ignored by the pinned Node client/);
});

test('public JSON loader bounds input and never accepts wallet-shaped or malformed configuration', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'railgun-public-config-'));
  try {
    const file = join(dir, 'operator.json');
    await writeFile(file, JSON.stringify({ schemaVersion: 1, broadcasterAllowlist: [publicAddress] }));
    assert.deepEqual((await loadBroadcasterProbeConfig(file)).broadcasterAllowlist, [publicAddress]);
    await writeFile(file, '{'); await assert.rejects(loadBroadcasterProbeConfig(file), /valid JSON/);
    await writeFile(file, ' '.repeat(16 * 1024 + 1)); await assert.rejects(loadBroadcasterProbeConfig(file), /16 KiB/);
    await writeFile(file, JSON.stringify({ schemaVersion: 1, railgun: { mnemonic: 'synthetic wallet-shaped data' } }));
    await assert.rejects(loadBroadcasterProbeConfig(file), /Unsupported/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

const offer = () => ({ railgunAddress: publicAddress, tokenAddress: CONTRACTS.weth,
  tokenFee: { relayAdapt: CONTRACTS.relayAdapt, feePerUnitGas: '100', feesID: 'synthetic-fees-id', availableWallets: 1,
    expiration: Date.now() + 120_000 } });

test('compatible offer checks require the exact token/adapter, fresh positive quote and selected operator', () => {
  const config = parseBroadcasterProbeConfig({ schemaVersion: 1, broadcasterAllowlist: [publicAddress] });
  assert.equal(compatibleBroadcasterOffer(offer(), config), true);
  for (const changed of [
    { ...offer(), railgunAddress: otherAddress }, { ...offer(), tokenAddress: '0x' + '01'.repeat(20) },
    ...[{ relayAdapt: '0x' + '01'.repeat(20) }, { feePerUnitGas: '0' }, { feePerUnitGas: 1 },
      { feesID: '' }, { availableWallets: 0 }, { expiration: Date.now() + 1000 }]
      .map(override => ({ ...offer(), tokenFee: { ...offer().tokenFee, ...override } })),
  ]) assert.equal(compatibleBroadcasterOffer(changed, config), false);
});

function fakeClient(offers = []) {
  let callback, started = false;
  const calls = [];
  return { calls,
    setAddressFilters(allowlist, blocklist) { calls.push(['filters', allowlist, blocklist]); },
    async start(chain, options, onStatus) { calls.push(['start', chain, options]); callback = onStatus; started = true; callback(chain, offers.length ? 'Connected' : 'Searching'); },
    async stop() { calls.push(['stop']); started = false; callback?.({}, 'Disconnected'); },
    isStarted: () => started,
    findAllBroadcastersForChain: () => offers,
    findBroadcastersForToken: () => offers,
    getWakuCore: () => ({ libp2p: { getConnections: () => [{}, {}, {}] } }),
    getContentTopics: () => ['/railgun/v2/0-11155111-fees/json'],
  };
}

test('probe finds SDK-selected compatible offers without constructing a transaction or recording its own disconnect', async () => {
  const client = fakeClient([offer()]);
  const config = parseBroadcasterProbeConfig({ schemaVersion: 1, broadcasterAllowlist: [publicAddress] });
  const report = await probeBroadcasters(client, config, { timeoutMs: 100, sampleIntervalMs: 5 });
  assert.equal(report.ok, true); assert.equal(report.broadcast, false); assert.equal(report.offer.railgunAddress, publicAddress);
  assert.equal(report.transport.connections, 3); assert.equal(report.compatibleWethOffers, 1);
  assert.deepEqual(report.states, ['Connected']);
  assert.deepEqual(client.calls.map(([name]) => name), ['filters', 'start', 'stop']);
  assert.deepEqual(client.calls[1][1], { type: 0, id: CHAIN_ID });
});

test('bounded probe distinguishes reachable transport from absent offers and fails closed on a wrong fee token', async () => {
  const config = parseBroadcasterProbeConfig({ schemaVersion: 1 });
  for (const offers of [[], [{ ...offer(), tokenAddress: '0x' + '01'.repeat(20) }]]) {
    const client = fakeClient(offers);
    const report = await probeBroadcasters(client, config, { timeoutMs: 25, sampleIntervalMs: 5 });
    assert.equal(report.ok, false); assert.equal(report.status, 'discovery-timeout');
    assert.equal(report.transport.connections, 3); assert.equal(report.compatibleWethOffers, 0);
    assert.equal(report.states.includes('Disconnected'), false); assert.equal(report.broadcast, false);
    assert.ok(report.samples.length > 0);
  }
});

test('invalid operator config exits the actual CLI before discovery and reports the unsupported direct-peer option', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'railgun-config-cli-'));
  try {
    const file = join(dir, 'operator.json');
    await writeFile(file, JSON.stringify({ schemaVersion: 1, additionalDirectPeers: ['/synthetic-never-dialed'] }));
    const { stdout } = await promisify(execFile)(process.execPath,
      [fileURLToPath(new URL('../broadcaster-probe.mjs', import.meta.url))],
      { env: { ...process.env, RAILGUN_BROADCASTER_CONFIG: file }, timeout: 5000 });
    const report = JSON.parse(stdout.trim().split('\n').at(-1));
    assert.equal(report.ok, false); assert.equal(report.status, 'configuration-error');
    assert.match(report.blocker, /ignored by the pinned Node client/);
    assert.equal(report.broadcast, false); assert.equal(report.transport, undefined);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('client startup errors are bounded and never expose upstream request details', async () => {
  const client = fakeClient();
  client.start = async () => { throw new Error('https://secret-credential.example/failure'); };
  const report = await probeBroadcasters(client, parseBroadcasterProbeConfig({ schemaVersion: 1 }), { timeoutMs: 25, sampleIntervalMs: 5 });
  assert.equal(report.status, 'client-error'); assert.equal(report.ok, false);
  assert.equal(JSON.stringify(report).includes('secret-credential'), false);
  assert.equal(report.broadcast, false);
});
