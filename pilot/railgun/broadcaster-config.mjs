import { readFile, stat } from 'node:fs/promises';
import { RailgunEngine } from '@railgun-community/engine';
import { CHAIN_ID, CONTRACTS } from './config.mjs';

const fields = new Set(['schemaVersion', 'chainId', 'feeToken', 'useRelayAdapt', 'broadcasterAllowlist',
  'useDNSDiscovery', 'useCustomDNS', 'peerDiscoveryTimeout']);

export function parseBroadcasterProbeConfig(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || input.schemaVersion !== 1) throw new Error('Invalid public broadcaster probe configuration');
  if (Object.hasOwn(input, 'additionalDirectPeers')) throw new Error('additionalDirectPeers is ignored by the pinned Node client; use a verified custom DNS discovery tree instead');
  if (Object.keys(input).some(key => !fields.has(key))) throw new Error('Unsupported public broadcaster probe configuration field');
  if ((input.chainId !== undefined && input.chainId !== CHAIN_ID)
      || (input.feeToken !== undefined && (typeof input.feeToken !== 'string' || input.feeToken.toLowerCase() !== CONTRACTS.weth.toLowerCase()))
      || (input.useRelayAdapt !== undefined && input.useRelayAdapt !== true)) {
    throw new Error('Broadcaster probe is pinned to Sepolia, its exact WETH, and RelayAdapt withdrawals');
  }
  let allowlist;
  if (input.broadcasterAllowlist !== undefined) {
    if (!Array.isArray(input.broadcasterAllowlist) || !input.broadcasterAllowlist.length || input.broadcasterAllowlist.length > 8) throw new Error('Broadcaster allowlist must contain one to eight public RAILGUN addresses');
    allowlist = input.broadcasterAllowlist.map(address => {
      if (typeof address !== 'string' || address !== address.toLowerCase()) throw new Error('Broadcaster allowlist requires lowercase public RAILGUN addresses');
      let decoded;
      try { decoded = RailgunEngine.decodeAddress(address); } catch { throw new Error('Invalid public RAILGUN broadcaster address'); }
      if (decoded.chain && (decoded.chain.type !== 0 || decoded.chain.id !== CHAIN_ID)) throw new Error('Broadcaster address is restricted to a different chain');
      return address;
    });
    if (new Set(allowlist).size !== allowlist.length) throw new Error('Duplicate broadcaster allowlist address');
  }
  const options = {};
  if (input.peerDiscoveryTimeout !== undefined) {
    if (!Number.isSafeInteger(input.peerDiscoveryTimeout) || input.peerDiscoveryTimeout < 1000 || input.peerDiscoveryTimeout > 35_000) throw new Error('Peer discovery timeout must be 1000 to 35000 milliseconds');
    options.peerDiscoveryTimeout = input.peerDiscoveryTimeout;
  }
  if (input.useDNSDiscovery !== undefined && typeof input.useDNSDiscovery !== 'boolean') throw new Error('useDNSDiscovery must be a boolean');
  if (input.useDNSDiscovery === true) {
    const dns = input.useCustomDNS;
    if (!dns || typeof dns !== 'object' || Array.isArray(dns)
        || Object.keys(dns).some(key => !['onlyCustom', 'enrTreePeers'].includes(key))
        || typeof dns.onlyCustom !== 'boolean' || !Array.isArray(dns.enrTreePeers)
        || dns.enrTreePeers.length < 1 || dns.enrTreePeers.length > 8
        || dns.enrTreePeers.some(tree => typeof tree !== 'string' || !/^enrtree:\/\/[A-Z2-7]{52,64}@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(tree))
        || new Set(dns.enrTreePeers).size !== dns.enrTreePeers.length) throw new Error('Custom DNS discovery needs bounded public ENR tree URLs and an explicit onlyCustom boolean');
    options.useDNSDiscovery = true;
    options.useCustomDNS = { onlyCustom: dns.onlyCustom, enrTreePeers: [...dns.enrTreePeers] };
  } else if (input.useCustomDNS !== undefined) throw new Error('Custom DNS is ignored unless useDNSDiscovery is true');
  return { schemaVersion: 1, chainId: CHAIN_ID, feeToken: CONTRACTS.weth, useRelayAdapt: true,
    broadcasterAllowlist: allowlist, sdkOptions: options, probeOnly: true };
}

export async function loadBroadcasterProbeConfig(path) {
  if (!path) return parseBroadcasterProbeConfig({ schemaVersion: 1 });
  const info = await stat(path);
  if (!info.isFile() || info.size > 16 * 1024) throw new Error('Public broadcaster probe config must be a JSON file of at most 16 KiB');
  const bytes = await readFile(path);
  if (bytes.length > 16 * 1024) throw new Error('Public broadcaster probe config exceeds 16 KiB');
  let parsed;
  try { parsed = JSON.parse(bytes.toString('utf8')); } catch { throw new Error('Public broadcaster probe config is not valid JSON'); }
  return parseBroadcasterProbeConfig(parsed);
}

// This adds local compatibility checks to the SDK's authenticated offer filters;
// it never injects a fee, skips signature/POI validation, or constructs a spend.
export function compatibleBroadcasterOffer(offer, config, now = Date.now()) {
  try {
    return typeof offer?.railgunAddress === 'string'
      && (!config.broadcasterAllowlist || config.broadcasterAllowlist.includes(offer.railgunAddress))
      && offer.tokenAddress.toLowerCase() === CONTRACTS.weth.toLowerCase()
      && offer.tokenFee.relayAdapt.toLowerCase() === CONTRACTS.relayAdapt.toLowerCase()
      && typeof offer.tokenFee.feePerUnitGas === 'string' && /^[1-9][0-9]*$/.test(offer.tokenFee.feePerUnitGas)
      && typeof offer.tokenFee.feesID === 'string' && offer.tokenFee.feesID.length > 0 && offer.tokenFee.feesID.length <= 256
      && Number.isSafeInteger(offer.tokenFee.availableWallets) && offer.tokenFee.availableWallets > 0
      && Number.isSafeInteger(offer.tokenFee.expiration) && offer.tokenFee.expiration > now + 40_000;
  } catch { return false; }
}
