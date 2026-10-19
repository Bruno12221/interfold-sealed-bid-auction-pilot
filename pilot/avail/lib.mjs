import { createHash } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { AbiCoder, Contract, formatUnits, Interface, keccak256, toBeHex } from 'ethers';

// The SDK is CommonJS. Import all Polkadot classes through it to avoid loading
// independent ESM and CommonJS registries into the same process.
const require = createRequire(import.meta.url);
const { ApiPromise, HttpProvider, spec } = require('avail-js-sdk');
const { decodeAddress, encodeAddress } = require('@polkadot/util-crypto');

export const TURING = Object.freeze({
  genesisHash: '0xd3d2f3a3495dc597434a99d7d449ebad6616db45e4e4f178f31cc6fa14378b70',
  rpc: 'https://turing-rpc.avail.so/rpc',
  bridgeApi: 'https://turing-bridge-api.avail.so',
  maxPayloadBytes: 1_048_576,
  tokenDecimals: 18,
});
const OBSERVED_CUTOVER_CODE_HASH = '0xa8c685d1049161bb6ccc61a0b85d0a9e2091b814f8d89c27b34dc62b68c103fc';

export function publicationFeePolicy(eligibility) {
  const recognized = eligibility?.runtimeSpecVersion === '57'
    && eligibility?.runtimeCodeStorageHash === OBSERVED_CUTOVER_CODE_HASH;
  return { status: recognized ? 'cutover-accounting-unverified' : 'unknown-runtime-accounting',
    publicationSupported: false,
    reason: recognized
      ? 'Observed cutover runtime: nominal paymentInfo and TransactionFeePaid amounts may differ from the actual balance debit. Publication accounting is not verified; signing remains disabled.'
      : 'No verified publication fee/accounting policy exists for this finalized runtime; signing remains disabled.',
    caveat: 'No zero-fee bypass is inferred from a runtime version. A fee quote or nominal fee event does not establish a native-token funding requirement.' };
}
export const SEPOLIA = Object.freeze({
  chainId: 11155111n,
  verifier: '0x6D373da705B443EF76e37cb96275623818c50657',
  bridge: '0x967F7DdC4ec508462231849AE81eeaa68Ad01389',
  vectorx: '0xe542dB219a7e2b29C7AEaEAce242c9a2Cd528F96',
  runtimeHashes: {
    verifier: '0x20f8b240265bea5d95067d4192997390573ed1bd55738eda0b7c64b9e8609dbd',
    bridge: '0x78168a9262adad7fa623076295d940f37c0f84c04c1d302e43a75b132f0d5793',
    vectorx: '0x184390dbe2dec22a44d6660b99d4b33e43e4a977793a7954485fcb2cb8cd4986',
  },
});
export const VERIFIER_ABI = new Interface([
  'function bridge() view returns(address)',
  'function vectorx() view returns(address)',
  'function verifyDataAvailability(bytes32,bytes) view returns((bytes32 contentHash,uint32 blockNumber,uint128 leafIndex))',
]);
export const PROOF_TUPLE = '(bytes32[] dataRootProof,bytes32[] leafProof,bytes32 rangeHash,uint256 dataRootIndex,bytes32 blobRoot,bytes32 bridgeRoot,bytes32 leaf,uint256 leafIndex)';

export function httpUrl(value, label) {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error(`${label} must use HTTP or HTTPS`);
  return url;
}

export function uint(value, label, bits = 32) {
  if (typeof value === 'number' && !Number.isSafeInteger(value)) throw new Error(`Invalid ${label}`);
  if (!/^(0|[1-9][0-9]*)$/.test(String(value))) throw new Error(`Invalid ${label}`);
  const n = BigInt(value);
  if (n >= 1n << BigInt(bits)) throw new Error(`${label} exceeds uint${bits}`);
  return n;
}

export function hash32(value, label) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(value)) throw new Error(`Invalid ${label}`);
  return value.toLowerCase();
}

export function publisherAddress(value) {
  // Addresses and raw 32-byte public keys only. Never interpret input as a seed,
  // secret URI, or Ethereum 20-byte address.
  if (typeof value !== 'string' || value.includes('//') || value.includes(' ')
      || (value.startsWith('0x') && !/^0x[0-9a-fA-F]{64}$/.test(value))) {
    throw new Error('Publisher must be an SS58 address or a 32-byte public key');
  }
  let decoded;
  try { decoded = decodeAddress(value); } catch { throw new Error('Invalid public publisher address'); }
  if (decoded.length !== 32 || decoded.every(byte => byte === 0)) throw new Error('Publisher must be a nonzero 32-byte public key');
  return encodeAddress(decoded, 42);
}

export async function readPayload(path) {
  const info = await stat(path);
  if (!info.isFile() || info.size < 1 || info.size > TURING.maxPayloadBytes) {
    throw new Error('Ciphertext must be a nonempty binary file of at most 1 MiB');
  }
  const payload = await readFile(path);
  if (payload.length < 1 || payload.length > TURING.maxPayloadBytes || payload.length !== info.size) {
    throw new Error('Ciphertext file changed while reading or exceeds the 1 MiB cap');
  }
  return payload;
}

export function payloadIdentity(payload) {
  if (!(payload instanceof Uint8Array) || payload.length < 1 || payload.length > TURING.maxPayloadBytes) {
    throw new Error('Ciphertext payload must contain 1 to 1048576 bytes');
  }
  return { bytes: payload.length, contentHash: keccak256(payload),
    sha256: `0x${createHash('sha256').update(payload).digest('hex')}` };
}

export async function connectTuring(endpoint = TURING.rpc) {
  const url = httpUrl(endpoint, 'Avail RPC');
  const api = new ApiPromise({ provider: new HttpProvider(url.toString(), {}, 30_000),
    types: spec.types, rpc: spec.rpc, signedExtensions: spec.signedExtensions,
    noInitWarn: true, throwOnConnect: true });
  try {
    await api.isReadyOrError;
    if (api.genesisHash.toHex() !== TURING.genesisHash) throw new Error('RPC genesis differs from Avail Turing');
    if (api.registry.chainDecimals[0] !== TURING.tokenDecimals || api.registry.chainTokens[0] !== 'AVAIL') {
      throw new Error('Unexpected native token properties');
    }
    if (!api.registry.signedExtensions.includes('CheckAppId') || !api.tx.dataAvailability?.submitData) {
      throw new Error('Avail submitData or CheckAppId signed extension is unavailable');
    }
    return api;
  } catch (error) { await api.disconnect(); throw error; }
}

export async function turingStatus(api) {
  const [chain, finalizedHash, nextAppId] = await Promise.all([
    api.rpc.system.chain(), api.rpc.chain.getFinalizedHead(), api.query.dataAvailability.nextAppId(),
  ]);
  const finalized = await api.rpc.chain.getHeader(finalizedHash);
  return { network: chain.toString(), genesisHash: api.genesisHash.toHex(),
    finalizedBlock: finalized.number.toNumber(), finalizedBlockHash: finalizedHash.toHex(),
    runtimeSpecVersion: api.runtimeVersion.specVersion.toString(),
    transactionVersion: api.runtimeVersion.transactionVersion.toString(),
    nextAppId: nextAppId.toString(), nativeToken: 'AVAIL', nativeTokenDecimals: TURING.tokenDecimals,
    maxPayloadBytes: Math.min(TURING.maxPayloadBytes, api.consts.dataAvailability.maxAppDataLength.toNumber()),
    signedExtensions: [...api.registry.signedExtensions] };
}

// Every eligibility fact comes from one finalized state and its own runtime
// metadata. Presence in this whitelist is a dispatch prerequisite, independent
// of App ID allocation, native balance, or a successful paymentInfo quote.
export async function publisherEligibility(api, publisherInput) {
  const publisher = publisherAddress(publisherInput);
  if (api.genesisHash.toHex() !== TURING.genesisHash) throw new Error('Publisher eligibility requires Avail Turing');
  const report = { schemaVersion: 1, checkedAt: new Date().toISOString(), readOnly: true, broadcast: false,
    publisher, genesisHash: TURING.genesisHash, eligibilityKnown: false, submitDataWhitelisted: null,
    whitelistPrerequisiteSatisfied: false, finalizedBlock: null, finalizedBlockHash: null,
    runtimeSpecVersion: null, runtimeTransactionVersion: null, runtimeCodeStorageHash: null,
    feeAccounting: publicationFeePolicy(null),
    limitation: 'A finalized whitelist entry establishes only this dispatch prerequisite; it does not establish signing access, fee policy, or successful publication.' };
  try {
    const finalizedHash = await api.rpc.chain.getFinalizedHead();
    report.finalizedBlockHash = hash32(finalizedHash.toHex?.() ?? String(finalizedHash), 'finalized block hash');
    const [header, runtime, codeHash, snapshot] = await Promise.all([
      api.rpc.chain.getHeader(report.finalizedBlockHash),
      api.rpc.state.getRuntimeVersion(report.finalizedBlockHash),
      api.rpc.state.getStorageHash(':code', report.finalizedBlockHash),
      api.at(report.finalizedBlockHash),
    ]);
    report.finalizedBlock = Number(uint(header.number.toString(), 'finalized block', 32));
    report.runtimeSpecVersion = uint(runtime.specVersion.toString(), 'runtime spec version').toString();
    report.runtimeTransactionVersion = uint(runtime.transactionVersion.toString(), 'runtime transaction version').toString();
    report.runtimeCodeStorageHash = hash32(codeHash.toHex?.() ?? String(codeHash), 'runtime code storage hash');
    report.feeAccounting = publicationFeePolicy(report);
    const whitelist = snapshot.query.dataAvailability?.submitDataWhitelist;
    if (typeof whitelist !== 'function') {
      report.reason = 'Finalized runtime has no recognized submitDataWhitelist query; publication fails closed.';
      return report;
    }
    const entry = await whitelist(publisher);
    if (!((entry.isSome === true && entry.isNone === false) || (entry.isSome === false && entry.isNone === true))) {
      report.reason = 'Finalized whitelist response is not a recognized Option; publication fails closed.';
      return report;
    }
    report.eligibilityKnown = true;
    report.submitDataWhitelisted = entry.isSome === true;
    report.whitelistPrerequisiteSatisfied = report.submitDataWhitelisted;
    report.reason = report.submitDataWhitelisted
      ? 'Publisher is present in the finalized submitData whitelist.'
      : 'Publisher is absent from the finalized submitData whitelist; funding alone cannot enable publication.';
    return report;
  } catch {
    // RPC errors can contain endpoint credentials. The public report retains
    // successfully observed coordinates but no upstream exception or request.
    report.reason = 'Could not authenticate publisher eligibility at one finalized state; publication fails closed.';
    return report;
  }
}

export async function requirePublisherEligibility(api, publisher) {
  const report = await publisherEligibility(api, publisher);
  if (!report.eligibilityKnown) throw new Error('Turing publisher eligibility is unknown; no wallet access, signature, or broadcast is permitted');
  if (!report.submitDataWhitelisted) throw new Error('Turing publisher is not in the finalized submitData whitelist; funding alone cannot enable publication');
  return report;
}

export async function publicationPlan(api, payload, appIdInput, publisherInput) {
  const identity = payloadIdentity(payload), publisher = publisherAddress(publisherInput);
  const appId = Number(uint(appIdInput, 'appId'));
  const status = await turingStatus(api);
  if (payload.length > status.maxPayloadBytes) throw new Error('Payload exceeds the live chain maximum');
  if (appId >= Number(status.nextAppId)) throw new Error('App ID has not been allocated on Turing');
  // submitData accepts a hex byte string. Passing Uint8Array to this pinned API
  // version instead invokes SCALE decoding and can change/reject the intended data.
  const tx = api.tx.dataAvailability.submitData(`0x${Buffer.from(payload).toString('hex')}`);
  const [info, account] = await Promise.all([
    tx.paymentInfo(publisher, { appId, tip: 0 }), api.query.system.account(publisher),
  ]);
  if (tx.isSigned) throw new Error('Unsigned publication plan unexpectedly acquired a signature');
  const fee = BigInt(info.partialFee.toString());
  const free = BigInt(account.data.free.toString()), frozen = BigInt(account.data.frozen?.toString() ?? '0');
  const spendableUpperBound = free > frozen ? free - frozen : 0n;
  const eligibility = await publisherEligibility(api, publisher);
  return { schemaVersion: 1, checkedAt: new Date().toISOString(), readOnly: true, broadcast: false,
    ...status, payload: identity, publisher, appId,
    publisherEligibility: eligibility,
    appIdScope: appId === 0 ? 'Public default application ID; no dedicated application namespace' : 'Allocated application ID',
    unsignedCall: { pallet: 'dataAvailability', method: 'submitData', callHex: tx.method.toHex(),
      signedExtensionOptions: { appId, tip: '0' } },
    feeQuote: { partialFeePlanck: fee.toString(), partialFeeAvail: formatUnits(fee, TURING.tokenDecimals), denomination: 'AVAIL',
      stateContext: 'Live paymentInfo/account queries; not pinned to the separate finalized eligibility snapshot.',
      weight: info.weight.toJSON(), dispatchClass: info.class.toString(),
      publisherFreePlanck: free.toString(), publisherFrozenPlanck: frozen.toString(),
      spendableUpperBoundPlanck: spendableUpperBound.toString(),
      accountCanCoverQuotedFeeUpperBound: spendableUpperBound >= fee,
      caveat: 'paymentInfo estimate using an internally fake-signed call; no signature is exported. The cutover runtime may emit nominal fees without debiting them. This quote does not establish actual fees, publisher eligibility, or a funding requirement.' },
      remaining: ['An authorized publisher in the live finalized submitData whitelist and a verified runtime fee/accounting policy are required before signing.',
      'After finalization and VectorX bridging, retrieve an inclusion proof and verify it against the pinned Sepolia adapter.'],
  };
}

export function canonicalBridgeProof(response, expectedHash, expectedBlockHash) {
  if (!response || typeof response !== 'object') throw new Error('Invalid bridge proof response');
  if (hash32(response.leaf, 'proof leaf') !== hash32(expectedHash, 'expected content hash')
      || hash32(response.blockHash, 'proof block hash') !== hash32(expectedBlockHash, 'expected block hash')) {
    throw new Error('Bridge proof refers to different ciphertext bytes or a different block');
  }
  const array = (value, label) => {
    if (!Array.isArray(value) || value.length > 64) throw new Error(`Invalid ${label}`);
    return value.map(item => hash32(item, label));
  };
  const proof = {
    dataRootProof: array(response.dataRootProof, 'data root proof'),
    leafProof: array(response.leafProof, 'leaf proof'),
    rangeHash: hash32(response.rangeHash, 'range hash'),
    dataRootIndex: uint(response.dataRootIndex, 'data root index'),
    blobRoot: hash32(response.blobRoot, 'blob root'),
    bridgeRoot: hash32(response.bridgeRoot, 'bridge root'),
    leaf: expectedHash.toLowerCase(), leafIndex: uint(response.leafIndex, 'leaf index', 128),
  };
  return { proof, encoded: AbiCoder.defaultAbiCoder().encode([PROOF_TUPLE], [proof]) };
}

export async function fetchBridgeProof(base, blockHash, index, contentHash) {
  const url = httpUrl(base, 'Avail bridge API');
  url.pathname = `${url.pathname.replace(/\/$/, '')}/v1/proof/${SEPOLIA.chainId}`;
  url.search = '';
  url.searchParams.set('block_hash', hash32(blockHash, 'Avail block hash'));
  url.searchParams.set('index', String(uint(index, 'extrinsic index')));
  const response = await fetch(url, { signal: AbortSignal.timeout(30_000), headers: { accept: 'application/json' } });
  if (!response.ok) throw new Error(`Avail bridge API returned HTTP ${response.status}; publication may not yet be bridged`);
  const json = await response.json();
  return { ...canonicalBridgeProof(json, contentHash, blockHash), bridgeApiOrigin: url.origin };
}

export async function retrievePublication(api, expectedPayload, blockHashInput, indexInput) {
  const blockHash = hash32(blockHashInput, 'Avail block hash'), index = Number(uint(indexInput, 'extrinsic index'));
  const [signedBlock, finalizedHash] = await Promise.all([
    api.rpc.chain.getBlock(blockHash), api.rpc.chain.getFinalizedHead(),
  ]);
  const finalizedHeader = await api.rpc.chain.getHeader(finalizedHash);
  const blockNumber = signedBlock.block.header.number.toNumber();
  if (blockNumber < 1 || blockNumber > finalizedHeader.number.toNumber()
      || (await api.rpc.chain.getBlockHash(blockNumber)).toHex() !== blockHash) {
    throw new Error('Avail publication block is not finalized and canonical');
  }
  const tx = signedBlock.block.extrinsics[index];
  if (!tx || tx.method.section !== 'dataAvailability' || tx.method.method !== 'submitData') {
    throw new Error('Selected extrinsic is not dataAvailability.submitData');
  }
  const retrieved = Buffer.from(tx.method.args[0].toU8a(true));
  const identity = payloadIdentity(expectedPayload);
  if (!retrieved.equals(Buffer.from(expectedPayload)) || keccak256(retrieved) !== identity.contentHash) {
    throw new Error('Published payload differs from the exact supplied ciphertext bytes');
  }
  // Confirm dispatch success; mere block inclusion does not establish publication.
  const events = await api.query.system.events.at(blockHash);
  const successful = events.some(({ phase, event }) => phase.isApplyExtrinsic
    && phase.asApplyExtrinsic.toNumber() === index && event.section === 'system' && event.method === 'ExtrinsicSuccess');
  const failed = events.some(({ phase, event }) => phase.isApplyExtrinsic
    && phase.asApplyExtrinsic.toNumber() === index && event.section === 'system' && event.method === 'ExtrinsicFailed');
  if (!successful || failed) throw new Error('Cannot establish successful Avail publication dispatch');
  return { ...identity, blockNumber, blockHash, extrinsicIndex: index, transactionHash: tx.hash.toHex(),
    finalized: true, dispatchSuccessVerified: true, retrievedBytesMatch: true, payload: retrieved };
}

export async function pinnedSepoliaVerifier(provider) {
  if ((await provider.getNetwork()).chainId !== SEPOLIA.chainId) throw new Error('Expected Ethereum Sepolia');
  const codeHashes = {};
  for (const name of ['verifier', 'bridge', 'vectorx']) {
    const code = await provider.getCode(SEPOLIA[name]);
    codeHashes[name] = keccak256(code);
    if (code === '0x' || codeHashes[name] !== SEPOLIA.runtimeHashes[name]) throw new Error(`Pinned ${name} runtime changed`);
  }
  const verifier = new Contract(SEPOLIA.verifier, VERIFIER_ABI, provider);
  const bridge = new Contract(SEPOLIA.bridge, ['function vectorx() view returns(address)'], provider);
  const [actualBridge, actualVectorX, bridgeVectorX] = await Promise.all([verifier.bridge(), verifier.vectorx(), bridge.vectorx()]);
  if (actualBridge.toLowerCase() !== SEPOLIA.bridge.toLowerCase()
      || actualVectorX.toLowerCase() !== SEPOLIA.vectorx.toLowerCase()
      || bridgeVectorX.toLowerCase() !== SEPOLIA.vectorx.toLowerCase()) throw new Error('Pinned bridge wiring changed');
  return { verifier, codeHashes };
}

export async function verifyInclusion(verifier, contentHash, proof, blockNumber) {
  const receipt = await verifier.verifyDataAvailability(contentHash, proof.encoded);
  if (receipt.contentHash.toLowerCase() !== contentHash.toLowerCase()
      || receipt.blockNumber !== BigInt(blockNumber) || receipt.blockNumber === 0n
      || receipt.leafIndex !== proof.proof.leafIndex) throw new Error('Sepolia receipt coordinates differ from the retrieved publication');
  const altered = { ...proof.proof, dataRootProof: [...proof.proof.dataRootProof], leafProof: [...proof.proof.leafProof] };
  if (altered.leafProof.length) altered.leafProof[0] = toBeHex(BigInt(altered.leafProof[0]) ^ 1n, 32);
  else if (altered.dataRootProof.length) altered.dataRootProof[0] = toBeHex(BigInt(altered.dataRootProof[0]) ^ 1n, 32);
  else altered.blobRoot = toBeHex(BigInt(altered.blobRoot) ^ 1n, 32);
  const badProof = AbiCoder.defaultAbiCoder().encode([PROOF_TUPLE], [altered]);
  const mustReject = async (hash, encoded, label) => {
    try { await verifier.verifyDataAvailability(hash, encoded); }
    catch (error) { if (error.code === 'CALL_EXCEPTION') return; throw error; }
    throw new Error(`Sepolia verifier accepted ${label}`);
  };
  await mustReject(contentHash, badProof, 'a tampered proof');
  await mustReject(toBeHex(BigInt(contentHash) ^ 1n, 32), proof.encoded, 'the wrong content hash');
  return { contentHash: receipt.contentHash, blockNumber: receipt.blockNumber.toString(),
    leafIndex: receipt.leafIndex.toString(), validProofVerified: true,
    tamperedProofRejected: true, wrongContentHashRejected: true,
    validCalldata: VERIFIER_ABI.encodeFunctionData('verifyDataAvailability', [contentHash, proof.encoded]),
    tamperedCalldata: VERIFIER_ABI.encodeFunctionData('verifyDataAvailability', [contentHash, badProof]) };
}
