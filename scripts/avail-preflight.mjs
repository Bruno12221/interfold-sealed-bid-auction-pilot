import { writeFile, mkdir } from 'node:fs/promises';
import { AbiCoder, Contract, Interface, keccak256, toBeHex } from 'ethers';
import { sepoliaProvider } from './config.mjs';

// Interfold v0.19.0 deployed CRISP manifest; read-only candidate reuse, not a release approval.
const addresses = { verifier: '0x6D373da705B443EF76e37cb96275623818c50657',
  bridge: '0x967F7DdC4ec508462231849AE81eeaa68Ad01389', vectorx: '0xe542dB219a7e2b29C7AEaEAce242c9a2Cd528F96',
  crisp: '0xA9894A39061EC33f8550a2B63A66Be59fb9fa443' };
const iface = new Interface(['function bridge() view returns(address)', 'function vectorx() view returns(address)',
  'function verifyDataAvailability(bytes32,bytes) view returns((bytes32 contentHash,uint32 blockNumber,uint128 leafIndex))']);
const finalize = new Interface(['function finalizeInput(uint256,address,bytes32,bytes32,uint40,bytes)']);
const tuple = '(bytes32[] dataRootProof,bytes32[] leafProof,bytes32 rangeHash,uint256 dataRootIndex,bytes32 blobRoot,bytes32 bridgeRoot,bytes32 leaf,uint256 leafIndex)';
const args = process.argv.slice(2);
const txHash = args.find(arg => !arg.startsWith('--'));
if (args.some(arg => arg !== txHash && arg !== '--retrieve') || (txHash && !/^0x[0-9a-fA-F]{64}$/.test(txHash))
    || (args.includes('--retrieve') && !txHash)) throw new Error('Usage: pilot:avail -- [CRISP_FINALIZE_INPUT_TXHASH] [--retrieve]');

async function retrieveVerifiedPayload(reference) {
  const endpoint = process.env.AVAIL_RPC_URL || 'https://turing-rpc.avail.so/rpc';
  const url = new URL(endpoint);
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Avail RPC must use HTTP or HTTPS');
  const request = async (method, params) => {
    const response = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }), signal: AbortSignal.timeout(30_000) });
    if (!response.ok) throw new Error(`Avail RPC returned HTTP ${response.status}`);
    const body = await response.json();
    if (body.error || body.result == null) throw new Error(`Avail RPC ${method} failed`);
    return body.result;
  };
  const blockNumber = Number(reference.blockNumber);
  const blockHash = await request('chain_getBlockHash', [blockNumber]);
  const result = await request('chain_getBlock', [blockHash]);
  if (Number(BigInt(result.block?.header?.number)) !== blockNumber || !Array.isArray(result.block.extrinsics)) throw new Error('Avail RPC returned the wrong block');
  for (const [extrinsicIndex, raw] of result.block.extrinsics.entries()) {
    if (typeof raw !== 'string' || !/^0x(?:[0-9a-fA-F]{2})+$/.test(raw)) throw new Error('Invalid Avail extrinsic encoding');
    const bytes = Buffer.from(raw.slice(2), 'hex');
    // submit_data's Vec<u8> is the call's final SCALE item. Find bounded compact
    // lengths that consume the exact suffix, then authenticate the candidate bytes
    // against the hash already verified by the Ethereum bridge. This retrieval
    // needs no assumption about a particular signed-extension prefix or pallet ID.
    for (let offset = 0; offset < bytes.length; offset++) {
      const mode = bytes[offset] & 3;
      let width, length;
      if (mode === 0) { width = 1; length = bytes[offset] >> 2; }
      else if (mode === 1 && offset + 1 < bytes.length) { width = 2; length = bytes.readUInt16LE(offset) >> 2; }
      else if (mode === 2 && offset + 3 < bytes.length) { width = 4; length = bytes.readUInt32LE(offset) >>> 2; }
      else continue; // Four-byte SCALE covers the upstream one-MiB object bound.
      if (length < 1 || length > 1_048_576 || offset + width + length !== bytes.length) continue;
      const payload = bytes.subarray(offset + width);
      if (keccak256(payload) !== reference.contentHash) continue;
      if (await request('chain_getBlockHash', [blockNumber]) !== blockHash) throw new Error('Avail block changed during retrieval');
      await mkdir('.pilot', { recursive: true, mode: 0o700 });
      await writeFile('.pilot/avail-known-payload.bin', payload);
      return { payloadBytes: payload.length, contentHashVerified: true, availabilityBlock: blockNumber,
        availabilityBlockHash: blockHash, extrinsicIndex, rpcOrigin: url.origin,
        artifact: '.pilot/avail-known-payload.bin' };
    }
  }
  throw new Error('The verified Avail block did not yield bytes with the receipt content hash');
}

const provider = await sepoliaProvider();
try {
  const verifier = new Contract(addresses.verifier, iface, provider);
  const bridge = new Contract(addresses.bridge, ['function vectorx() view returns(address)'], provider);
  const hashes = {};
  for (const [name, address] of Object.entries(addresses)) {
    const code = await provider.getCode(address);
    if (code === '0x') throw new Error(`No deployed ${name}`);
    hashes[name] = keccak256(code);
  }
  if ((await verifier.bridge()).toLowerCase() !== addresses.bridge.toLowerCase()
      || (await verifier.vectorx()).toLowerCase() !== addresses.vectorx.toLowerCase()
      || (await bridge.vectorx()).toLowerCase() !== addresses.vectorx.toLowerCase()) throw new Error('Avail bridge/VectorX wiring differs from manifest');
  let zeroRejected = false;
  try { await verifier.verifyDataAvailability(toBeHex(0, 32), '0x'); }
  catch (error) { if (error.code === 'CALL_EXCEPTION') zeroRejected = true; else throw error; }
  if (!zeroRejected) throw new Error('Verifier accepted zero padding as published data');
  const report = { checkedAt: new Date().toISOString(), blockNumber: await provider.getBlockNumber(), readOnly: true,
    addresses, runtimeCodeHashes: hashes, wiringVerified: true, zeroContentHashRejected: true, knownAnswerVerified: false,
    caveat: 'Candidate existing verifier; bridge wiring alone does not establish an available ciphertext or validate an inclusion proof.' };
  if (txHash) {
    const [tx, receipt] = await Promise.all([provider.getTransaction(txHash), provider.getTransactionReceipt(txHash)]);
    if (!tx || !tx.blockHash || tx.to?.toLowerCase() !== addresses.crisp.toLowerCase()
        || (receipt && receipt.status !== 1)) throw new Error('Expected a mined CRISP finalizeInput transaction with no known failed receipt');
    // Some public RPCs retain transaction bodies but prune old receipts. The historical
    // execution status is not needed to establish the proof's validity today: verify
    // canonical inclusion, then independently call the deployed verifier below. Do not
    // mistake a missing historical receipt for either success or a failed DA proof.
    const block = await provider.getBlock(tx.blockNumber);
    if (!block || block.hash !== tx.blockHash || !block.transactions.includes(tx.hash)) throw new Error('Known-answer transaction is not in the canonical block');
    const parsed = finalize.parseTransaction(tx);
    const contentHash = parsed.args[3], proof = parsed.args[5];
    const result = await verifier.verifyDataAvailability(contentHash, proof);
    if (result.contentHash !== contentHash || result.blockNumber === 0n) throw new Error('Invalid real inclusion receipt');
    const abi = AbiCoder.defaultAbiCoder();
    const [p] = abi.decode([tuple], proof);
    const bad = { dataRootProof: [...p.dataRootProof], leafProof: [...p.leafProof], rangeHash: p.rangeHash,
      dataRootIndex: p.dataRootIndex, blobRoot: p.blobRoot, bridgeRoot: p.bridgeRoot, leaf: p.leaf, leafIndex: p.leafIndex };
    if (bad.leafProof.length) bad.leafProof[0] = toBeHex(BigInt(bad.leafProof[0]) ^ 1n, 32);
    else if (bad.dataRootProof.length) bad.dataRootProof[0] = toBeHex(BigInt(bad.dataRootProof[0]) ^ 1n, 32);
    else bad.blobRoot = toBeHex(BigInt(bad.blobRoot) ^ 1n, 32);
    const tampered = abi.encode([tuple], [bad]);
    let rejected = false;
    try { await verifier.verifyDataAvailability(contentHash, tampered); }
    catch (error) { if (error.code === 'CALL_EXCEPTION') rejected = true; else throw error; }
    if (!rejected) throw new Error('Verifier accepted tampered inclusion proof');
    let wrongContentHashRejected = false;
    try { await verifier.verifyDataAvailability(toBeHex(BigInt(contentHash) ^ 1n, 32), proof); }
    catch (error) { if (error.code === 'CALL_EXCEPTION') wrongContentHashRejected = true; else throw error; }
    if (!wrongContentHashRejected) throw new Error('Verifier accepted an inclusion proof for a different content hash');
    const canonicalBlock = await provider.getBlock(tx.blockNumber);
    if (canonicalBlock?.hash !== block.hash) throw new Error('Known-answer transaction block changed during validation');
    report.knownAnswerVerified = true;
    report.knownAnswer = { transactionHash: txHash, contentHash, availabilityBlock: String(result.blockNumber),
      leafIndex: String(result.leafIndex), proofBytes: (proof.length - 2) / 2,
      canonicalTransactionBlock: block.number, canonicalTransactionBlockHash: block.hash,
      historicalReceiptStatus: receipt ? 'success' : 'unavailable-pruned',
      currentVerifierCallSucceeded: true, tamperedProofRejected: true, wrongContentHashRejected: true };
    report.caveat = 'Replayed a real canonical CRISP transaction proof against the current deployed verifier. This verifies that existing data-availability receipt; it does not publish or prove availability of new auction ciphertexts.';
    if (args.includes('--retrieve')) {
      const retrieval = await retrieveVerifiedPayload(result);
      const api = new URL(process.env.AVAIL_BRIDGE_API_URL || 'https://turing-bridge-api.avail.so');
      if (!['http:', 'https:'].includes(api.protocol)) throw new Error('Avail bridge API must use HTTP or HTTPS');
      api.pathname = `${api.pathname.replace(/\/$/, '')}/v1/proof/11155111`;
      api.searchParams.set('block_hash', retrieval.availabilityBlockHash);
      api.searchParams.set('index', String(retrieval.extrinsicIndex));
      const response = await fetch(api, { signal: AbortSignal.timeout(30_000) });
      if (!response.ok) throw new Error(`Avail bridge API returned HTTP ${response.status}`);
      const fresh = await response.json();
      if (fresh.leaf !== contentHash || fresh.blockHash !== retrieval.availabilityBlockHash) throw new Error('Avail bridge API returned a different object');
      const freshProof = AbiCoder.defaultAbiCoder().encode([tuple], [fresh]);
      const freshResult = await verifier.verifyDataAvailability(contentHash, freshProof);
      if (freshResult.contentHash !== contentHash || freshResult.blockNumber !== result.blockNumber
          || freshResult.leafIndex !== result.leafIndex) throw new Error('Fresh bridge API proof returned different retrieval coordinates');
      report.knownAnswer.retrieval = { ...retrieval, bridgeApiOrigin: api.origin,
        bridgeApiProofVerified: true, bridgeApiProofMatchesHistorical: freshProof === proof };
    }
    await mkdir('.pilot', { recursive: true, mode: 0o700 });
    await writeFile('.pilot/avail-known-answer.json', JSON.stringify({ cases: [{ to: addresses.verifier, from: addresses.crisp,
      validCalldata: iface.encodeFunctionData('verifyDataAvailability', [contentHash, proof]),
      tamperedCalldata: iface.encodeFunctionData('verifyDataAvailability', [contentHash, tampered]) }] }, null, 2) + '\n');
  }
  await mkdir('.pilot', { recursive: true, mode: 0o700 });
  await writeFile('.pilot/avail-preflight.json', JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report, null, 2));
} finally { provider.destroy(); }
