import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { AbiCoder, keccak256 } from 'ethers';
import { canonicalBridgeProof, hash32, payloadIdentity, PROOF_TUPLE, publicationPlan, publisherAddress,
  readPayload, retrievePublication, TURING, uint, verifyInclusion } from '../lib.mjs';

const hash = byte => `0x${byte.repeat(64)}`;
const proofResponse = () => ({ leaf: hash('1'), blockHash: hash('2'), dataRootProof: [hash('3')],
  leafProof: [hash('4')], rangeHash: hash('5'), dataRootIndex: '7', blobRoot: hash('6'),
  bridgeRoot: hash('7'), leafIndex: '340282366920938463463374607431768211455' });

test('ciphertext identity hashes exact binary bytes, including zero bytes', () => {
  const bytes = Buffer.from([0, 255, 1, 0]);
  assert.equal(payloadIdentity(bytes).contentHash, keccak256('0x00ff0100'));
  assert.notEqual(payloadIdentity(bytes).contentHash, keccak256(Buffer.from('0x00ff0100')));
  assert.throws(() => payloadIdentity(Buffer.alloc(0)), /1 to/);
  assert.throws(() => payloadIdentity(Buffer.alloc(TURING.maxPayloadBytes + 1)), /1 to/);
});

test('binary file loader rejects empty and oversized files before publication', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'auction-avail-'));
  try {
    await writeFile(join(dir, 'small'), Buffer.from([4, 0, 7]));
    await writeFile(join(dir, 'empty'), Buffer.alloc(0));
    await writeFile(join(dir, 'large'), Buffer.alloc(TURING.maxPayloadBytes + 1));
    assert.deepEqual(await readPayload(join(dir, 'small')), Buffer.from([4, 0, 7]));
    await assert.rejects(readPayload(join(dir, 'empty')), /at most 1 MiB/);
    await assert.rejects(readPayload(join(dir, 'large')), /at most 1 MiB/);
  } finally { await rm(dir, { recursive: true }); }
});

test('public publisher parsing rejects Ethereum addresses, seed URIs, and zero keys', () => {
  const address = publisherAddress(`0x${'12'.repeat(32)}`);
  assert.equal(publisherAddress(address), address);
  for (const value of [`0x${'12'.repeat(20)}`, '//Alice', 'one two three four', `0x${'00'.repeat(32)}`]) {
    assert.throws(() => publisherAddress(value));
  }
});

test('integer and hash parsing reject ambiguous values without narrowing large indices', () => {
  assert.equal(uint('4294967295', 'appId'), 4294967295n);
  for (const value of ['-1', '01', '1e3', '2.1', 9007199254740992, '4294967296']) assert.throws(() => uint(value, 'appId'));
  assert.equal(hash32(hash('A'), 'hash'), hash('a'));
  assert.throws(() => hash32('0x12', 'hash'));
});

test('bridge proof binds the exact content hash and block and preserves uint128 leaf index', () => {
  const expected = proofResponse();
  const { proof, encoded } = canonicalBridgeProof(expected, expected.leaf, expected.blockHash);
  assert.equal(proof.leafIndex, (1n << 128n) - 1n);
  assert.equal(AbiCoder.defaultAbiCoder().decode([PROOF_TUPLE], encoded)[0].leafIndex, proof.leafIndex);
  assert.throws(() => canonicalBridgeProof(expected, hash('9'), expected.blockHash), /different ciphertext/);
  assert.throws(() => canonicalBridgeProof(expected, expected.leaf, hash('9')), /different ciphertext/);
  assert.throws(() => canonicalBridgeProof({ ...expected, leafIndex: Number.MAX_SAFE_INTEGER + 1 }, expected.leaf, expected.blockHash), /Invalid leaf index/);
  assert.throws(() => canonicalBridgeProof({ ...expected, dataRootProof: Array(65).fill(hash('0')) }, expected.leaf, expected.blockHash), /Invalid data root proof/);
});

test('receipt verification requires positive exact coordinates and same-statement proof tampering rejection', async () => {
  const response = proofResponse(), proof = canonicalBridgeProof(response, response.leaf, response.blockHash);
  const calls = [];
  const verifier = { async verifyDataAvailability(contentHash, encoded) {
    calls.push({ contentHash, encoded });
    if (contentHash !== response.leaf || encoded !== proof.encoded) throw Object.assign(new Error('revert'), { code: 'CALL_EXCEPTION' });
    return { contentHash, blockNumber: 123n, leafIndex: proof.proof.leafIndex };
  } };
  const receipt = await verifyInclusion(verifier, response.leaf, proof, 123);
  assert.equal(receipt.tamperedProofRejected, true);
  assert.equal(calls.length, 3);
  assert.equal(calls[0].contentHash, calls[1].contentHash);
  assert.notEqual(calls[0].encoded, calls[1].encoded);
  await assert.rejects(verifyInclusion(verifier, response.leaf, proof, 124), /coordinates differ/);
  await assert.rejects(verifyInclusion({ async verifyDataAvailability() {
    return { contentHash: response.leaf, blockNumber: 123n, leafIndex: proof.proof.leafIndex };
  } }, response.leaf, proof, 123), /accepted a tampered proof/);
});

function mockApi({ payload = Buffer.from([7, 0, 3]), finalized = 125, canonical = hash('2'), method = 'submitData', success = true } = {}) {
  const number = n => ({ toNumber: () => n });
  return { rpc: { chain: {
    async getBlock() { return { block: { header: { number: number(123) }, extrinsics: [{ hash: { toHex: () => hash('8') },
      method: { section: 'dataAvailability', method, args: [{ toU8a: () => payload }] } }] } }; },
    async getFinalizedHead() { return hash('9'); },
    async getHeader() { return { number: number(finalized) }; },
    async getBlockHash() { return { toHex: () => canonical }; },
  } }, query: { system: { events: { async at() { return [{ phase: { isApplyExtrinsic: true, asApplyExtrinsic: number(0) },
    event: { section: 'system', method: success ? 'ExtrinsicSuccess' : 'ExtrinsicFailed' } }]; } } } } };
}

test('retrieval verifies exact payload, finalized canonical block, method, and dispatch success', async () => {
  const payload = Buffer.from([7, 0, 3]);
  const result = await retrievePublication(mockApi(), payload, hash('2'), 0);
  assert.equal(result.contentHash, keccak256(payload));
  assert.equal(result.retrievedBytesMatch, true);
  assert.equal(result.dispatchSuccessVerified, true);
  await assert.rejects(retrievePublication(mockApi(), Buffer.from([7, 0, 4]), hash('2'), 0), /exact supplied ciphertext/);
  await assert.rejects(retrievePublication(mockApi({ finalized: 122 }), payload, hash('2'), 0), /not finalized/);
  await assert.rejects(retrievePublication(mockApi({ canonical: hash('3') }), payload, hash('2'), 0), /not finalized/);
  await assert.rejects(retrievePublication(mockApi({ method: 'createApplicationKey' }), payload, hash('2'), 0), /not dataAvailability.submitData/);
  await assert.rejects(retrievePublication(mockApi({ success: false }), payload, hash('2'), 0), /successful Avail publication/);
  await assert.rejects(retrievePublication(mockApi(), payload, hash('2'), 1), /not dataAvailability.submitData/);
});

test('publication plan estimates the exact ciphertext with explicit App ID while remaining unsigned', async () => {
  const calls = [];
  const value = n => ({ toString: () => String(n), toNumber: () => n, toHex: () => hash('2') });
  const api = {
    rpc: { system: { async chain() { return 'Avail Turing Network'; } }, chain: {
      async getFinalizedHead() { return value(123); }, async getHeader() { return { number: value(123) }; },
    } }, query: {
      dataAvailability: { async nextAppId() { return value(531); } },
      system: { async account() { return { data: { free: value(10), frozen: value(2) } }; } },
    }, genesisHash: { toHex: () => TURING.genesisHash }, registry: { signedExtensions: ['CheckAppId'] },
    runtimeVersion: { specVersion: value(57), transactionVersion: value(1) },
    consts: { dataAvailability: { maxAppDataLength: value(TURING.maxPayloadBytes) } },
    tx: { dataAvailability: { submitData(payload) {
      calls.push(payload);
      return { isSigned: false, method: { toHex: () => '0x1d010c010203' },
        async paymentInfo(publisher, options) {
          calls.push({ publisher, options });
          return { partialFee: value(7), weight: { toJSON: () => ({ refTime: 1 }) }, class: value('Normal') };
        } };
    } } },
  };
  const result = await publicationPlan(api, Buffer.from([1, 2, 3]), '5', `0x${'12'.repeat(32)}`);
  assert.equal(calls[0], '0x010203');
  assert.deepEqual(calls[1].options, { appId: 5, tip: 0 });
  assert.equal(result.unsignedCall.signedExtensionOptions.appId, 5);
  assert.equal(result.feeQuote.partialFeePlanck, '7');
  assert.equal(result.broadcast, false);
  assert.equal(result.publisherEligibility.whitelistPrerequisiteSatisfied, false);
  assert.equal(result.publisherEligibility.feeAccounting.publicationSupported, false);
  assert.match(result.feeQuote.caveat, /does not establish actual fees.*funding requirement/);
  await assert.rejects(publicationPlan(api, Buffer.from([1]), '531', `0x${'12'.repeat(32)}`), /has not been allocated/);
});
