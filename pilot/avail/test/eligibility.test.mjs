import assert from 'node:assert/strict';
import { access, mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { publisherEligibility, requirePublisherEligibility, TURING } from '../lib.mjs';
import { assertPublicationBudget, publishAuthorized, PUBLICATION_POLICY } from '../publish.mjs';

const blockHash = `0x${'42'.repeat(32)}`;
const codeHash = '0xa8c685d1049161bb6ccc61a0b85d0a9e2091b814f8d89c27b34dc62b68c103fc';
const codec = value => ({ toString: () => String(value), toHex: () => value });

function eligibilityApi({ whitelisted = false, storageMissing = false, invalidOption = false, queryFails = false,
  runtimeCodeHash = codeHash } = {}) {
  const calls = [];
  const sideEffects = { accountReads: 0, signed: 0, broadcasts: 0 };
  const api = {
    genesisHash: codec(TURING.genesisHash),
    // The finalized runtime must win over this deliberately stale live value.
    runtimeVersion: { specVersion: codec(56) },
    rpc: { chain: {
      async getFinalizedHead() { calls.push(['finalized']); return codec(blockHash); },
      async getHeader(hash) { calls.push(['header', hash]); return { number: codec(4023694) }; },
    }, state: {
      async getRuntimeVersion(hash) { calls.push(['runtime', hash]); return { specVersion: codec(57), transactionVersion: codec(1) }; },
      async getStorageHash(key, hash) { calls.push(['code', key, hash]); return codec(runtimeCodeHash); },
    }, author: { async submitExtrinsic() { sideEffects.broadcasts++; throw new Error('must not broadcast'); } } },
    query: { system: { async account() {
      sideEffects.accountReads++;
      return { nonce: codec(0), data: { free: codec('1000000000000000000'), frozen: codec(0) } };
    } } },
    tx: { dataAvailability: { submitData() { return { sign() { sideEffects.signed++; } }; } } },
    async at(hash) {
      calls.push(['snapshot', hash]);
      return { query: { dataAvailability: storageMissing ? {} : { async submitDataWhitelist(address) {
        calls.push(['whitelist', address, hash]);
        if (queryFails) throw new Error('https://private-credential.example/rpc');
        return invalidOption ? { isSome: true, isNone: true } : { isSome: whitelisted, isNone: !whitelisted };
      } } } };
    },
  };
  return { api, calls, sideEffects };
}

test('publisher eligibility binds whitelist, runtime and code hash to one finalized snapshot', async () => {
  const { api, calls } = eligibilityApi({ whitelisted: true });
  const report = await publisherEligibility(api, PUBLICATION_POLICY.publisher);
  assert.equal(report.eligibilityKnown, true); assert.equal(report.submitDataWhitelisted, true);
  assert.equal(report.whitelistPrerequisiteSatisfied, true);
  assert.equal(report.finalizedBlock, 4023694); assert.equal(report.finalizedBlockHash, blockHash);
  assert.equal(report.runtimeSpecVersion, '57'); assert.equal(report.runtimeCodeStorageHash, codeHash);
  assert.equal(report.readOnly, true); assert.equal(report.broadcast, false);
  assert.equal(report.feeAccounting.status, 'cutover-accounting-unverified');
  assert.equal(report.feeAccounting.publicationSupported, false);
  assert.deepEqual(calls.filter(([name]) => ['header', 'runtime', 'snapshot'].includes(name))
    .map(([, hash]) => hash), [blockHash, blockHash, blockHash]);
  assert.deepEqual(calls.find(([name]) => name === 'code'), ['code', ':code', blockHash]);
  assert.deepEqual(calls.find(([name]) => name === 'whitelist'), ['whitelist', PUBLICATION_POLICY.publisher, blockHash]);
  assert.equal((await requirePublisherEligibility(api, PUBLICATION_POLICY.publisher)).submitDataWhitelisted, true);
  // Whitelist admission alone does not remove the existing conservative budget checks.
  assert.doesNotThrow(() => assertPublicationBudget('200', '1000', '0', '1'));
  assert.throws(() => assertPublicationBudget('200', '249', '0', '1'), /lacks AVAIL/);
});

for (const options of [{}, { storageMissing: true }, { invalidOption: true }, { queryFails: true }, { whitelisted: true }]) {
  const description = options.whitelisted ? 'whitelisted publisher with unverified cutover accounting'
    : Object.keys(options)[0] ?? 'funded unwhitelisted publisher';
  test(`${description} cannot read a wallet, create an intent, sign or broadcast`, async () => {
    const directory = await mkdtemp(join(tmpdir(), 'avail-eligibility-'));
    const { api, sideEffects } = eligibilityApi(options);
    try {
      await assert.rejects(publishAuthorized(api, directory, join(directory, 'missing-public-bid.json'), join(directory, 'raw.bin')),
        options.whitelisted ? /fee\/accounting policy is unverified.*cutover-accounting-unverified/
          : Object.keys(options).length ? /eligibility is unknown/ : /not in the finalized submitData whitelist/);
      assert.deepEqual(sideEffects, { accountReads: 0, signed: 0, broadcasts: 0 });
      // There is deliberately no wallet or payload fixture: reaching either file
      // would fail differently and violate the public eligibility-first gate.
      assert.deepEqual(await readdir(directory), []);
      await assert.rejects(access(join(directory, 'publication-intent.json')), { code: 'ENOENT' });
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
}

test('unknown runtime code cannot inherit the observed cutover accounting policy', async () => {
  const { api } = eligibilityApi({ whitelisted: true, runtimeCodeHash: `0x${'99'.repeat(32)}` });
  const report = await publisherEligibility(api, PUBLICATION_POLICY.publisher);
  assert.equal(report.eligibilityKnown, true); assert.equal(report.feeAccounting.status, 'unknown-runtime-accounting');
  assert.equal(report.feeAccounting.publicationSupported, false);
});

test('unknown eligibility reports contain no upstream credentials and wrong chains are rejected', async () => {
  const { api } = eligibilityApi({ queryFails: true });
  const report = await publisherEligibility(api, PUBLICATION_POLICY.publisher);
  assert.equal(report.eligibilityKnown, false); assert.equal(report.submitDataWhitelisted, null);
  assert.equal(JSON.stringify(report).includes('private-credential'), false);
  api.genesisHash = codec(`0x${'00'.repeat(32)}`);
  await assert.rejects(publisherEligibility(api, PUBLICATION_POLICY.publisher), /requires Avail Turing/);
});
