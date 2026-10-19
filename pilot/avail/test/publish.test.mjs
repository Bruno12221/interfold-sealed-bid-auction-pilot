import assert from 'node:assert/strict';
import { lstat, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { assertPublicationBudget, authorizedCiphertext, executeOneShot, withPublicationLock } from '../publish.mjs';

test('publication budget requires a funded account and 25% fee reserve below 0.3 AVAIL', () => {
  const budget = assertPublicationBudget('216265696776155513', '1000000000000000000', '0', '1000000000000');
  assert.equal(budget.onChainMaxFee, false);
  assert.equal(budget.quoteWithReservePlanck, '270332120970194392');
  assert.throws(() => assertPublicationBudget('241000000000000000', '1000000000000000000', '0', '1'), /exceeds the local/);
  assert.throws(() => assertPublicationBudget('200', '249', '0', '1'), /lacks AVAIL/);
  assert.throws(() => assertPublicationBudget('200', '1000', '800', '1'), /lacks AVAIL/);
  assert.throws(() => assertPublicationBudget('0', '1000', '0', '1'), /Invalid fee/);
});

test('signed intent is synced before exactly one submission; an existing intent blocks all retries', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'auction-avail-intent-'));
  const calls = [];
  const hash = `0x${'12'.repeat(32)}`;
  try {
    const result = await executeOneShot(directory, {
      async prepare() { calls.push('prepare'); return { signedExtrinsic: '0x1234', extrinsicHash: hash }; },
      async submit(encoded) {
        calls.push('submit');
        const saved = JSON.parse(await readFile(join(directory, 'publication-intent.json'), 'utf8'));
        assert.equal(saved.stage, 'signed-before-broadcast');
        assert.equal(saved.signedExtrinsic, encoded);
        assert.equal(saved.extrinsicHash, hash);
        assert.equal((await lstat(join(directory, 'publication-intent.json'))).mode & 0o777, 0o600);
        return hash;
      },
      async observe(intent) { calls.push('observe'); assert.equal(intent.stage, 'submitted'); return { finalized: true }; },
    });
    assert.deepEqual(calls, ['prepare', 'submit', 'observe']);
    assert.equal(result.finalized, true);
    assert.equal(JSON.parse(await readFile(join(directory, 'publication-intent.json'), 'utf8')).stage, 'finalized');
    await assert.rejects(executeOneShot(directory, {
      async prepare() { throw new Error('must not prepare another signature'); },
    }), /intent already exists/);
    assert.deepEqual(calls, ['prepare', 'submit', 'observe']);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('ambiguous submission keeps the signed transaction and never retries or claims success', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'auction-avail-intent-'));
  let submissions = 0, observations = 0;
  const handlers = {
    async prepare() { return { signedExtrinsic: '0xabcd', extrinsicHash: `0x${'34'.repeat(32)}` }; },
    async submit() { submissions++; throw new Error('network disconnected after acceptance'); },
    async observe() { observations++; return { finalized: true }; },
  };
  try {
    await assert.rejects(executeOneShot(directory, handlers), /submission is ambiguous/);
    const saved = JSON.parse(await readFile(join(directory, 'publication-intent.json'), 'utf8'));
    assert.equal(saved.stage, 'submission-unknown');
    assert.equal(saved.signedExtrinsic, '0xabcd');
    await assert.rejects(executeOneShot(directory, handlers), /intent already exists/);
    assert.equal(submissions, 1);
    assert.equal(observations, 0);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('exclusive publication lock rejects simultaneous execution', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'auction-avail-lock-'));
  let release, entered;
  const held = new Promise(resolve => { release = resolve; });
  const ready = new Promise(resolve => { entered = resolve; });
  try {
    const first = withPublicationLock(directory, async () => { entered(); await held; return 1; });
    await ready;
    await assert.rejects(withPublicationLock(directory, async () => 2), /exclusive publication lock exists/);
    release();
    assert.equal(await first, 1);
    assert.equal(await withPublicationLock(directory, async () => 3), 3);
  } finally { release(); await rm(directory, { recursive: true, force: true }); }
});

test('a mismatched RPC transaction hash is ambiguous and blocks rebroadcast', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'auction-avail-intent-'));
  let attempts = 0;
  const handlers = {
    async prepare() { return { signedExtrinsic: '0xabcd', extrinsicHash: `0x${'34'.repeat(32)}` }; },
    async submit() { attempts++; return `0x${'56'.repeat(32)}`; },
    async observe() { throw new Error('must not observe a different hash'); },
  };
  try {
    await assert.rejects(executeOneShot(directory, handlers), /different transaction hash/);
    assert.equal(JSON.parse(await readFile(join(directory, 'publication-intent.json'), 'utf8')).stage, 'submission-unknown');
    await assert.rejects(executeOneShot(directory, handlers), /intent already exists/);
    assert.equal(attempts, 1);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('publication authorization rejects any other ciphertext or slot', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'auction-avail-payload-'));
  try {
    const source = join(directory, 'public-bid.json');
    await writeFile(source, JSON.stringify({ ciphertext: '0x010203', ciphertextHash: `0x${'12'.repeat(32)}`, slot: 1 }));
    await assert.rejects(authorizedCiphertext(source, join(directory, 'raw.bin')), /one exact synthetic/);
    await assert.rejects(readFile(join(directory, 'raw.bin')), { code: 'ENOENT' });
  } finally { await rm(directory, { recursive: true, force: true }); }
});
