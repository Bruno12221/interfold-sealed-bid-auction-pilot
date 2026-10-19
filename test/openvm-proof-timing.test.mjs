import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { collectTimings, timingSnapshot } from '../scripts/openvm-proof-timing.mjs';

test('recorder attaches to an existing run and persists exact final phase and total durations', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'openvm-timing-'));
  const path = join(dir, 'status.json');
  const report = { schemaVersion: 1, pid: process.pid, status: 'running', currentPhase: 'prove',
    startedAt: '2026-01-01T00:00:00.000Z', applicationProofVerified: false, evmReceiptGenerated: false,
    phases: { identity: { status: 'complete', startedAt: '2026-01-01T00:00:00.000Z', finishedAt: '2026-01-01T00:00:30.000Z' },
      prove: { status: 'running', startedAt: '2026-01-01T00:00:30.000Z' } } };
  let sampled;
  const firstSample = new Promise(resolve => { sampled = resolve; });
  try {
    const original = JSON.stringify(report);
    await writeFile(path, original);
    const collector = collectTimings([dir], { watch: true, intervalMs: 100, onSnapshot: sampled });
    await firstSample;
    assert.equal(await readFile(path, 'utf8'), original);
    assert.equal(JSON.parse(await readFile(join(dir, 'timing.json'), 'utf8')).etaSeconds, null);
    report.status = 'complete'; report.currentPhase = null;
    report.finishedAt = '2026-01-01T01:23:55.000Z'; report.applicationProofVerified = true;
    report.phases.prove.status = 'complete'; report.phases.prove.finishedAt = '2026-01-01T01:23:45.000Z';
    report.phases.verify = { status: 'complete', startedAt: '2026-01-01T01:23:45.000Z', finishedAt: report.finishedAt };
    const finalStatus = JSON.stringify(report);
    await writeFile(path, finalStatus);
    const [finished] = await collector;
    const saved = JSON.parse(await readFile(join(dir, 'timing.json'), 'utf8'));
    assert.deepEqual(saved, finished);
    assert.equal(saved.collectionFinished, true);
    assert.equal(saved.timings.elapsedSeconds, 5035);
    assert.equal(saved.timings.phases.prove.elapsedSeconds, 4995);
    assert.equal(saved.timings.phases.prove.elapsedHuman, '01:23:15');
    assert.equal(saved.timings.phases.verify.elapsedSeconds, 10);
    assert.equal(saved.applicationProofVerified, true);
    assert.equal(saved.evmReceiptGenerated, false);
    assert.equal(saved.etaSeconds, null);
    assert.equal(await readFile(path, 'utf8'), finalStatus);
    const history = (await readFile(join(dir, 'timing.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
    assert.equal(history[0].collectionFinished, false);
    assert.deepEqual(history.at(-1), saved);
    const later = await timingSnapshot(dir, { now: Date.parse('2026-01-02T00:00:00Z') });
    assert.deepEqual(later.timings, saved.timings);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('an unexpected stop records observation bounds without inventing a finish time or success', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'openvm-timing-stopped-'));
  try {
    await writeFile(join(dir, 'status.json'), JSON.stringify({ schemaVersion: 1, pid: 10,
      status: 'running', startedAt: '2026-01-01T00:00:00Z', currentPhase: 'prove',
      phases: { prove: { pid: 20, status: 'running', startedAt: '2026-01-01T00:00:01Z' } } }));
    const live = await timingSnapshot(dir, { now: Date.parse('2026-01-01T00:01:00Z'),
      probe: pid => ({ pid, state: 'alive', identityVerified: true }) });
    const stopped = await timingSnapshot(dir, { now: Date.parse('2026-01-01T00:01:30Z'), previous: live,
      probe: pid => ({ pid, state: 'dead', identityVerified: false }) });
    assert.equal(stopped.collectionFinished, true);
    assert.equal(stopped.stopTimeUnknown, true);
    assert.equal(stopped.timings.finishedAt, null);
    assert.equal(stopped.timings.elapsedSeconds, null);
    assert.equal(stopped.timings.phases.prove.elapsedSeconds, null);
    assert.equal(stopped.lastObservedChildAliveAt, live.checkedAt);
    assert.equal(stopped.stopObservedAt, '2026-01-01T00:01:30.000Z');
    assert.equal(stopped.applicationProofVerified, false);
    assert.equal(stopped.etaSeconds, null);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('completed application summaries preserve the existing verified flag with or without a saved scope', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'openvm-app-summary-'));
  try {
    for (const scope of [undefined, 'application-stark-proof-only']) {
      await writeFile(join(dir, 'status.json'), JSON.stringify({ schemaVersion: 1, scope, pid: process.pid,
        status: 'complete', currentPhase: null, applicationProofVerified: true, evmReceiptGenerated: false,
        startedAt: '2026-01-01T00:00:00Z', finishedAt: '2026-01-01T01:00:10Z',
        phases: { prove: { status: 'complete', startedAt: '2026-01-01T00:00:00Z', finishedAt: '2026-01-01T01:00:00Z' } } }));
      const messages = [];
      await collectTimings([dir], { onSnapshot: message => messages.push(message) });
      assert.deepEqual(messages, [`${basename(dir)}: complete; proving 01:00:00; total 01:00:10; verified=true`]);
    }
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('Halo2 summaries use the EVM receipt result rather than the unrelated application flag', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'openvm-halo2-summary-'));
  try {
    for (const [status, generated] of [['complete', true], ['failed', false], ['interrupted', false]]) {
      await writeFile(join(dir, 'status.json'), JSON.stringify({ schemaVersion: 1, scope: 'halo2-root-compression',
        pid: process.pid, status, currentPhase: null, applicationProofVerified: false, evmReceiptGenerated: generated,
        startedAt: '2026-01-01T00:00:00Z', finishedAt: '2026-01-01T01:00:10Z',
        phases: { compress: { status, startedAt: '2026-01-01T00:00:00Z', finishedAt: '2026-01-01T01:00:10Z' } } }));
      const messages = [];
      const [snapshot] = await collectTimings([dir], { onSnapshot: message => messages.push(message) });
      assert.equal(snapshot.scope, 'halo2-root-compression');
      assert.equal(snapshot.evmReceiptGenerated, generated);
      assert.deepEqual(messages, [`${basename(dir)}: ${status}; compress 01:00:10; total 01:00:10; evmReceiptGenerated=${generated}`]);
      assert.equal(messages[0].includes('verified='), false);
    }
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('recursive/root queue summaries describe stage completion without claiming application verification', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'openvm-root-summary-'));
  try {
    for (const status of ['complete', 'failed', 'interrupted']) {
      await writeFile(join(dir, 'status.json'), JSON.stringify({ schemaVersion: 1, scope: 'receipt-stark-stages',
        pid: process.pid, status, currentPhase: null, applicationProofVerified: false, evmReceiptGenerated: false,
        startedAt: '2026-01-01T00:00:00Z', finishedAt: '2026-01-01T01:00:10Z',
        phases: { root: { status, startedAt: '2026-01-01T00:00:00Z', finishedAt: '2026-01-01T01:00:10Z' } } }));
      const messages = [];
      await collectTimings([dir], { onSnapshot: message => messages.push(message) });
      assert.deepEqual(messages, [`${basename(dir)}: ${status}; root 01:00:10; total 01:00:10; stagesComplete=${status === 'complete'}`]);
      assert.equal(messages[0].includes('verified='), false);
    }
  } finally { await rm(dir, { recursive: true, force: true }); }
});
