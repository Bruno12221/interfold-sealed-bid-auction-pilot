import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createHash } from 'node:crypto';
import { access, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { runReceiptStages } from '../scripts/openvm-receipt-stages.mjs';
import { processStartIdentity, readProofStatus } from '../scripts/openvm-proof-status.mjs';

async function eventually(check) {
  for (let i = 0; i < 200; i++) {
    try { if (await check()) return; } catch (error) { if (error.code !== 'ENOENT') throw error; }
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw new Error('Timed out waiting for harmless receipt-stage worker');
}

async function fixture({ mode = 'success', maxRssBytes, compression = false, sampleIntervalMs } = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'openvm-receipt-stages-'));
  const paths = Object.fromEntries(['worker', 'spec', 'config', 'journal', 'app', 'aggregate', 'root', 'run', 'events', 'seal', 'seal2']
    .map(name => [name, join(dir, name)]));
  await writeFile(paths.config, '{}'); await writeFile(paths.journal, Buffer.alloc(288));
  await writeFile(paths.app, 'harmless fake application proof');
  if (compression) await mkdir(paths.root);
  await writeFile(paths.worker, `#!/usr/bin/env node
import { appendFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
const [action, config, input, journal, output] = process.argv.slice(2);
appendFileSync(${JSON.stringify(paths.events)}, JSON.stringify({action, config, input, journal, output, threads:process.env.RAYON_NUM_THREADS})+'\\n');
if (${JSON.stringify(mode)} === 'fail' || (${JSON.stringify(mode)} === 'fail-next' && output === ${JSON.stringify(paths.seal2)})) process.exit(7);
if (${JSON.stringify(mode)} === 'wait') {
  for (const signal of ['SIGINT','SIGTERM']) process.on(signal, () => {
    writeFileSync(${JSON.stringify(join(dir, 'received-signal'))}, signal); process.exit(0);
  });
  writeFileSync(${JSON.stringify(join(dir, 'child-started'))}, String(process.pid));
  setInterval(() => {},1000);
} else if (action === 'compress-root') {
  // Test double only: this is a canonical container with dummy proof bytes,
  // never a cryptographic proof. The production worker must verify the proof.
  let seal = Buffer.alloc(1856); seal.fill(0xab,96);
  seal[31]=1; seal[63]=64; seal.writeUInt16BE(1760,94);
  if (${JSON.stringify(mode)} === 'bad-version') seal[0]=1;
  if (${JSON.stringify(mode)} === 'bad-offset') seal[63]=96;
  if (${JSON.stringify(mode)} === 'bad-length') seal.writeUInt16BE(1728,94);
  if (${JSON.stringify(mode)} === 'truncated') seal=seal.subarray(0,1855);
  if (${JSON.stringify(mode)} === 'trailing') seal=Buffer.concat([seal,Buffer.from([0])]);
  writeFileSync(output,seal,{flag:'wx',mode:0o600});
} else {
  mkdirSync(output,{mode:0o700});
  writeFileSync(join(output,'manifest.json'), JSON.stringify({schemaVersion:1,stage:action}));
}
`, { mode: 0o700 });
  const spec = { schemaVersion: 1, ...(maxRssBytes === undefined ? {} : { maxRssBytes }),
    ...(sampleIntervalMs === undefined ? {} : { sampleIntervalMs }),
    ...(compression ? { scope: 'halo2-root-compression', allowHalo2Compression: true } : {}),
    stages: compression ? [
      { name: 'compress', action: 'compress-root', config: paths.config, input: paths.root, journal: paths.journal, output: paths.seal },
      { name: 'compress_next', action: 'compress-root', config: paths.config, input: paths.root, journal: paths.journal, output: paths.seal2 },
    ] : [
      { name: 'aggregate', action: 'aggregate-stark', config: paths.config, input: paths.app, journal: paths.journal, output: paths.aggregate },
      { name: 'root', action: 'prove-root', config: paths.config, input: paths.aggregate, journal: paths.journal, output: paths.root },
    ] };
  await writeFile(paths.spec, JSON.stringify(spec));
  return { dir, ...paths, job: spec };
}

test('runs saved STARK stages sequentially and saves durations, fingerprints and resource records', async () => {
  const f = await fixture();
  try {
    const report = await runReceiptStages({ worker: f.worker, spec: f.spec, output: f.run });
    assert.equal(report.status, 'complete'); assert.equal(report.scope, 'receipt-stark-stages');
    assert.equal(report.applicationProofVerified, false); assert.equal(report.evmReceiptGenerated, false);
    assert.equal(report.maxRssBytes, 8 * 1024 ** 3); assert.equal(report.rayonThreads, 2);
    assert.equal(report.sampleIntervalMs, 2000);
    assert.equal(report.timings.completed, true);
    const events = (await readFile(f.events, 'utf8')).trim().split('\n').map(line => JSON.parse(line));
    assert.deepEqual(events.map(event => event.action), ['aggregate-stark', 'prove-root']);
    assert.deepEqual(events.map(event => event.threads), ['2', '2']);
    assert.equal(events[1].input, f.aggregate);
    assert.ok(Date.parse(report.phases.root.startedAt) >= Date.parse(report.phases.aggregate.finishedAt));
    assert.match(report.fingerprints.worker.sha256, /^[a-f0-9]{64}$/);
    assert.match(report.fingerprints.spec.sha256, /^[a-f0-9]{64}$/);
    assert.match(report.fingerprints.stages.aggregate.config.sha256, /^[a-f0-9]{64}$/);
    assert.match(report.phases.root.manifest.sha256, /^[a-f0-9]{64}$/);
    assert.equal((await stat(f.run)).mode & 0o777, 0o700);
    for (const name of ['status.json', 'resource.jsonl', 'aggregate.log', 'root.log']) {
      assert.equal((await stat(join(f.run, name))).mode & 0o777, 0o600);
    }
    const samples = (await readFile(join(f.run, 'resource.jsonl'), 'utf8')).trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
    assert.ok(samples.every(row => row.rssBytes >= 0 && row.maxRssBytes === report.maxRssBytes));
    assert.equal((await readProofStatus(f.run)).observedStatus, 'complete');
    await assert.rejects(runReceiptStages({ worker: f.worker, spec: f.spec, output: f.run }), /new output path/);
  } finally { await rm(f.dir, { recursive: true, force: true }); }
});

test('explicit compression-only opt-in saves canonical seals and attributes verification to the trusted worker', async () => {
  const f = await fixture({ compression: true });
  try {
    const report = await runReceiptStages({ worker: f.worker, spec: f.spec, output: f.run });
    assert.equal(report.status, 'complete'); assert.equal(report.scope, 'halo2-root-compression');
    assert.equal(report.sampleIntervalMs, 250); assert.equal(report.maxRssBytes, 8 * 1024 ** 3);
    assert.equal(report.applicationProofVerified, false); assert.equal(report.evmReceiptGenerated, true);
    assert.equal(report.receiptVerification.independentJavaScriptCryptographicVerification, false);
    assert.match(report.receiptVerification.source, /trusted worker/);
    for (const [name, output] of [['compress', f.seal], ['compress_next', f.seal2]]) {
      const seal = await readFile(output), metadata = report.phases[name].seal;
      assert.equal(seal.length, 1856); assert.equal(metadata.bytes, 1856);
      assert.equal(metadata.canonicalAbiEncoding, true); assert.equal(metadata.proofDataBytes, 1760);
      assert.equal(metadata.sha256, createHash('sha256').update(seal).digest('hex'));
      assert.match(metadata.cryptographicVerification, /JavaScript checks encoding only/);
      assert.equal(report.phases[name].manifest, undefined);
    }
    const events = (await readFile(f.events, 'utf8')).trim().split('\n').map(line => JSON.parse(line));
    assert.deepEqual(events.map(event => event.action), ['compress-root', 'compress-root']);
    assert.ok(Date.parse(report.phases.compress_next.startedAt) >= Date.parse(report.phases.compress.finishedAt));
  } finally { await rm(f.dir, { recursive: true, force: true }); }
});

test('compression requires both opt-in fields and rejects mixed STARK stages', async () => {
  for (const change of [
    job => { delete job.allowHalo2Compression; },
    job => { delete job.scope; },
    job => { job.allowHalo2Compression = false; },
    job => { job.allowHalo2Compression = 'true'; },
    job => { job.stages[1].action = 'prove-root'; },
    job => { job.stages[1].action = 'aggregate-stark'; },
  ]) {
    const f = await fixture({ compression: true });
    try {
      change(f.job); await writeFile(f.spec, JSON.stringify(f.job));
      await assert.rejects(runReceiptStages({ worker: f.worker, spec: f.spec, output: f.run }), /Invalid/);
      await assert.rejects(access(f.run), { code: 'ENOENT' }); await assert.rejects(access(f.events), { code: 'ENOENT' });
    } finally { await rm(f.dir, { recursive: true, force: true }); }
  }
});

test('sampling interval accepts the bounded range and rejects invalid values before starting a worker', async () => {
  for (const sampleIntervalMs of [99, 5001, 250.5, '250', 0, null]) {
    const f = await fixture({ compression: true, sampleIntervalMs });
    try {
      await assert.rejects(runReceiptStages({ worker: f.worker, spec: f.spec, output: f.run }), /Invalid receipt stage job spec/);
      await assert.rejects(access(f.run), { code: 'ENOENT' }); await assert.rejects(access(f.events), { code: 'ENOENT' });
    } finally { await rm(f.dir, { recursive: true, force: true }); }
  }
  for (const sampleIntervalMs of [100, 5000]) {
    const f = await fixture({ compression: true, sampleIntervalMs });
    try {
      const report = await runReceiptStages({ worker: f.worker, spec: f.spec, output: f.run });
      assert.equal(report.sampleIntervalMs, sampleIntervalMs);
      assert.match(report.resourceMeasurement, /not an operating-system memory limit/);
    } finally { await rm(f.dir, { recursive: true, force: true }); }
  }
});

test('a later compression failure preserves the completed seal but never marks the incomplete queue successful', async () => {
  const f = await fixture({ compression: true, mode: 'fail-next' });
  const thirdSeal = join(f.dir, 'third-seal');
  try {
    f.job.stages.push({ ...f.job.stages[1], name: 'compress_third', output: thirdSeal });
    await writeFile(f.spec, JSON.stringify(f.job));
    await assert.rejects(runReceiptStages({ worker: f.worker, spec: f.spec, output: f.run }), /compress_next failed/);
    const report = JSON.parse(await readFile(join(f.run, 'status.json'), 'utf8'));
    assert.equal(report.status, 'failed'); assert.equal(report.evmReceiptGenerated, false);
    assert.equal(report.phases.compress.status, 'complete'); assert.equal(report.phases.compress.seal.bytes, 1856);
    assert.equal(report.phases.compress_next.status, 'failed'); assert.equal(report.phases.compress_third, undefined);
    assert.equal(report.receiptVerification, null);
    assert.equal((await readFile(f.events, 'utf8')).trim().split('\n').length, 2);
    assert.equal((await stat(f.seal)).size, 1856); await assert.rejects(access(thirdSeal), { code: 'ENOENT' });
  } finally { await rm(f.dir, { recursive: true, force: true }); }
});

for (const mode of ['bad-version', 'bad-offset', 'bad-length', 'truncated', 'trailing', 'fail']) {
  test(`compression ${mode} output prevents all later work and never claims an EVM receipt`, async () => {
    const f = await fixture({ compression: true, mode });
    try {
      await assert.rejects(runReceiptStages({ worker: f.worker, spec: f.spec, output: f.run }),
        mode === 'fail' ? /compress failed/ : /canonical ABI encoding|1856-byte seal/);
      const report = JSON.parse(await readFile(join(f.run, 'status.json'), 'utf8'));
      assert.equal(report.status, 'failed'); assert.equal(report.phases.compress.status, 'failed');
      assert.equal(report.phases.compress_next, undefined); assert.equal(report.evmReceiptGenerated, false);
      assert.equal(report.receiptVerification, null);
      assert.equal((await readFile(f.events, 'utf8')).trim().split('\n').length, 1);
      await assert.rejects(access(f.seal2), { code: 'ENOENT' });
    } finally { await rm(f.dir, { recursive: true, force: true }); }
  });
}

for (const reason of ['SIGTERM', 'resource-limit']) {
  test(`compression ${reason} interruption leaves later work unstarted and its receipt flag false`, async () => {
    const f = await fixture({ compression: true, mode: 'wait', ...(reason === 'resource-limit' ? { maxRssBytes: 1 } : {}) });
    const supervisor = spawn(process.execPath, [resolve('scripts/openvm-receipt-stages.mjs'), f.worker, f.spec, f.run], { stdio: 'ignore' });
    const exited = once(supervisor, 'exit');
    let childPid, identity;
    try {
      if (reason === 'SIGTERM') {
        await eventually(async () => {
          childPid = Number(await readFile(join(f.dir, 'child-started'), 'utf8'));
          identity = processStartIdentity(childPid); return childPid > 0;
        });
        supervisor.kill('SIGTERM');
      }
      const [code, signal] = await exited;
      assert.equal(code, reason === 'resource-limit' ? 137 : 143); assert.equal(signal, null);
      const report = JSON.parse(await readFile(join(f.run, 'status.json'), 'utf8'));
      assert.equal(report.status, 'interrupted'); assert.equal(report.scope, 'halo2-root-compression');
      assert.equal(report.interruption.reason, reason === 'resource-limit' ? 'resource-limit' : 'signal');
      assert.equal(report.phases.compress.status, 'interrupted'); assert.equal(report.phases.compress_next, undefined);
      assert.equal(report.evmReceiptGenerated, false); assert.equal(report.receiptVerification, null);
      assert.equal(report.sampleIntervalMs, 250); await assert.rejects(access(f.seal2), { code: 'ENOENT' });
    } finally {
      if (supervisor.exitCode === null && supervisor.signalCode === null) supervisor.kill('SIGKILL');
      if (childPid && identity && processStartIdentity(childPid) === identity) {
        try { process.kill(childPid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
      }
      await rm(f.dir, { recursive: true, force: true });
    }
  });
}

test('a worker failure records its exit code and prevents every later stage', async () => {
  const f = await fixture({ mode: 'fail' });
  try {
    await assert.rejects(runReceiptStages({ worker: f.worker, spec: f.spec, output: f.run }), /aggregate failed/);
    const report = JSON.parse(await readFile(join(f.run, 'status.json'), 'utf8'));
    assert.equal(report.status, 'failed'); assert.equal(report.phases.aggregate.exitCode, 7);
    assert.equal(report.phases.aggregate.status, 'failed'); assert.equal(report.timings.completed, true);
    assert.equal(report.phases.root, undefined);
    const events = (await readFile(f.events, 'utf8')).trim().split('\n'); assert.equal(events.length, 1);
    await assert.rejects(access(f.root), { code: 'ENOENT' });
  } finally { await rm(f.dir, { recursive: true, force: true }); }
});

test('refuses compression actions before creating any run or starting a worker', async () => {
  const f = await fixture();
  try {
    f.job.stages[0].action = 'compress-root'; await writeFile(f.spec, JSON.stringify(f.job));
    await assert.rejects(runReceiptStages({ worker: f.worker, spec: f.spec, output: f.run }), /Invalid or duplicate receipt stage/);
    await assert.rejects(access(f.run), { code: 'ENOENT' }); await assert.rejects(access(f.events), { code: 'ENOENT' });
  } finally { await rm(f.dir, { recursive: true, force: true }); }
});

for (const reason of ['SIGTERM', 'SIGINT', 'resource-limit']) {
  test(`${reason} stops only its own child and never starts the root stage`, async () => {
    const f = await fixture({ mode: 'wait', ...(reason === 'resource-limit' ? { maxRssBytes: 1 } : {}) });
    const supervisor = spawn(process.execPath, [resolve('scripts/openvm-receipt-stages.mjs'), f.worker, f.spec, f.run], {
      stdio: 'ignore', env: { ...process.env, PATH: process.env.PATH },
    });
    const exited = once(supervisor, 'exit');
    const bystander = spawn(process.execPath, ['-e', 'setInterval(() => {},1000)'], { stdio: 'ignore' });
    const bystanderExited = once(bystander, 'exit');
    let childPid, identity;
    try {
      if (reason !== 'resource-limit') {
        await eventually(async () => {
          childPid = Number(await readFile(join(f.dir, 'child-started'), 'utf8'));
          identity = processStartIdentity(childPid); return childPid > 0;
        });
        supervisor.kill(reason);
      }
      const [code, signal] = await exited;
      assert.equal(code, reason === 'resource-limit' ? 137 : reason === 'SIGINT' ? 130 : 143);
      assert.equal(signal, null);
      const report = JSON.parse(await readFile(join(f.run, 'status.json'), 'utf8'));
      assert.equal(report.status, 'interrupted');
      assert.equal(report.interruption.reason, reason === 'resource-limit' ? 'resource-limit' : 'signal');
      assert.equal(report.interruption.signal, reason === 'SIGINT' ? 'SIGINT' : 'SIGTERM');
      assert.equal(report.phases.aggregate.status, 'interrupted');
      assert.equal(report.phases.aggregate.requestedSignal, reason === 'SIGINT' ? 'SIGINT' : 'SIGTERM');
      assert.equal(report.timings.completed, true); assert.equal(report.timings.phases.aggregate.completed, true);
      assert.equal(report.phases.root, undefined); assert.equal(report.applicationProofVerified, false);
      assert.equal(report.evmReceiptGenerated, false); assert.equal(bystander.exitCode, null);
      if (reason !== 'resource-limit') {
        assert.equal(report.phases.aggregate.exitCode, 0);
        assert.equal(await readFile(join(f.dir, 'received-signal'), 'utf8'), reason);
      } else {
        assert.ok(report.peakRssBytes > 1); assert.ok(report.interruption.rssBytes > 1);
      }
      await assert.rejects(access(f.root), { code: 'ENOENT' });
    } finally {
      if (supervisor.exitCode === null && supervisor.signalCode === null) supervisor.kill('SIGKILL');
      if (childPid && identity && processStartIdentity(childPid) === identity) {
        try { process.kill(childPid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
      }
      bystander.kill('SIGTERM'); await bystanderExited;
      await rm(f.dir, { recursive: true, force: true });
    }
  });
}
