import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, readFile, writeFile, rm, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { once } from 'node:events';
import { processStartIdentity, readProofStatus, reconcileProofStatus } from '../scripts/openvm-proof-status.mjs';
import { proveApplication } from '../scripts/openvm-application-proof.mjs';

test('unsafe segment bounds reject before any artifact read or prover launch', async () => {
  for (const segmentMaxMemoryBytes of [0, -1, 268435455, 2147483649, 1073741824.5, NaN]) {
    await assert.rejects(proveApplication({ segmentMaxMemoryBytes }), /segment memory/);
  }
});

async function eventually(check) {
  for (let i = 0; i < 200; ++i) {
    try { if (await check()) return; } catch (error) { if (error.code !== 'ENOENT') throw error; }
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw new Error('Timed out waiting for harmless child process');
}

test('reconciliation distinguishes a reused supervisor PID and an orphaned child', () => {
  const record = { pid: 10, status: 'running', currentPhase: 'prove', phases: { prove: { pid: 20 } } };
  const probe = (pid) => ({ pid, state: pid === 10 ? 'reused' : 'alive', identityVerified: false });
  assert.equal(reconcileProofStatus(record, probe).observedStatus, 'orphaned-child-alive');
  assert.equal(record.status, 'running');
  assert.equal(reconcileProofStatus(record, pid => ({ pid, state: 'dead' })).observedStatus, 'stopped-without-final-status');
  assert.equal(reconcileProofStatus(record, pid => ({ pid, state: 'alive', identityVerified: false })).observedStatus,
    'supervisor-alive-identity-unverified');
});

test('read-only status detects live orphan and stopped job without writing or signalling', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'openvm-proof-status-'));
  const ended = spawn(process.execPath, ['-e', ''], { stdio: 'ignore' });
  await once(ended, 'exit');
  const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
  const exited = once(child, 'exit');
  try {
    const report = { schemaVersion: 1, pid: ended.pid, status: 'running', currentPhase: 'prove',
      phases: { prove: { pid: child.pid, startIdentity: processStartIdentity(child.pid) } } };
    const original = JSON.stringify(report);
    const path = join(dir, 'status.json'); await writeFile(path, original);
    const live = await readProofStatus(dir);
    assert.equal(live.observedStatus, 'orphaned-child-alive');
    assert.equal(live.child.state, 'alive');
    assert.equal(child.exitCode, null);
    assert.equal(await readFile(path, 'utf8'), original);
    child.kill('SIGTERM'); await exited;
    assert.equal((await readProofStatus(path)).observedStatus, 'stopped-without-final-status');
    assert.equal(await readFile(path, 'utf8'), original);
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await rm(dir, { recursive: true, force: true });
  }
});

for (const signal of ['SIGTERM', 'SIGINT']) {
  test(`${signal} saves interruption, forwards signal to its child, and never starts verification`, async () => {
    const dir = await mkdtemp(join(tmpdir(), 'openvm-proof-interrupt-'));
    const keys = join(dir, 'keys'); await mkdir(keys);
    for (const name of ['app.pk', 'app.vk']) await writeFile(join(keys, name), 'harmless test key');
    for (const name of ['manifest', 'exe', 'input']) await writeFile(join(dir, name), 'harmless public test input');
    await writeFile(join(dir, 'journal'), Buffer.alloc(288));
    const tool = join(dir, 'fake-tool.mjs'), helper = join(dir, 'fake-helper.mjs');
    // The fake prover exits successfully after receiving the forwarded signal.
    // The supervisor must still mark interruption and refuse the next phase.
    await writeFile(tool, `#!/usr/bin/env node
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
const output = dirname(process.argv[process.argv.indexOf('--proof') + 1]);
writeFileSync(join(output, 'segment-memory-argument'), process.argv[process.argv.indexOf('--segment-max-memory') + 1]);
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => {
  writeFileSync(join(output, 'received-signal'), signal); process.exit(0);
});
writeFileSync(join(output, 'child-started'), String(process.pid));
setInterval(() => {}, 1000);
`, { mode: 0o700 });
    await writeFile(helper, `#!/usr/bin/env node
import { writeFileSync } from 'node:fs';
if (process.argv[2] === 'identity') console.log(JSON.stringify({ applicationExecutableCommitment: '0x' + '01'.repeat(32) }));
else { writeFileSync(${JSON.stringify(join(dir, 'verification-started'))}, 'unexpected'); process.exit(1); }
`, { mode: 0o700 });
    const output = join(dir, 'run');
    const supervisor = spawn(process.execPath, [resolve('scripts/openvm-application-proof.mjs'),
      join(dir, 'manifest'), join(dir, 'exe'), keys, join(dir, 'input'), join(dir, 'journal'), output],
    { stdio: 'ignore', env: { ...process.env, CARGO_OPENVM_BIN: tool, OPENVM_TOOLS_BIN: helper,
      OPENVM_SEGMENT_MAX_MEMORY_BYTES: '1073741824' } });
    const exited = once(supervisor, 'exit');
    let childPid, childIdentity;
    try {
      await eventually(async () => {
        childPid = Number(await readFile(join(output, 'child-started'), 'utf8'));
        childIdentity = processStartIdentity(childPid);
        return childPid > 0;
      });
      supervisor.kill(signal);
      const [code, exitSignal] = await exited;
      assert.equal(code, signal === 'SIGINT' ? 130 : 143);
      assert.equal(exitSignal, null);
      const report = JSON.parse(await readFile(join(output, 'status.json'), 'utf8'));
      assert.equal(report.status, 'interrupted');
      assert.equal(report.segmentMaxMemoryBytes, 1073741824);
      assert.equal(await readFile(join(output, 'segment-memory-argument'), 'utf8'), '1073741824');
      assert.equal(report.interruption.signal, signal);
      assert.equal(report.phases.prove.status, 'interrupted');
      assert.equal(report.phases.prove.requestedSignal, signal);
      assert.equal(report.phases.prove.exitCode, 0);
      assert.equal(report.applicationProofVerified, false);
      assert.equal(await readFile(join(output, 'received-signal'), 'utf8'), signal);
      await assert.rejects(access(join(dir, 'verification-started')), { code: 'ENOENT' });
      assert.equal((await readProofStatus(output)).observedStatus, 'interrupted');
    } finally {
      if (supervisor.exitCode === null && supervisor.signalCode === null) supervisor.kill('SIGKILL');
      if (childPid && childIdentity && processStartIdentity(childPid) === childIdentity) {
        try { process.kill(childPid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
      }
      await rm(dir, { recursive: true, force: true });
    }
  });
}
