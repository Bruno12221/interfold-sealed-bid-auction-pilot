import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { chmod, cp, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { packageRootHandoff, setupArtifactUrls } from '../scripts/package-root-handoff.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');

async function eventually(check) {
  for (let count = 0; count < 400; count++) {
    try { if (await check()) return; } catch (error) { if (error.code !== 'ENOENT') throw error; }
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw new Error('Timed out waiting for harmless handoff test worker');
}

function isAlive(pid) {
  try { process.kill(pid, 0); return true; } catch (error) { if (error.code === 'ESRCH') return false; throw error; }
}

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), 'root-handoff-'));
  const publicDir = join(directory, 'public');
  const root = join(publicDir, 'root');
  const worker = join(directory, 'worker');
  const setup = join(directory, 'setup');
  await mkdir(root, { recursive: true });
  const commit = { app_exe_commit: '0x' + '01'.repeat(32), app_vm_commit: '0x' + '02'.repeat(32) };
  const artifacts = { app_pk: 'public app proving key', executable: 'public executable', aggregation_pk: 'public aggregation key', verifier_artifact: 'public verifier artifact' };
  const config = { app_commit: commit, segment_memory_bytes: 2147483648, verifier_sha256: hash(artifacts.verifier_artifact), halo2_pk: join(setup, 'halo2.pk'), halo2_params_dir: join(setup, 'params') };
  for (const [name, value] of Object.entries(artifacts)) {
    config[name] = join(publicDir, name);
    await writeFile(config[name], value);
  }
  const journal = Buffer.alloc(288, 9);
  const rootBytes = Buffer.from('harmless fake root checkpoint, not a cryptographic proof');
  const manifest = {
    schema_version: 1, openvm_version: 'v2.0', openvm_revision: '59a69b8b0cbee7011ac978e4cc07707ee3681944', stage: 'prove-root',
    app_commit: commit, journal_sha256: hash(journal), journal_bytes: journal.length,
    config_artifacts: Object.fromEntries(Object.entries(artifacts).map(([name, value]) => [name, hash(value)])),
    files: { 'root.bin': hash(rootBytes) },
  };
  const job = { name: 'compute', config: join(publicDir, 'config.json'), root, journal: join(publicDir, 'journal.bin'), identity: join(publicDir, 'identity.json') };
  await writeFile(job.config, JSON.stringify(config));
  await writeFile(job.journal, journal);
  await writeFile(job.identity, JSON.stringify({ app_commit: commit }));
  await writeFile(join(root, 'manifest.json'), JSON.stringify(manifest));
  await writeFile(join(root, 'root.bin'), rootBytes);
  await writeFile(join(root, 'private-wallet.json'), 'do not copy this secret decoy');
  await writeFile(join(publicDir, 'raw-input.bin'), 'do not copy this witness decoy');
  const setupManifest = { schemaVersion: 1, openvmVersion: '2.0.2', artifacts: {} };
  for (const [name, url] of Object.entries(setupArtifactUrls())) {
    const value = name.endsWith('verifier.bytecode.json') ? artifacts.verifier_artifact : `harmless setup fixture ${name}`;
    setupManifest.artifacts[name] = { url, status: 'complete', sha256: hash(value), bytes: Buffer.byteLength(value) };
    await mkdir(dirname(join(setup, name)), { recursive: true });
    await writeFile(join(setup, name), value);
  }
  const setupDownloadManifest = join(directory, 'setup-download.json');
  await writeFile(setupDownloadManifest, JSON.stringify(setupManifest));
  const sourceNames = ['Cargo.toml', 'Cargo.lock', 'LICENSE.md', 'NOTICE.md', 'README.md', 'fetch-setup.py', 'src/main.rs'];
  for (const name of sourceNames) {
    await mkdir(dirname(join(worker, name)), { recursive: true });
    await writeFile(join(worker, name), `harmless worker source fixture ${name}`);
  }
  await writeFile(join(worker, 'wallet.private.json'), 'do not copy this private decoy');
  return { directory, setup, config, manifest, job, options: { output: join(directory, 'handoff'), jobs: [job], worker, setupDownloadManifest } };
}

test('public root handoff uses a fixed allowlist, keeps artifact bytes, and relocates absolute configs', async t => {
  const data = await fixture();
  t.after(() => rm(data.directory, { recursive: true, force: true }));
  const result = await packageRootHandoff(data.options);
  const manifest = JSON.parse(await readFile(join(result.output, 'bundle-manifest.json')));
  assert.equal(manifest.jobs.length, 1);
  assert.ok(Object.keys(manifest.files).every(name => !/private|wallet|raw-input/.test(name)));
  assert.equal(await readFile(join(result.output, 'jobs/compute/root/root.bin'), 'utf8'), 'harmless fake root checkpoint, not a cryptographic proof');
  const template = await readFile(join(result.output, 'jobs/compute/config.template.json'), 'utf8');
  assert.equal(template.includes(data.directory), false);
  assert.equal(template.includes('halo2_pk'), true);
  const moved = join(data.directory, 'different-host-path');
  await cp(result.output, moved, { recursive: true });
  let check = spawnSync('python3', [join(moved, 'configure.py'), '--bundle-only'], { encoding: 'utf8' });
  assert.equal(check.status, 0, check.stderr);
  check = spawnSync('python3', [join(moved, 'configure.py'), '--setup', data.setup], { encoding: 'utf8' });
  assert.equal(check.status, 0, check.stderr);
  const actual = JSON.parse(await readFile(join(moved, 'config/compute.json')));
  assert.equal(actual.app_pk, await realpath(join(moved, 'jobs/compute/app.pk')));
  assert.equal(actual.halo2_pk, await realpath(join(data.setup, 'halo2.pk')));
  assert.deepEqual(actual.app_commit, data.config.app_commit);
  check = spawnSync('python3', [join(moved, 'configure.py'), '--setup', data.setup], { encoding: 'utf8' });
  assert.notEqual(check.status, 0, 'existing generated configs must not be overwritten');
  await assert.rejects(packageRootHandoff(data.options), /EEXIST/);
});

test('compression runner records worker failure without claiming a verified receipt', async t => {
  const data = await fixture();
  t.after(() => rm(data.directory, { recursive: true, force: true }));
  const result = await packageRootHandoff(data.options);
  let check = spawnSync('python3', [join(result.output, 'configure.py'), '--setup', data.setup], { encoding: 'utf8' });
  assert.equal(check.status, 0, check.stderr);
  const worker = join(result.output, 'target/release/interfold-openvm-prover');
  await mkdir(dirname(worker), { recursive: true });
  await writeFile(worker, '#!/bin/sh\nprintf "harmless test worker failure\\n" >&2\nexit 7\n');
  await chmod(worker, 0o700);
  check = spawnSync('python3', [join(result.output, 'run-compression.py'), 'compute'], { encoding: 'utf8' });
  assert.equal(check.status, 7, check.stderr);
  const report = JSON.parse(await readFile(join(result.output, 'results/compute/timing.json')));
  assert.equal(report.status, 'failed');
  assert.equal(report.exitCode, 7);
  assert.equal(report.nativeAndLocalEvmVerified, false);
  assert.equal(report.canonicalSealEncoding, false);
  assert.equal(report.sealSha256, undefined);
  assert.ok(report.elapsedSeconds >= 0);
  assert.ok(report.peakWorkerRssBytes > 0);
  assert.equal(report.workerSha256, hash(await readFile(worker)));
  assert.ok(report.workerPid > 0);
});

test('compression runner finalizes a failed timing report when the worker is absent', async t => {
  const data = await fixture();
  t.after(() => rm(data.directory, { recursive: true, force: true }));
  const result = await packageRootHandoff(data.options);
  const configure = spawnSync('python3', [join(result.output, 'configure.py'), '--setup', data.setup], { encoding: 'utf8' });
  assert.equal(configure.status, 0, configure.stderr);
  const check = spawnSync('python3', [join(result.output, 'run-compression.py'), 'compute'], { encoding: 'utf8' });
  assert.equal(check.status, 1, check.stderr);
  const report = JSON.parse(await readFile(join(result.output, 'results/compute/timing.json')));
  assert.equal(report.status, 'failed');
  assert.equal(report.errorType, 'FileNotFoundError');
  assert.equal(report.exitCode, null);
  assert.equal(report.nativeAndLocalEvmVerified, false);
  assert.ok(report.finishedAt);
  assert.ok(report.elapsedSeconds >= 0);
});

test('compression runner refuses an exit-zero output with the wrong ABI seal header', async t => {
  const data = await fixture();
  t.after(() => rm(data.directory, { recursive: true, force: true }));
  const result = await packageRootHandoff(data.options);
  const configure = spawnSync('python3', [join(result.output, 'configure.py'), '--setup', data.setup], { encoding: 'utf8' });
  assert.equal(configure.status, 0, configure.stderr);
  const worker = join(result.output, 'target/release/interfold-openvm-prover');
  await mkdir(dirname(worker), { recursive: true });
  await writeFile(worker, '#!/usr/bin/env python3\nfrom pathlib import Path\nimport sys\nPath(sys.argv[-1]).write_bytes(bytes(1856))\n');
  await chmod(worker, 0o700);
  const check = spawnSync('python3', [join(result.output, 'run-compression.py'), 'compute'], { encoding: 'utf8' });
  assert.equal(check.status, 1, check.stderr);
  const report = JSON.parse(await readFile(join(result.output, 'results/compute/timing.json')));
  assert.equal(report.exitCode, 0);
  assert.equal(report.status, 'failed');
  assert.equal(report.canonicalSealEncoding, false);
  assert.equal(report.nativeAndLocalEvmVerified, false);
});

test('final timing persistence failure removes completion claims from the printed report', async t => {
  const data = await fixture();
  t.after(() => rm(data.directory, { recursive: true, force: true }));
  const result = await packageRootHandoff(data.options);
  const configure = spawnSync('python3', [join(result.output, 'configure.py'), '--setup', data.setup], { encoding: 'utf8' });
  assert.equal(configure.status, 0, configure.stderr);
  const worker = join(result.output, 'target/release/interfold-openvm-prover');
  await mkdir(dirname(worker), { recursive: true });
  await writeFile(worker, '#!/usr/bin/env python3\nfrom pathlib import Path\nimport sys\nPath(sys.argv[-1]).write_bytes(b"".join(word.to_bytes(32, "big") for word in [1, 64, 1760]) + bytes(1760))\n');
  await chmod(worker, 0o700);
  const wrapper = `import importlib.util
import sys
sys.path.insert(0, ${JSON.stringify(result.output)})
spec = importlib.util.spec_from_file_location("handoff_runner", ${JSON.stringify(join(result.output, 'run-compression.py'))})
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
original_save = module.save_report
def fail_final(path, report):
    if report["status"] == "complete":
        raise OSError("Injected final report persistence failure")
    original_save(path, report)
module.save_report = fail_final
sys.argv = [${JSON.stringify(join(result.output, 'run-compression.py'))}, "compute"]
module.main()
`;
  const check = spawnSync('python3', ['-c', wrapper], { encoding: 'utf8' });
  assert.equal(check.status, 1, check.stderr);
  const report = JSON.parse(check.stdout);
  assert.equal(report.exitCode, 0);
  assert.equal(report.status, 'failed');
  assert.match(report.reportPersistenceError, /Injected final report persistence failure/);
  assert.equal(report.nativeAndLocalEvmVerified, false);
  assert.equal(report.sealBytes, undefined);
  assert.equal(report.sealSha256, undefined);
});

async function longRunningFixture(t, { ignoreSignals = false, errorAfterSpawn = false } = {}) {
  const data = await fixture();
  t.after(() => rm(data.directory, { recursive: true, force: true }));
  const result = await packageRootHandoff(data.options);
  const configure = spawnSync('python3', [join(result.output, 'configure.py'), '--setup', data.setup], { encoding: 'utf8' });
  assert.equal(configure.status, 0, configure.stderr);
  const worker = join(result.output, 'target/release/interfold-openvm-prover');
  const ready = join(data.directory, 'harmless-worker-ready');
  const received = join(data.directory, 'harmless-worker-signal');
  await mkdir(dirname(worker), { recursive: true });
  await writeFile(worker, `#!/usr/bin/env python3
import os
from pathlib import Path
import signal
import sys
import time
def stop(signum, frame):
    Path(${JSON.stringify(received)}).write_text(signal.Signals(signum).name)
    # Harmless canonical bytes deliberately test that an interruption still wins
    # over an exit-zero child. This fixture does not generate a proof.
    Path(sys.argv[-1]).write_bytes(b"".join(word.to_bytes(32, "big") for word in [1, 64, 1760]) + bytes(1760))
    raise SystemExit(0)
for signum in [signal.SIGINT, signal.SIGTERM]:
    signal.signal(signum, signal.SIG_IGN if ${ignoreSignals ? 'True' : 'False'} else stop)
Path(${JSON.stringify(ready)}).write_text(str(os.getpid()))
while True:
    time.sleep(0.1)
`);
  await chmod(worker, 0o700);
  const wrapper = `import importlib.util
from pathlib import Path
import sys
import time
sys.path.insert(0, ${JSON.stringify(result.output)})
spec = importlib.util.spec_from_file_location("handoff_runner", ${JSON.stringify(join(result.output, 'run-compression.py'))})
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.STOP_GRACE_SECONDS = 0.1
${errorAfterSpawn ? `original_save = module.save_report
injected = False
def fail_once(path, report):
    global injected
    if report.get("workerPid") and report["status"] == "running" and not injected:
        injected = True
        deadline = time.monotonic() + 5
        while not Path(${JSON.stringify(ready)}).exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        raise OSError("Injected timing write failure after Popen")
    original_save(path, report)
module.save_report = fail_once
` : ''}
sys.argv = [${JSON.stringify(join(result.output, 'run-compression.py'))}, "compute"]
module.main()
`;
  const runner = spawn('python3', ['-c', wrapper], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = '';
  runner.stderr.on('data', chunk => { stderr += chunk; });
  const finished = new Promise((resolve, reject) => {
    runner.once('error', reject);
    runner.once('close', (code, signal) => resolve({ code, signal }));
  });
  t.after(async () => {
    if (runner.exitCode === null && runner.signalCode === null) runner.kill('SIGTERM');
    await finished;
  });
  const reportPath = join(result.output, 'results/compute/timing.json');
  await eventually(async () => {
    const value = await readFile(ready, 'utf8');
    return /^\d+$/.test(value);
  });
  return { runner, finished, reportPath, received, workerPid: Number(await readFile(ready, 'utf8')), stderr: () => stderr };
}

for (const [requestedSignal, exitCode] of [['SIGINT', 130], ['SIGTERM', 143]]) {
  test(`compression runner forwards ${requestedSignal}, reaps its child, and interruption overrides exit-zero`, async t => {
    const data = await longRunningFixture(t);
    data.runner.kill(requestedSignal);
    const finish = await data.finished;
    assert.equal(finish.code, exitCode, data.stderr());
    assert.equal(finish.signal, null);
    const report = JSON.parse(await readFile(data.reportPath));
    assert.equal(report.status, 'interrupted');
    assert.equal(report.requestedSignal, requestedSignal);
    assert.equal(report.exitCode, 0);
    assert.equal(report.canonicalSealEncoding, true);
    assert.equal(report.nativeAndLocalEvmVerified, false);
    assert.equal(report.sealSha256, undefined);
    assert.ok(report.finishedAt);
    assert.ok(report.interruptedAt);
    assert.equal(await readFile(data.received, 'utf8'), requestedSignal);
    assert.equal(isAlive(data.workerPid), false);
  });
}

test('compression runner escalates an ignored signal to SIGKILL and reaps its child', async t => {
  const data = await longRunningFixture(t, { ignoreSignals: true });
  data.runner.kill('SIGTERM');
  const finish = await data.finished;
  assert.equal(finish.code, 143, data.stderr());
  const report = JSON.parse(await readFile(data.reportPath));
  assert.equal(report.status, 'interrupted');
  assert.equal(report.exitCode, -9);
  assert.equal(report.nativeAndLocalEvmVerified, false);
  assert.equal(isAlive(data.workerPid), false);
});

test('post-spawn timing write failure terminates and reaps the owned child before final failure', async t => {
  const data = await longRunningFixture(t, { ignoreSignals: true, errorAfterSpawn: true });
  const finish = await data.finished;
  assert.equal(finish.code, 1, data.stderr());
  const report = JSON.parse(await readFile(data.reportPath));
  assert.equal(report.status, 'failed');
  assert.equal(report.errorType, 'OSError');
  assert.match(report.error, /Injected timing write failure/);
  assert.equal(report.exitCode, -9);
  assert.equal(report.nativeAndLocalEvmVerified, false);
  assert.equal(isAlive(data.workerPid), false);
});

test('root handoff rejects changed checkpoint, application key and journal before copying', async t => {
  for (const variant of ['root', 'application', 'journal', 'unknown-manifest-field', 'symlink']) {
    await t.test(variant, async () => {
      const data = await fixture();
      try {
        if (variant === 'root') await writeFile(join(data.job.root, 'root.bin'), 'changed');
        if (variant === 'application') await writeFile(data.config.app_pk, 'changed');
        if (variant === 'journal') await writeFile(data.job.journal, Buffer.alloc(288));
        if (variant === 'unknown-manifest-field') await writeFile(join(data.job.root, 'manifest.json'), JSON.stringify({ ...data.manifest, secret: 'must not copy unknown data' }));
        if (variant === 'symlink') {
          await rm(data.config.app_pk);
          await symlink(data.job.journal, data.config.app_pk);
        }
        await assert.rejects(packageRootHandoff(data.options), /differs|Unexpected|regular/);
      } finally { await rm(data.directory, { recursive: true, force: true }); }
    });
  }
});

test('host verification rejects changed bundle and independently changed setup bytes', async t => {
  const data = await fixture();
  t.after(() => rm(data.directory, { recursive: true, force: true }));
  const result = await packageRootHandoff(data.options);
  await writeFile(join(data.setup, 'halo2.pk'), 'changed setup bytes');
  let check = spawnSync('python3', [join(result.output, 'configure.py'), '--setup', data.setup], { encoding: 'utf8' });
  assert.notEqual(check.status, 0);
  assert.match(check.stderr, /size or SHA-256 differs: halo2.pk/);
  await writeFile(join(result.output, 'jobs/compute/root/root.bin'), 'changed checkpoint bytes');
  check = spawnSync('python3', [join(result.output, 'configure.py'), '--bundle-only'], { encoding: 'utf8' });
  assert.notEqual(check.status, 0);
  assert.match(check.stderr, /size or SHA-256 differs: jobs\/compute\/root\/root.bin/);
});
