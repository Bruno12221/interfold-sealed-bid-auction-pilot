import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { AbiCoder, keccak256 } from 'ethers';
import { packageInputProofJob } from '../scripts/package-input-proof-job.mjs';
import { setupArtifactUrls } from '../scripts/package-root-handoff.mjs';
import { CHAIN_ID, PROTOCOL } from '../scripts/config.mjs';
import { SECURE_PARAMS_HASH } from '../scripts/lib/program-plan.mjs';
import { PINNED_OPENVM } from '../scripts/lib/verifier-stack.mjs';

const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const metadata = bytes => ({ bytes: Buffer.byteLength(bytes), sha256: digest(bytes) });
const names = ['chainId', 'program', 'interfold', 'auction', 'context', 'e3Id', 'committeePublicKey', 'paramsHash', 'slot', 'bidder', 'maxTick', 'ciphertextHash', 'ciphertextCommitment'];
const types = ['uint256', 'address', 'address', 'address', 'bytes32', 'uint256', 'bytes32', 'bytes32', 'uint256', 'address', 'uint256', 'bytes32', 'bytes32'];

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'input-proof-job-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const handoff = join(directory, 'old'), worker = join(directory, 'worker'), publicBundle = join(directory, 'public'), setup = join(directory, 'setup');
  const statementPath = join(publicBundle, 'statement.json');
  const statement = { chainId: String(CHAIN_ID), program: '0x1111111111111111111111111111111111111111', interfold: PROTOCOL,
    auction: '0x2222222222222222222222222222222222222222', context: '0x' + '33'.repeat(32), e3Id: '4',
    committeePublicKey: '0x' + '44'.repeat(32), paramsHash: SECURE_PARAMS_HASH, slot: '1',
    bidder: '0x5555555555555555555555555555555555555555', maxTick: '100', ciphertextHash: keccak256('0x1234'), ciphertextCommitment: '0x' + '66'.repeat(32) };
  await mkdir(publicBundle, { recursive: true });
  const journal = Buffer.from(AbiCoder.defaultAbiCoder().encode(types, names.map(n => statement[n])).slice(2), 'hex');
  const framed = Buffer.alloc(438); framed.writeUInt32LE(2); framed.writeBigUInt64LE(416n, 4); journal.copy(framed, 12);
  framed.writeBigUInt64LE(2n, 428); framed.set([0x12, 0x34], 436);
  await writeFile(statementPath, JSON.stringify(statement)); await writeFile(join(publicBundle, 'input.bin'), framed);
  await writeFile(join(publicBundle, 'statement.bin'), journal);
  await writeFile(join(publicBundle, 'bid.private.json'), 'private witness decoy must never be copied');
  const app_commit = { app_exe_commit: PINNED_OPENVM.bindingExeCommit, app_vm_commit: PINNED_OPENVM.vmCommit };
  const verifier = await readFile('test/fixtures/openvm-receipts/verifier.bytecode.json');
  const artifacts = { 'app.pk': 'public app key', 'guest.vmexe': 'public guest', 'aggregation.pk': 'public agg key',
    'identity.json': JSON.stringify({ app_commit }), 'verifier.bytecode.json': verifier };
  const original = { schemaVersion: 1, openvmVersion: '2.0.2', openvmRevision: '59a69b8b0cbee7011ac978e4cc07707ee3681944', files: {} };
  const sources = { schemaVersion: 1, openvmVersion: '2.0.2', artifacts: {} };
  for (const [name, url] of Object.entries(setupArtifactUrls())) {
    const value = name.endsWith('verifier.bytecode.json') ? verifier : Buffer.from('fake public setup ' + name);
    sources.artifacts[name] = { url, ...metadata(value) };
    await mkdir(dirname(join(setup, name)), { recursive: true }); await writeFile(join(setup, name), value);
  }
  const config = { app_pk: 'jobs/binding/app.pk', executable: 'jobs/binding/guest.vmexe', aggregation_pk: 'jobs/binding/aggregation.pk',
    verifier_artifact: 'jobs/binding/verifier.bytecode.json', halo2_pk: '@SETUP@/halo2.pk', halo2_params_dir: '@SETUP@/params',
    verifier_sha256: PINNED_OPENVM.verifierArtifactSha256.slice(2), app_commit, segment_memory_bytes: 2147483648 };
  const files = { 'SETUP-SOURCES.json': JSON.stringify(sources), 'jobs/binding/config.template.json': JSON.stringify(config),
    ...Object.fromEntries(Object.entries(artifacts).map(([name, value]) => ['jobs/binding/' + name, value])) };
  for (const [name, value] of Object.entries(files)) {
    await mkdir(dirname(join(handoff, name)), { recursive: true }); await writeFile(join(handoff, name), value);
    original.files[name] = metadata(value);
  }
  await writeFile(join(handoff, 'bundle-manifest.json'), JSON.stringify(original));
  await mkdir(join(handoff, 'jobs/binding/root'), { recursive: true });
  await writeFile(join(handoff, 'jobs/binding/root/root.bin'), 'old wrong-journal root must never be copied');
  for (const name of ['Cargo.toml', 'Cargo.lock', 'LICENSE.md', 'NOTICE.md', 'README.md', 'fetch-setup.py', 'src/main.rs']) {
    await mkdir(dirname(join(worker, name)), { recursive: true }); await writeFile(join(worker, name), 'harmless public source "prove-app"');
  }
  return { directory, setup, statement, statementPath, publicBundle, handoff, worker,
    options: { output: join(directory, 'bundle'), statement: statementPath, publicBundle, trustedHandoff: handoff, worker } };
}

const python = (folder, ...args) => spawnSync('python3', [join(folder, 'run-proof.py'), ...args], { encoding: 'utf8', timeout: 30_000 });

async function installWorker(folder, mode = 'normal') {
  const path = join(folder, 'target/release/interfold-openvm-prover');
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `#!/usr/bin/env python3
# Harmless orchestration fixture. These bytes are not cryptographic proofs.
import hashlib,json,os,signal,sys,time
from pathlib import Path
action,conf,source,journal,target=sys.argv[1:]
config=json.loads(Path(conf).read_text()); target=Path(target); root=Path(conf).parent
sha=lambda path:hashlib.sha256(Path(path).read_bytes()).hexdigest()
artifacts={key:sha(config[key]) for key in ['app_pk','executable','aggregation_pk','verifier_artifact']}
if ${JSON.stringify(mode)} == 'wait':
    (root/'ready.pid').write_text(str(os.getpid()))
    def stop(signum, frame): raise SystemExit(0)
    signal.signal(signal.SIGTERM,stop); signal.signal(signal.SIGINT,stop)
    while True: time.sleep(.05)
if ${JSON.stringify(mode)} == 'fail-once' and action == 'aggregate-stark' and not (root/'failed-once').exists():
    (root/'failed-once').write_text('yes'); raise SystemExit(7)
if action == 'prove-app':
    target.write_bytes(b'not a real app proof')
    m={'schema_version':1,'openvm_version':'v2.0','openvm_revision':'59a69b8b0cbee7011ac978e4cc07707ee3681944',
       'stage':action,'proof_format':'openvm-sdk-bitcode-ContinuationVmProof<SC>','app_commit':config['app_commit'],
       'journal_bytes':416,'sources':{'config_sha256':sha(conf),'input_sha256':sha(source),'journal_sha256':sha(journal),'config_artifacts':artifacts},
       'proof_sha256':sha(target),'proof_bytes':target.stat().st_size}
    Path(str(target)+'.manifest.json').write_text(json.dumps(m))
elif action in ['aggregate-stark','prove-root']:
    target.mkdir(); names=['aggregate.json','metadata.bin'] if action=='aggregate-stark' else ['root.bin']
    for name in names: (target/name).write_bytes(('not a real proof '+name).encode())
    m={'schema_version':1,'openvm_version':'v2.0','openvm_revision':'59a69b8b0cbee7011ac978e4cc07707ee3681944',
       'stage':action,'app_commit':config['app_commit'],'journal_sha256':hashlib.sha256(Path(journal).read_bytes()).hexdigest(),
       'journal_bytes':416,'config_artifacts':artifacts,'files':{name:hashlib.sha256((target/name).read_bytes()).hexdigest() for name in names}}
    (target/'manifest.json').write_text(json.dumps(m))
elif action=='compress-root':
    target.write_bytes(bytes(1856) if ${JSON.stringify(mode)}=='bad-seal' else b''.join(x.to_bytes(32,'big') for x in [1,64,1760])+bytes(1760))
elif action=='verify':
    p=json.loads(Path(source).read_text())
    assert p['version']=='v2.0' and p['app_exe_commit']==config['app_commit']['app_exe_commit']
    assert p['user_public_values']=='0x'+hashlib.sha256(Path(journal).read_bytes()).hexdigest()
    target.write_bytes(b''.join(x.to_bytes(32,'big') for x in [1,64,1760])+bytes.fromhex(p['proof_data']['accumulator'][2:])+bytes.fromhex(p['proof_data']['proof'][2:]))
else: raise ValueError(action)
`);
  await chmod(path, 0o700);
  return path;
}

async function prepared(t, mode = 'normal') {
  const data = await fixture(t); const result = await packageInputProofJob(data.options);
  const configured = python(result.output, 'configure', '--setup', data.setup);
  assert.equal(configured.status, 0, configured.stderr);
  data.output = result.output; data.binary = await installWorker(result.output, mode);
  return data;
}

test('fixed allowlist packages public framed input and latest source, excluding witnesses and all old proofs', async t => {
  const data = await fixture(t); const result = await packageInputProofJob(data.options);
  const manifest = JSON.parse(await readFile(join(result.output, 'bundle-manifest.json')));
  assert.equal(manifest.knownAnswer.liveAuctionProof, false);
  assert.equal(manifest.app_commit.app_exe_commit, PINNED_OPENVM.bindingExeCommit);
  assert.ok(Object.keys(manifest.files).includes('job/input.bin'));
  assert.ok(Object.keys(manifest.files).every(name => !/private|root\.bin|app\.proof/.test(name)));
  assert.equal(python(result.output, 'configure', '--bundle-only').status, 0);
  await assert.rejects(packageInputProofJob(data.options), /EEXIST/);
});

test('packaging rejects unknown statement fields, journal changes, input framing changes and symlinked public artifacts', async t => {
  for (const mutation of ['statement', 'journal', 'frame', 'symlink']) {
    const data = await fixture(t);
    if (mutation === 'statement') await writeFile(data.statementPath, JSON.stringify({ ...data.statement, privateKey: 'must not copy' }));
    if (mutation === 'journal') await writeFile(join(data.publicBundle, 'statement.bin'), Buffer.alloc(416));
    if (mutation === 'frame') await writeFile(join(data.publicBundle, 'input.bin'), Buffer.alloc(438));
    if (mutation === 'symlink') { await rm(join(data.handoff, 'jobs/binding/app.pk')); await symlink(data.statementPath, join(data.handoff, 'jobs/binding/app.pk')); }
    await assert.rejects(packageInputProofJob(data.options), /fields|journal|framing|regular/);
  }
});

test('configuration verifies existing setup and refuses overwriting a config or accepting a changed setup', async t => {
  const data = await prepared(t);
  assert.notEqual(python(data.output, 'configure', '--setup', data.setup).status, 0);
  await writeFile(join(data.setup, 'halo2.pk'), 'changed');
  const checked = python(data.output, 'run');
  assert.notEqual(checked.status, 0);
  assert.match(checked.stderr, /SHA-256 differs/);
});

test('harmless worker completes stages, verifies reconstructed seal, records timings and returns an allowlisted archive', async t => {
  const data = await prepared(t);
  const result = python(data.output, 'run', '--threads', '4'); assert.equal(result.status, 0, result.stderr);
  const state = JSON.parse(await readFile(join(data.output, 'results/state.json')));
  assert.equal(state.status, 'complete'); assert.equal(state.nativeAndLocalEvmVerified, true);
  assert.equal(state.liveAuctionProof, false); assert.equal(Object.keys(state.stages).length, 5);
  assert.equal(state.stages['prove-app'].cryptographicallyRevalidatedByNextStage, 'aggregate-stark');
  const report = JSON.parse(await readFile(join(data.output, state.stages['prove-app'].timing)));
  assert.equal(report.status, 'complete'); assert.equal(report.threads, 4);
  assert.ok(report.elapsedSeconds >= 0); assert.ok(Number.isInteger(report.workerPid)); assert.ok(report.finishedAt);
  assert.match(report.signature.worker.sha256, /^[a-f0-9]{64}$/);
  assert.equal(python(data.output, 'status').status, 0);
  const archive = python(data.output, 'archive'); assert.equal(archive.status, 0, archive.stderr);
  const listing = spawnSync('tar', ['-tzf', join(data.directory, 'interfold-input-proof-results.tar.gz')], { encoding: 'utf8' });
  assert.equal(listing.status, 0); assert.match(listing.stdout, /checked.seal/);
  assert.doesNotMatch(listing.stdout, /setup\/|target\/|private|witness/);
  assert.notEqual(python(data.output, 'archive').status, 0, 'must not overwrite return archive');
});

test('resume reuses only completed prefix and retries failed stage in a new directory', async t => {
  const data = await prepared(t, 'fail-once');
  assert.notEqual(python(data.output, 'run').status, 0);
  const before = JSON.parse(await readFile(join(data.output, 'results/state.json')));
  assert.deepEqual(Object.keys(before.stages), ['prove-app']);
  const resumed = python(data.output, 'run', '--resume'); assert.equal(resumed.status, 0, resumed.stderr);
  const after = JSON.parse(await readFile(join(data.output, 'results/state.json')));
  assert.equal(after.stages['prove-app'].primary, before.stages['prove-app'].primary);
  assert.equal(after.attempts, 6);
  const completedResume = python(data.output, 'run', '--resume'); assert.equal(completedResume.status, 0, completedResume.stderr);
  const final = JSON.parse(await readFile(join(data.output, 'results/state.json')));
  assert.equal(final.attempts, 7, 'completed seal must be reverified in a fresh path');
});

test('resume rejects modified completed proof, worker or public source', async t => {
  for (const mutation of ['proof', 'worker', 'source']) {
    const data = await prepared(t, 'fail-once'); assert.notEqual(python(data.output, 'run').status, 0);
    const state = JSON.parse(await readFile(join(data.output, 'results/state.json')));
    const changed = mutation === 'proof' ? join(data.output, state.stages['prove-app'].primary)
      : mutation === 'worker' ? data.binary : join(data.output, 'worker/README.md');
    await writeFile(changed, 'modified');
    assert.notEqual(python(data.output, 'run', '--resume').status, 0);
  }
});

test('resume skips orphan attempt paths and rejects a completed primary outside its exact stage output', async t => {
  const data = await prepared(t, 'fail-once'); assert.notEqual(python(data.output, 'run').status, 0);
  const statePath = join(data.output, 'results/state.json');
  const before = JSON.parse(await readFile(statePath));
  await mkdir(join(data.output, 'results/attempts/0003-aggregate-stark'));
  const primary = before.stages['prove-app'].primary;
  before.stages['prove-app'].primary = join(data.directory, 'outside-private-material');
  await writeFile(statePath, JSON.stringify(before));
  const rejected = python(data.output, 'run', '--resume');
  assert.notEqual(rejected.status, 0); assert.match(rejected.stderr, /primary differs/);
  before.stages['prove-app'].primary = primary;
  await writeFile(statePath, JSON.stringify(before));
  const resumed = python(data.output, 'run', '--resume'); assert.equal(resumed.status, 0, resumed.stderr);
  const after = JSON.parse(await readFile(statePath));
  assert.match(after.stages['aggregate-stark'].primary, /0004-aggregate-stark/);
});

test('status does not grow elapsed time for dead PIDs and archive refuses a concurrent owner', async t => {
  const data = await prepared(t);
  const statePath = join(data.output, 'results/state.json');
  const attempt = 'results/attempts/0001-prove-app';
  await mkdir(join(data.output, attempt), { recursive: true });
  await writeFile(statePath, JSON.stringify({ status: 'running', currentPhase: 'prove-app', currentAttempt: attempt,
    supervisorPid: 99999999, stages: {} }));
  await writeFile(join(data.output, attempt, 'timing.json'), JSON.stringify({ status: 'running', startedAt: '2026-01-01T00:00:00Z',
    startedUnix: 1, workerPid: 99999998 }));
  const status = python(data.output, 'status'); assert.equal(status.status, 0, status.stderr);
  const reported = JSON.parse(status.stdout);
  assert.equal(reported.status, 'stale-or-unconfirmed-running-state');
  assert.equal(reported.supervisorAlive, false); assert.equal(reported.workerAlive, false);
  assert.equal(reported.phaseElapsedSeconds, null); assert.equal(reported.finishTimeUnknown, true);
  const holder = spawn('python3', ['-c', `import fcntl,time\nf=open(${JSON.stringify(join(data.output, 'results/.run.lock'))},'a')\nfcntl.flock(f,fcntl.LOCK_EX)\nprint('locked',flush=True)\ntime.sleep(30)`], { stdio: ['ignore', 'pipe', 'ignore'] });
  await new Promise(resolve => holder.stdout.once('data', resolve));
  try {
    const archived = python(data.output, 'archive');
    assert.notEqual(archived.status, 0); assert.match(archived.stderr, /concurrently/);
  } finally { holder.kill('SIGTERM'); await new Promise(resolve => holder.once('exit', resolve)); }
});

test('exit-zero worker cannot claim completion for malformed final seal', async t => {
  const data = await prepared(t, 'bad-seal'); const result = python(data.output, 'run');
  assert.notEqual(result.status, 0); assert.match(result.stderr, /Noncanonical/);
  const state = JSON.parse(await readFile(join(data.output, 'results/state.json')));
  assert.equal(state.status, 'failed'); assert.equal(state.nativeAndLocalEvmVerified, false);
  assert.notEqual(python(data.output, 'archive').status, 0);
});

test('interruption reaps only the owned worker and leaves an interrupted resumable state', async t => {
  const data = await prepared(t, 'wait');
  const runner = spawn('python3', [join(data.output, 'run-proof.py'), 'run'], { stdio: 'ignore' });
  const exit = new Promise(resolve => runner.on('exit', (code, signal) => resolve({ code, signal })));
  let workerPid;
  for (let i = 0; i < 200; i++) {
    try { workerPid = Number(await readFile(join(data.output, 'ready.pid'), 'utf8')); break; } catch {}
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  assert.ok(workerPid); runner.kill('SIGTERM'); const result = await exit;
  assert.equal(result.code, 143);
  assert.throws(() => process.kill(workerPid, 0), /ESRCH/);
  const state = JSON.parse(await readFile(join(data.output, 'results/state.json')));
  assert.equal(state.status, 'interrupted'); assert.equal(state.nativeAndLocalEvmVerified, false);
  assert.equal((await readdir(join(data.output, 'results/attempts'))).length, 1);
});
