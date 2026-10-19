import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { access, mkdir, open, readFile, rename, stat, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { processStartIdentity } from './openvm-proof-status.mjs';
import { proofTimings } from './lib/proof-timing.mjs';

const base = resolve('pilot/auction-compute');
const sha256 = raw => createHash('sha256').update(raw).digest('hex');

export class ProofInterruptedError extends Error {
  constructor(signal) { super(`Application proof interrupted by ${signal}`); this.signal = signal; }
}

async function executable(candidates) {
  for (const candidate of candidates.filter(Boolean)) {
    try { await access(candidate); return resolve(candidate); } catch {}
  }
  throw new Error('Required pinned OpenVM tool is missing; build it before starting a long proof');
}

export async function proveApplication({ manifest, exe, keys, input, journal, output,
  segmentMaxMemoryBytes = Number(process.env.OPENVM_SEGMENT_MAX_MEMORY_BYTES || 2147483648) }) {
  // This is the VM's continuation segmentation threshold, not an RSS limit.
  // Smaller segments trade additional proofs for a smaller trace working set.
  if (!Number.isSafeInteger(segmentMaxMemoryBytes) || segmentMaxMemoryBytes < 268435456
      || segmentMaxMemoryBytes > 2147483648) throw new Error('Application segment memory must be 256 MiB to 2 GiB in whole bytes');
  const tool = await executable([process.env.CARGO_OPENVM_BIN,
    join(base, '.tools/openvm-parallel/bin/cargo-openvm'), join(base, '.tools/openvm/bin/cargo-openvm')]);
  const helper = await executable([process.env.OPENVM_TOOLS_BIN,
    join(base, '.tools/host-target/release/interfold-auction-openvm-tools'),
    resolve('pilot/openvm-tools/target/release/interfold-auction-openvm-tools')]);
  const paths = Object.fromEntries(Object.entries({ manifest, exe, input, journal, output, keys }).map(([k, v]) => [k, resolve(v)]));
  const appPk = join(paths.keys, 'app.pk'), appVk = join(paths.keys, 'app.vk');
  for (const path of [paths.manifest, paths.exe, paths.input, paths.journal, appPk, appVk]) {
    if (!(await stat(path)).isFile()) throw new Error('Expected saved file for every proving input');
  }
  const journalBytes = await readFile(paths.journal);
  if (![288, 416].includes(journalBytes.length)) throw new Error('Expected a compute or input-binding journal');
  const fingerprints = {};
  for (const [name, path] of Object.entries({ executable: paths.exe, provingKey: appPk, verifyingKey: appVk,
    input: paths.input, journal: paths.journal, prover: tool, identityVerifier: helper })) {
    fingerprints[name] = sha256(await readFile(path));
  }
  await mkdir(paths.output, { mode: 0o700 }); // New immutable run; never silently reuse an old proof.
  const report = { schemaVersion: 1, scope: 'application-stark-proof-only', pid: process.pid,
    supervisorStartIdentity: processStartIdentity(process.pid),
    startedAt: new Date().toISOString(), status: 'running', fingerprints, segmentMaxMemoryBytes,
    journalBytes: journalBytes.length, applicationProofVerified: false, evmReceiptGenerated: false, phases: {} };
  const statusPath = join(paths.output, 'status.json');
  let saves = Promise.resolve();
  function save() {
    report.timings = proofTimings(report);
    const serialized = JSON.stringify(report, null, 2) + '\n';
    const next = saves.then(async () => {
      await writeFile(statusPath + '.tmp', serialized, { mode: 0o600 });
      await rename(statusPath + '.tmp', statusPath);
    });
    saves = next.catch(() => {});
    return next;
  }
  let interruption = null, activeChild = null, escalation = null;
  function throwIfInterrupted() { if (interruption) throw new ProofInterruptedError(interruption); }
  function interrupt(signal) {
    if (interruption) return;
    interruption = signal;
    report.status = 'interrupted'; report.finishedAt = new Date().toISOString();
    report.interruption = { signal, at: report.finishedAt };
    if (activeChild) {
      const phase = report.phases[report.currentPhase];
      phase.requestedSignal = signal;
      activeChild.kill(signal);
      // Only this invocation's child is signalled. Reconciliation never kills a process.
      const child = activeChild;
      escalation = setTimeout(() => {
        if (activeChild !== child || child.exitCode !== null || child.signalCode !== null) return;
        phase.escalatedSignal = 'SIGKILL'; child.kill('SIGKILL'); void save().catch(() => {});
      }, 10_000);
      escalation.unref();
    }
    void save().catch(() => {});
  }
  const onSigint = () => interrupt('SIGINT'), onSigterm = () => interrupt('SIGTERM');
  process.on('SIGINT', onSigint); process.on('SIGTERM', onSigterm);
  async function run(phase, command, args) {
    throwIfInterrupted();
    const startedAt = new Date().toISOString();
    report.currentPhase = phase; report.phases[phase] = { startedAt, status: 'running' }; await save();
    throwIfInterrupted();
    const log = await open(join(paths.output, phase + '.log'), 'wx', 0o600);
    try {
      throwIfInterrupted();
      const child = spawn(command, args, { stdio: ['ignore', log.fd, log.fd], env: {
        ...process.env, RAYON_NUM_THREADS: process.env.RAYON_NUM_THREADS || '3', RUST_LOG: process.env.RUST_LOG || 'info',
      } });
      // Register listeners immediately: a fast identity helper can exit while
      // the phase record is being saved. Waiting afterwards would miss its exit.
      const completion = new Promise(res => {
        child.once('error', error => res({ error, code: null, signal: null }));
        child.once('exit', (code, signal) => res({ code, signal }));
      });
      activeChild = child;
      report.phases[phase].pid = child.pid;
      report.phases[phase].startIdentity = processStartIdentity(child.pid); await save();
      const { code, signal, error } = await completion;
      activeChild = null; clearTimeout(escalation); escalation = null;
      report.phases[phase].finishedAt = new Date().toISOString();
      report.phases[phase].exitCode = code;
      report.phases[phase].signal = signal;
      if (error) report.phases[phase].spawnError = error.code ?? 'UNKNOWN';
      report.phases[phase].status = interruption ? 'interrupted' : code === 0 && !error ? 'complete' : 'failed'; await save();
      throwIfInterrupted();
      if (error) throw new Error(`OpenVM ${phase} could not start; see saved phase status`);
      if (code !== 0) throw new Error(`OpenVM ${phase} failed; see saved phase log`);
    } finally { await log.close(); }
  }
  try {
    await save(); throwIfInterrupted();
    // Derive identity independently BEFORE proof generation. An app VK alone
    // identifies the VM, and cannot establish which program produced a proof.
    await run('identity', helper, ['identity', appPk, paths.exe]);
    const identity = JSON.parse(await readFile(join(paths.output, 'identity.log'), 'utf8'));
    const commitment = identity.applicationExecutableCommitment;
    if (!/^0x[0-9a-f]{64}$/.test(commitment)) throw new Error('Missing independently derived executable commitment');
    report.applicationExecutableCommitment = commitment; await save();
    const proof = join(paths.output, 'guest.app.proof');
    await run('prove', tool, ['openvm', 'prove', 'app', '--manifest-path', paths.manifest, '--exe', paths.exe,
      '--app-pk', appPk, '--input', paths.input, '--proof', proof, '--segment-max-memory', String(segmentMaxMemoryBytes)]);
    await run('verify', helper, ['verify-app', appVk, proof, commitment, paths.journal]);
    const verified = JSON.parse(await readFile(join(paths.output, 'verify.log'), 'utf8'));
    if (!verified.applicationProofVerified || !verified.exactExecutableCommitmentVerified
        || !verified.publicJournalDigestMatches || verified.journalSha256 !== sha256(journalBytes)) {
      throw new Error('Application verifier did not authenticate the exact program and journal');
    }
    // Inputs may be public but must still remain frozen throughout a long run.
    for (const [name, path] of Object.entries({ executable: paths.exe, provingKey: appPk, verifyingKey: appVk,
      input: paths.input, journal: paths.journal, prover: tool, identityVerifier: helper })) {
      if (sha256(await readFile(path)) !== fingerprints[name]) throw new Error(`Proving artifact changed during the run: ${name}`);
      throwIfInterrupted();
    }
    throwIfInterrupted();
    Object.assign(report, verified, { status: 'complete', finishedAt: new Date().toISOString(), currentPhase: null });
    await save(); throwIfInterrupted(); console.log(JSON.stringify(report, null, 2)); return report;
  } catch (error) {
    report.status = interruption ? 'interrupted' : 'failed'; report.finishedAt = new Date().toISOString(); report.error = error.message;
    await save(); throw error;
  } finally {
    process.off('SIGINT', onSigint); process.off('SIGTERM', onSigterm); clearTimeout(escalation);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [manifest, exe, keys, input, journal, output] = process.argv.slice(2);
  if (!output || process.argv.length !== 8) throw new Error('Usage: node scripts/openvm-application-proof.mjs MANIFEST EXE KEYS CLI_INPUT_JSON JOURNAL_BIN NEW_OUTPUT_DIRECTORY');
  try { await proveApplication({ manifest, exe, keys, input, journal, output }); } catch (error) {
    if (!(error instanceof ProofInterruptedError)) throw error;
    process.exitCode = error.signal === 'SIGINT' ? 130 : 143;
    console.error(error.message);
  }
}
