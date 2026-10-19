import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { access, lstat, mkdir, open, readFile, rename, stat, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { processStartIdentity } from './openvm-proof-status.mjs';
import { proofTimings } from './lib/proof-timing.mjs';

const ACTIONS = new Set(['aggregate-stark', 'prove-root']);
const DEFAULT_RSS_BYTES = 8 * 1024 ** 3;
const COMPRESSION_SCOPE = 'halo2-root-compression';

async function sealMetadata(path) {
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink() || info.size !== 1856) throw new Error('Receipt worker did not create a 1856-byte seal file');
  const bytes = await readFile(path);
  const header = Buffer.alloc(96);
  header[31] = 1; header[63] = 64; header.writeUInt16BE(1760, 94);
  if (bytes.length !== 1856 || !bytes.subarray(0, 96).equals(header)) throw new Error('Receipt seal is not the canonical ABI encoding');
  return { path, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'),
    version: 1, proofDataBytes: 1760, canonicalAbiEncoding: true,
    cryptographicVerification: 'The trusted pinned worker verified the EVM proof, application identity and journal before successful exit; JavaScript checks encoding only.' };
}

export class ReceiptStageInterruptedError extends Error {
  constructor(interruption) {
    super(interruption.reason === 'resource-limit'
      ? 'Receipt stage stopped after exceeding the sampled worker RSS budget'
      : `Receipt stages interrupted by ${interruption.signal}`);
    this.interruption = interruption;
  }
}

async function fingerprint(path, limit = null) {
  const info = await stat(path);
  if (!info.isFile() || (limit !== null && info.size > limit)) throw new Error('Invalid or oversized receipt-stage artifact');
  const hash = createHash('sha256');
  // Stream the executable instead of buffering it. Proof bodies and large keys
  // are never read by this supervisor; the worker authenticates those inputs.
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return { path, bytes: info.size, sha256: hash.digest('hex') };
}

async function mustNotExist(path) {
  try { await lstat(path); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
  throw new Error('Every receipt stage and run must use a new output path');
}

export function sampleRssBytes(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return null;
  const result = spawnSync('ps', ['-p', String(pid), '-o', 'rss='], {
    encoding: 'utf8', env: { ...process.env, LC_ALL: 'C' }, timeout: 2000,
  });
  const value = result.stdout?.trim();
  if (result.status !== 0 || !/^\d+$/.test(value)) return null;
  const bytes = Number(value) * 1024;
  return Number.isSafeInteger(bytes) ? bytes : null;
}

async function loadJob(specPath) {
  if ((await stat(specPath)).size > 64 * 1024) throw new Error('Receipt stage job spec exceeds 64 KiB');
  const raw = await readFile(specPath);
  if (raw.length > 64 * 1024) throw new Error('Receipt stage job spec exceeds 64 KiB');
  const spec = JSON.parse(raw.toString('utf8'));
  const compression = spec.scope === COMPRESSION_SCOPE && spec.allowHalo2Compression === true;
  const maxRssBytes = spec.maxRssBytes ?? DEFAULT_RSS_BYTES;
  const rayonThreads = spec.rayonThreads ?? 2;
  const sampleIntervalMs = spec.sampleIntervalMs === undefined ? (compression ? 250 : 2000) : spec.sampleIntervalMs;
  if (spec.schemaVersion !== 1 || !Number.isSafeInteger(maxRssBytes) || maxRssBytes < 1
      || !Number.isSafeInteger(rayonThreads) || rayonThreads < 1 || rayonThreads > 32
      || !Number.isSafeInteger(sampleIntervalMs) || sampleIntervalMs < 100 || sampleIntervalMs > 5000
      || (spec.scope !== undefined && !['receipt-stark-stages', COMPRESSION_SCOPE].includes(spec.scope))
      || (spec.allowHalo2Compression !== undefined && typeof spec.allowHalo2Compression !== 'boolean')
      || (spec.scope === COMPRESSION_SCOPE && !compression)
      || (spec.allowHalo2Compression === true && !compression)
      || !Array.isArray(spec.stages) || spec.stages.length < 1 || spec.stages.length > 16) {
    throw new Error('Invalid receipt stage job spec');
  }
  const names = new Set(), outputs = new Set();
  const stages = spec.stages.map(stage => {
    if (!stage || typeof stage !== 'object' || !/^[a-z][a-z0-9_-]{0,63}$/.test(stage.name)
        || names.has(stage.name) || (compression ? stage.action !== 'compress-root' : !ACTIONS.has(stage.action))) {
      throw new Error('Invalid or duplicate receipt stage');
    }
    names.add(stage.name);
    const paths = {};
    for (const key of ['config', 'input', 'journal', 'output']) {
      if (typeof stage[key] !== 'string' || !stage[key] || stage[key].includes('\0')) throw new Error('Invalid receipt stage path');
      paths[key] = resolve(dirname(specPath), stage[key]);
    }
    if (outputs.has(paths.output) || ['config', 'input', 'journal'].some(key => paths[key] === paths.output)) {
      throw new Error('Receipt stage output paths must be distinct from their inputs');
    }
    outputs.add(paths.output);
    return { name: stage.name, action: stage.action, ...paths };
  });
  return { maxRssBytes, rayonThreads, sampleIntervalMs, compression,
    scope: compression ? COMPRESSION_SCOPE : 'receipt-stark-stages', stages,
    specFingerprint: { path: specPath, bytes: raw.length, sha256: createHash('sha256').update(raw).digest('hex') } };
}

export async function runReceiptStages({ worker, spec, output }) {
  const workerPath = resolve(worker), specPath = resolve(spec), run = resolve(output);
  const job = await loadJob(specPath);
  await access(workerPath);
  const fingerprints = {
    worker: await fingerprint(workerPath), spec: job.specFingerprint, stages: {},
  };
  for (const stage of job.stages) {
    await mustNotExist(stage.output);
    fingerprints.stages[stage.name] = {
      config: await fingerprint(stage.config, 64 * 1024), journal: await fingerprint(stage.journal, 416),
    };
  }
  await mkdir(run, { mode: 0o700 });
  const report = { schemaVersion: 1, scope: job.scope, pid: process.pid,
    supervisorStartIdentity: processStartIdentity(process.pid), startedAt: new Date().toISOString(),
    status: 'running', currentPhase: null, maxRssBytes: job.maxRssBytes, rayonThreads: job.rayonThreads,
    sampleIntervalMs: job.sampleIntervalMs,
    resourceMeasurement: `Sampled worker-process RSS every ${job.sampleIntervalMs} ms; this is not an operating-system memory limit.`,
    peakRssBytes: 0, fingerprints, phases: {}, applicationProofVerified: false, evmReceiptGenerated: false,
    receiptVerification: null };
  const statusPath = join(run, 'status.json');
  const resources = await open(join(run, 'resource.jsonl'), 'wx', 0o600);
  let saves = Promise.resolve(), samples = Promise.resolve();
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
  let interruption = null, activeChild = null, escalation = null, sampler = null;
  function throwIfInterrupted() { if (interruption) throw new ReceiptStageInterruptedError(interruption); }
  function interrupt(signal, details = {}) {
    if (interruption) return;
    interruption = { reason: 'signal', ...details, signal, at: new Date().toISOString() };
    report.interruption = interruption; report.status = 'interrupted';
    report.evmReceiptGenerated = false; report.receiptVerification = null;
    if (activeChild) {
      const child = activeChild, phase = report.phases[report.currentPhase];
      phase.requestedSignal = signal;
      child.kill(signal);
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
  function sample(child, phase) {
    if (activeChild !== child || child.exitCode !== null || child.signalCode !== null) return;
    const rssBytes = sampleRssBytes(child.pid);
    if (rssBytes === null) return;
    phase.peakRssBytes = Math.max(phase.peakRssBytes, rssBytes);
    report.peakRssBytes = Math.max(report.peakRssBytes, rssBytes);
    const row = { checkedAt: new Date().toISOString(), phase: report.currentPhase, pid: child.pid,
      rssBytes, peakRssBytes: phase.peakRssBytes, maxRssBytes: job.maxRssBytes, sampleIntervalMs: job.sampleIntervalMs };
    const next = samples.then(() => resources.writeFile(JSON.stringify(row) + '\n'));
    samples = next.catch(error => interrupt('SIGTERM', { reason: 'resource-log-error', code: error.code ?? 'UNKNOWN' }));
    if (rssBytes > job.maxRssBytes) interrupt('SIGTERM', {
      reason: 'resource-limit', phase: report.currentPhase, rssBytes, maxRssBytes: job.maxRssBytes,
    });
    void save().catch(() => interrupt('SIGTERM', { reason: 'status-write-error' }));
  }
  async function checkFingerprints(stage) {
    for (const expected of [fingerprints.worker, fingerprints.spec,
      fingerprints.stages[stage.name].config, fingerprints.stages[stage.name].journal]) {
      const actual = await fingerprint(expected.path, expected.bytes);
      if (actual.sha256 !== expected.sha256 || actual.bytes !== expected.bytes) throw new Error('A receipt-stage artifact changed during the run');
      throwIfInterrupted();
    }
  }
  async function runStage(stage) {
    throwIfInterrupted(); await checkFingerprints(stage); await mustNotExist(stage.output);
    const inputInfo = await stat(stage.input);
    if (stage.action === 'aggregate-stark' ? !inputInfo.isFile() : !inputInfo.isDirectory()) {
      throw new Error('Receipt-stage input has the wrong file type');
    }
    throwIfInterrupted();
    const phase = { action: stage.action, startedAt: new Date().toISOString(), status: 'running',
      input: { path: stage.input, bytes: inputInfo.size, modifiedAt: inputInfo.mtime.toISOString() },
      output: stage.output, peakRssBytes: 0 };
    report.currentPhase = stage.name; report.phases[stage.name] = phase; await save();
    const log = await open(join(run, stage.name + '.log'), 'wx', 0o600);
    try {
      throwIfInterrupted();
      const child = spawn(workerPath, [stage.action, stage.config, stage.input, stage.journal, stage.output], {
        stdio: ['ignore', log.fd, log.fd], env: { ...process.env, RAYON_NUM_THREADS: String(job.rayonThreads),
          RUST_LOG: process.env.RUST_LOG || 'info' },
      });
      // A tiny worker can exit during the first status write. Never await before
      // registering both listeners, and never infer success from a missing PID.
      const completion = new Promise(res => {
        child.once('error', error => res({ error, code: null, signal: null }));
        child.once('exit', (code, signal) => res({ code, signal }));
      });
      activeChild = child; phase.pid = child.pid; phase.startIdentity = processStartIdentity(child.pid);
      sampler = setInterval(() => sample(child, phase), job.sampleIntervalMs);
      let supervisorError = null;
      try { sample(child, phase); await save(); }
      catch (error) {
        supervisorError = error;
        interrupt('SIGTERM', { reason: 'supervisor-error' });
      }
      const { code, signal, error } = await completion;
      clearInterval(sampler); sampler = null; activeChild = null;
      clearTimeout(escalation); escalation = null;
      await samples;
      Object.assign(phase, { finishedAt: new Date().toISOString(), exitCode: code, signal,
        status: interruption ? 'interrupted' : code === 0 && !error ? 'complete' : 'failed' });
      if (error) phase.spawnError = error.code ?? 'UNKNOWN';
      await save(); throwIfInterrupted();
      if (supervisorError) throw supervisorError;
      if (error || code !== 0) throw new Error(`Receipt stage ${stage.name} failed; see its saved log and status`);
      if (job.compression) phase.seal = await sealMetadata(stage.output);
      else {
        if (!(await stat(stage.output)).isDirectory()) throw new Error('Receipt worker did not create a stage output directory');
        phase.manifest = await fingerprint(join(stage.output, 'manifest.json'), 64 * 1024);
      }
      await checkFingerprints(stage); await save();
    } finally { await log.close(); }
  }
  try {
    await save();
    for (const stage of job.stages) await runStage(stage);
    throwIfInterrupted();
    Object.assign(report, { status: 'complete', currentPhase: null, finishedAt: new Date().toISOString(),
      evmReceiptGenerated: job.compression,
      receiptVerification: job.compression ? {
        source: 'Successful compress-root exits from the fingerprinted trusted worker for every queued seal.',
        independentJavaScriptCryptographicVerification: false,
        javascriptChecks: 'Exact 1856-byte canonical ABI seal encoding and SHA-256 fingerprints.',
      } : null });
    await save(); throwIfInterrupted(); return report;
  } catch (error) {
    const phase = report.phases[report.currentPhase];
    if (phase && ['running', 'complete'].includes(phase.status)) Object.assign(phase, {
      status: interruption ? 'interrupted' : 'failed', finishedAt: new Date().toISOString(),
    });
    report.status = interruption ? 'interrupted' : 'failed'; report.finishedAt = new Date().toISOString();
    report.evmReceiptGenerated = false; report.receiptVerification = null;
    report.error = error.message; await save(); throw error;
  } finally {
    process.off('SIGINT', onSigint); process.off('SIGTERM', onSigterm);
    clearInterval(sampler); clearTimeout(escalation);
    await samples; await resources.sync(); await resources.close();
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [worker, spec, output] = process.argv.slice(2);
  if (!output || process.argv.length !== 5) throw new Error('Usage: node scripts/openvm-receipt-stages.mjs WORKER JOB_SPEC_JSON NEW_RUN_DIR');
  try { console.log(JSON.stringify(await runReceiptStages({ worker, spec, output }), null, 2)); }
  catch (error) {
    console.error(error.message);
    process.exitCode = error instanceof ReceiptStageInterruptedError
      ? error.interruption.reason === 'resource-limit' ? 137 : error.interruption.signal === 'SIGINT' ? 130 : 143 : 1;
  }
}
