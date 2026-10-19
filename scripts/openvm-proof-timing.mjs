import { open, readdir, readFile, rename, stat, writeFile } from 'node:fs/promises';
import { resolve, join, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { reconcileProofStatus } from './openvm-proof-status.mjs';

const terminalStates = new Set(['complete', 'failed', 'interrupted']);

export async function timingSnapshot(directory, { now = Date.now(), previous = null, probe } = {}) {
  const run = resolve(directory), statusPath = join(run, 'status.json');
  if ((await stat(statusPath)).size > 64 * 1024) throw new Error('Proof status file is too large');
  const report = JSON.parse(await readFile(statusPath, 'utf8'));
  if (report.schemaVersion !== 1 || !report.phases || typeof report.phases !== 'object'
      || Array.isArray(report.phases) || !['running', ...terminalStates].includes(report.status)) {
    throw new Error('Unrecognized application proof status');
  }
  const live = reconcileProofStatus(report, probe, now);
  const stoppedWithoutTimestamp = live.observedStatus === 'stopped-without-final-status';
  const timings = live.timings;
  const childAlive = live.child.state === 'alive';
  const done = stoppedWithoutTimestamp || (terminalStates.has(report.status) && !childAlive);
  return { schemaVersion: 1, scope: report.scope ?? null, task: basename(run), checkedAt: new Date(now).toISOString(),
    status: report.status, observedStatus: live.observedStatus, currentPhase: report.currentPhase ?? null,
    collectionFinished: done, timings,
    lastObservedChildAliveAt: childAlive ? new Date(now).toISOString() : previous?.lastObservedChildAliveAt ?? null,
    stopTimeUnknown: stoppedWithoutTimestamp,
    stopObservedAt: stoppedWithoutTimestamp ? previous?.stopObservedAt ?? new Date(now).toISOString() : null,
    applicationProofVerified: report.applicationProofVerified === true,
    evmReceiptGenerated: report.evmReceiptGenerated === true,
    etaSeconds: null,
    measurement: 'Wall-clock durations from saved start/finish timestamps; concurrent jobs share this host. No estimated completion time.',
  };
}

function summary(snapshot) {
  const state = snapshot.stopTimeUnknown ? 'stopped' : snapshot.status;
  const phase = snapshot.currentPhase ? ` (${snapshot.currentPhase})` : '';
  const timedPhase = snapshot.timings.phases.prove ? 'prove'
    : snapshot.currentPhase ?? Object.keys(snapshot.timings.phases).at(-1);
  const phaseTime = snapshot.timings.phases[timedPhase]?.elapsedHuman ?? 'unknown';
  const phaseLabel = timedPhase === 'prove' ? 'proving' : timedPhase ?? 'phase';
  const total = snapshot.timings.elapsedHuman ?? 'unknown';
  let completion = '';
  if (snapshot.collectionFinished) {
    const complete = snapshot.status === 'complete' && !snapshot.stopTimeUnknown;
    if (snapshot.scope === 'halo2-root-compression') completion = `; evmReceiptGenerated=${snapshot.evmReceiptGenerated}`;
    else if (snapshot.scope === 'receipt-stark-stages') completion = `; stagesComplete=${complete}`;
    else if (!snapshot.scope || snapshot.scope === 'application-stark-proof-only') completion = `; verified=${snapshot.applicationProofVerified}`;
    else completion = `; runComplete=${complete}`;
  }
  return `${snapshot.task}: ${state}${phase}; ${phaseLabel} ${phaseTime}; total ${total}`
    + (snapshot.stopTimeUnknown ? '; stopped without a recorded finish time' : '')
    + completion;
}

async function persist(directory, snapshot) {
  // These files are independent of status.json, which belongs to the existing
  // supervisor. A timer can attach to a live proof without modifying that job.
  const path = join(directory, 'timing.json'), temporary = `${path}.${process.pid}.tmp`;
  await writeFile(temporary, JSON.stringify(snapshot, null, 2) + '\n', { mode: 0o600 });
  await rename(temporary, path);
  const history = await open(join(directory, 'timing.jsonl'), 'a', 0o600);
  try { await history.writeFile(JSON.stringify(snapshot) + '\n'); await history.sync(); }
  finally { await history.close(); }
}

export async function collectTimings(directories, { watch = false, intervalMs = 30_000, onSnapshot = console.log } = {}) {
  if (!Number.isSafeInteger(intervalMs) || intervalMs < 100 || intervalMs > 300_000) throw new Error('Invalid timing sample interval');
  const pending = new Map(directories.map(directory => [resolve(directory), null]));
  if (!pending.size) throw new Error('No saved proof runs found');
  const final = [];
  do {
    for (const [directory, previous] of pending) {
      const snapshot = await timingSnapshot(directory, { previous });
      if (watch) await persist(directory, snapshot);
      onSnapshot(summary(snapshot));
      if (snapshot.collectionFinished) { final.push(snapshot); pending.delete(directory); }
      else pending.set(directory, snapshot);
    }
    if (!watch || !pending.size) break;
    await new Promise(resolve => setTimeout(resolve, intervalMs));
  } while (pending.size);
  return final;
}

async function defaultRuns() {
  const base = resolve('.pilot/proving-runs');
  const candidates = (await readdir(base, { withFileTypes: true })).filter(entry => entry.isDirectory());
  const result = [];
  for (const entry of candidates) {
    const path = join(base, entry.name);
    try { if ((await stat(join(path, 'status.json'))).isFile()) result.push(path); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  return result.sort();
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2), watch = args.includes('--watch');
  if (args.some(arg => arg.startsWith('--') && arg !== '--watch')) throw new Error('Usage: node scripts/openvm-proof-timing.mjs [--watch] [RUN_DIRECTORY ...]');
  const directories = args.filter(arg => arg !== '--watch');
  await collectTimings(directories.length ? directories : await defaultRuns(), { watch });
}
