import { spawnSync } from 'node:child_process';
import { readFile, stat } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { proofTimings } from './lib/proof-timing.mjs';

// A PID can be reused during a long proof. Record its operating-system start
// identity when available; process.kill(pid, 0) alone cannot establish ownership.
export function processStartIdentity(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return null;
  const result = spawnSync('ps', ['-p', String(pid), '-o', 'lstart='], {
    encoding: 'utf8', env: { ...process.env, LC_ALL: 'C' }, timeout: 2000,
  });
  return result.status === 0 && result.stdout.trim() ? result.stdout.trim() : null;
}

export function probeProcess(pid, expectedStartIdentity = null) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return { pid: pid ?? null, state: 'unknown', identityVerified: false };
  try { process.kill(pid, 0); } catch (error) {
    if (error.code === 'ESRCH') return { pid, state: 'dead', identityVerified: false };
    if (error.code !== 'EPERM') return { pid, state: 'unknown', identityVerified: false };
  }
  const actual = processStartIdentity(pid);
  if (expectedStartIdentity && actual && actual !== expectedStartIdentity) {
    return { pid, state: 'reused', identityVerified: false };
  }
  return { pid, state: 'alive', identityVerified: Boolean(expectedStartIdentity && actual) };
}

export function reconcileProofStatus(report, probe = probeProcess, now = Date.now()) {
  const supervisor = probe(report.pid, report.supervisorStartIdentity);
  const phase = report.phases?.[report.currentPhase]
    ?? Object.values(report.phases ?? {}).findLast(value => value.pid);
  const child = phase?.pid ? probe(phase.pid, phase.startIdentity) : { pid: null, state: 'absent', identityVerified: false };
  const reachable = value => value.state === 'alive';
  const stopped = value => ['dead', 'reused', 'absent'].includes(value.state);
  let observedStatus;
  if (report.status !== 'running') {
    observedStatus = reachable(child) ? `${report.status}-child-alive` : report.status;
  } else if (reachable(supervisor)) {
    observedStatus = supervisor.identityVerified ? 'running' : 'supervisor-alive-identity-unverified';
  } else if (stopped(supervisor) && reachable(child)) {
    observedStatus = 'orphaned-child-alive';
  } else if (stopped(supervisor) && stopped(child)) {
    observedStatus = 'stopped-without-final-status';
  } else {
    observedStatus = 'liveness-unknown';
  }
  const timings = proofTimings(observedStatus === 'stopped-without-final-status'
    ? { ...report, status: 'interrupted' } : report, now);
  return { schemaVersion: 1, scope: report.scope ?? null, checkedAt: new Date(now).toISOString(), recordedStatus: report.status,
    observedStatus, currentPhase: report.currentPhase ?? null, supervisor, child,
    timings,
    applicationProofVerified: report.applicationProofVerified === true,
    evmReceiptGenerated: report.evmReceiptGenerated === true };
}

export async function readProofStatus(path) {
  let statusPath = resolve(path);
  if ((await stat(statusPath)).isDirectory()) statusPath = join(statusPath, 'status.json');
  if ((await stat(statusPath)).size > 64 * 1024) throw new Error('Proof status file is too large');
  const report = JSON.parse(await readFile(statusPath, 'utf8'));
  if (report.schemaVersion !== 1 || !['running', 'complete', 'failed', 'interrupted'].includes(report.status)
      || !report.phases || typeof report.phases !== 'object') throw new Error('Unrecognized proof status record');
  return { statusPath, ...reconcileProofStatus(report) };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) throw new Error('Usage: node scripts/openvm-proof-status.mjs RUN_DIRECTORY_OR_STATUS_JSON');
  console.log(JSON.stringify(await readProofStatus(process.argv[2]), null, 2));
}
