import test from 'node:test';
import assert from 'node:assert/strict';
import { formatDuration, proofTimings } from '../scripts/lib/proof-timing.mjs';

const at = iso => Date.parse(iso);
const startedAt = '2026-10-16T12:00:00.250Z';

test('running durations use recorded wall-clock starts and floor whole seconds', () => {
  const report = { status: 'running', startedAt, phases: {
    prove: { status: 'running', startedAt: '2026-10-16T12:00:01.750Z' },
  } };
  const original = JSON.stringify(report);
  assert.deepEqual(proofTimings(report, at('2026-10-16T13:20:01.249Z')), {
    startedAt, finishedAt: null, elapsedSeconds: 4800, elapsedHuman: '01:20:00', completed: false,
    phases: { prove: { startedAt: report.phases.prove.startedAt, finishedAt: null,
      elapsedSeconds: 4799, elapsedHuman: '01:19:59', completed: false } },
  });
  assert.equal(JSON.stringify(report), original);
});

for (const status of ['complete', 'failed', 'interrupted']) {
  test(`${status} durations freeze at the recorded end, including phases`, () => {
    const report = { status, startedAt, finishedAt: '2026-10-16T14:00:00.999Z', phases: {
      prove: { status: status === 'complete' ? 'complete' : 'failed',
        startedAt: '2026-10-16T12:00:01.000Z', finishedAt: '2026-10-16T13:59:59.999Z' },
    } };
    const result = proofTimings(report, at('2026-10-17T14:00:00.000Z'));
    assert.equal(result.completed, true);
    assert.equal(result.elapsedSeconds, 7200);
    assert.equal(result.elapsedHuman, '02:00:00');
    assert.equal(result.phases.prove.completed, true);
    assert.equal(result.phases.prove.elapsedSeconds, 7198);
    assert.deepEqual(result, proofTimings(report, at('2027-01-01T00:00:00.000Z')));
  });
}

test('completed and active phases use their own boundaries', () => {
  const result = proofTimings({ status: 'running', startedAt, phases: {
    keygen: { startedAt, finishedAt: '2026-10-16T12:00:10.250Z' },
    prove: { startedAt: '2026-10-16T12:00:12.250Z', status: 'running' },
    verify: {},
  } }, at('2026-10-16T12:01:00.250Z'));
  assert.equal(result.elapsedSeconds, 60);
  assert.equal(result.phases.keygen.elapsedSeconds, 10);
  assert.equal(result.phases.keygen.completed, true);
  assert.equal(result.phases.prove.elapsedSeconds, 48);
  assert.equal(result.phases.prove.completed, false);
  assert.equal(result.phases.verify.elapsedSeconds, null);
});

test('terminal status without a finish cannot invent an end or growing duration', () => {
  for (const status of ['failed', 'interrupted', 'complete']) {
    const result = proofTimings({ status, startedAt, phases: {
      prove: { status: 'running', startedAt },
    } }, at('2026-10-16T13:00:00.000Z'));
    assert.equal(result.completed, false);
    assert.equal(result.elapsedSeconds, null);
    assert.equal(result.elapsedHuman, null);
    assert.equal(result.phases.prove.elapsedSeconds, null);
  }
  const result = proofTimings({ status: 'failed', startedAt,
    finishedAt: '2026-10-16T13:00:00.000Z', phases: { prove: { startedAt } },
  }, at('2026-10-17T00:00:00.000Z'));
  assert.equal(result.completed, true);
  assert.equal(result.phases.prove.elapsedSeconds, null);
  assert.equal(result.phases.prove.finishedAt, null);
});

test('missing, invalid, future, and reversed timestamps never yield negative or NaN durations', () => {
  const now = at('2026-10-16T13:00:00.000Z');
  for (const bad of [undefined, null, '', 'not-a-date', '2026-02-30T12:00:00Z',
    '2026-10-16T24:00:00Z', '2026-10-16T12:00:00', 0, '2026-10-16T14:00:00Z']) {
    const result = proofTimings({ startedAt: bad, status: 'running' }, now);
    assert.equal(result.startedAt, null);
    assert.equal(result.elapsedSeconds, null);
    assert.equal(result.elapsedHuman, null);
  }
  for (const bad of ['not-a-date', '2026-10-16T14:00:00Z']) {
    const result = proofTimings({ startedAt, finishedAt: bad, status: 'running' }, now);
    assert.equal(result.finishedAt, null);
    assert.equal(result.completed, false);
    assert.equal(result.elapsedSeconds, null);
  }
  const reversed = proofTimings({ startedAt, finishedAt: '2026-10-16T11:59:59Z' }, now);
  assert.equal(reversed.elapsedSeconds, null);
  assert.equal(reversed.elapsedHuman, null);
  assert.equal(proofTimings({}, now).elapsedSeconds, null);
  assert.equal(proofTimings(null, now).elapsedSeconds, null);
  assert.equal(proofTimings({ startedAt }, NaN).elapsedSeconds, null);
});

test('wall time includes overnight sleep and preserves exact ISO timestamp strings', () => {
  const report = { startedAt: '2026-10-16T23:00:00+02:00',
    finishedAt: '2026-10-17T09:00:00+02:00', status: 'complete' };
  const result = proofTimings(report, at('2026-10-18T00:00:00Z'));
  assert.equal(result.startedAt, report.startedAt);
  assert.equal(result.finishedAt, report.finishedAt);
  assert.equal(result.elapsedSeconds, 36000);
  assert.equal(result.elapsedHuman, '10:00:00');
});

test('duration formatting supports unbounded hours without rounding up', () => {
  assert.equal(formatDuration(0), '00:00:00');
  assert.equal(formatDuration(59.999), '00:00:59');
  assert.equal(formatDuration(360000), '100:00:00');
  for (const value of [-1, NaN, Infinity, null, undefined, '60', Number.MAX_SAFE_INTEGER + 1]) {
    assert.equal(formatDuration(value), null);
  }
});
