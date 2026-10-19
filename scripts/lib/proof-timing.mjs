const TERMINAL_STATUSES = new Set(['complete', 'failed', 'interrupted']);

// Proof reports use ISO wall-clock timestamps. Requiring an explicit timezone
// avoids interpreting a saved run differently on a second computer.
function timestamp(value, nowMillis) {
  if (typeof value !== 'string' || !Number.isFinite(nowMillis)) return null;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (!match) return null;
  const [, yearText, monthText, dayText, hourText, minuteText, secondText] = match;
  const [year, month, day, hour, minute, second] =
    [yearText, monthText, dayText, hourText, minuteText, secondText].map(Number);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12 || day < 1 || day > days[month - 1]
      || hour > 23 || minute > 59 || second > 59) return null;
  const millis = Date.parse(value);
  return Number.isFinite(millis) && millis <= nowMillis ? { value, millis } : null;
}

export function formatDuration(seconds) {
  if (typeof seconds !== 'number' || !Number.isFinite(seconds) || seconds < 0) return null;
  const wholeSeconds = Math.floor(seconds);
  if (!Number.isSafeInteger(wholeSeconds)) return null;
  const hours = Math.floor(wholeSeconds / 3600);
  const minutes = Math.floor((wholeSeconds % 3600) / 60);
  const remainder = wholeSeconds % 60;
  return [hours, minutes, remainder].map(value => String(value).padStart(2, '0')).join(':');
}

function interval(record, nowMillis, parentFinished = false) {
  const start = timestamp(record?.startedAt, nowMillis);
  const finish = timestamp(record?.finishedAt, nowMillis);
  const hasInvalidFinish = record?.finishedAt != null && !finish;
  // A stopped job with a missing finish record has an unknown duration. The
  // run's finish also cannot stand in for a missing individual phase finish.
  const mayBeRunning = !TERMINAL_STATUSES.has(record?.status) && !parentFinished;
  const end = finish?.millis ?? (!hasInvalidFinish && mayBeRunning ? nowMillis : null);
  const elapsedSeconds = start && end != null && end >= start.millis
    ? Math.floor((end - start.millis) / 1000) : null;
  return {
    startedAt: start?.value ?? null,
    finishedAt: finish?.value ?? null,
    elapsedSeconds,
    elapsedHuman: formatDuration(elapsedSeconds),
    // Duration completion says nothing about cryptographic proof success.
    completed: Boolean(finish),
  };
}

export function proofTimings(report, nowMillis = Date.now()) {
  const run = interval(report, nowMillis);
  const parentFinished = run.completed || TERMINAL_STATUSES.has(report?.status);
  const phases = report?.phases && typeof report.phases === 'object' && !Array.isArray(report.phases)
    ? Object.fromEntries(Object.entries(report.phases).map(([name, phase]) =>
      [name, interval(phase, nowMillis, parentFinished)]))
    : {};
  return { ...run, phases };
}
