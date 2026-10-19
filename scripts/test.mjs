import { spawnSync } from 'node:child_process';
for (const [command, args] of [['forge', ['test', '-vv']], [process.execPath, ['--test', 'test/auction-codec.test.mjs', 'test/release.test.mjs', 'test/openvm-proof-process.test.mjs', 'test/proof-timing.test.mjs', 'test/openvm-proof-timing.test.mjs', 'test/openvm-receipt-stages.test.mjs', 'test/root-handoff.test.mjs', 'test/verifier-stack.test.mjs', 'test/program-plan.test.mjs', 'test/input-proof-job.test.mjs']]]) {
  const result = spawnSync(command, args, { stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}
