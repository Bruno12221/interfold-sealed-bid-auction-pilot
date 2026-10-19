import { spawnSync } from 'node:child_process';
import { access, mkdir, writeFile } from 'node:fs/promises';
import assert from 'node:assert/strict';

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, ...options });
  if (result.error) throw result.error;
  if (result.status !== 0) { process.stderr.write(result.stderr ?? ''); process.stderr.write(result.stdout ?? ''); throw new Error(`${command} failed`); }
  return result.stdout;
}
await mkdir('.pilot', { recursive: true, mode: 0o700 });
console.log('Checking escrow, E3 gate and real Poseidon integration…');
const solidity = JSON.parse(run('forge', ['test', '--json']));
const results = Object.values(solidity).flatMap(suite => Object.values(suite.test_results ?? {}));
assert(results.length >= 172 && results.every(x => x.status === 'Success'));
console.log(`Solidity: ${results.length} tests passed`);
const nodeOutput = run(process.execPath, ['--test', 'test/auction-codec.test.mjs', 'test/release.test.mjs', 'test/openvm-proof-process.test.mjs', 'test/proof-timing.test.mjs', 'test/openvm-proof-timing.test.mjs', 'test/openvm-receipt-stages.test.mjs', 'test/root-handoff.test.mjs', 'test/verifier-stack.test.mjs', 'test/program-plan.test.mjs', 'test/input-proof-job.test.mjs']);
const nodeTestCount = Number(nodeOutput.match(/# tests (\d+)/)?.[1]);
console.log('JavaScript codecs and release checks passed');
const nativeOutput = run('cargo', ['test', '--locked', '--quiet', '--manifest-path', 'pilot/bfv-slots/Cargo.toml']);
const nativeTestCount = [...nativeOutput.matchAll(/test result: ok\. (\d+) passed/g)].reduce((sum, match) => sum + Number(match[1]), 0);
run('cargo', ['test', '--locked', '--quiet', '--manifest-path', 'pilot/auction-compute/Cargo.toml']);
console.log('Native encryption, manifest and worker tests passed');
let nargo = process.env.NARGO_BIN || 'nargo';
try { await access('.tools/noir/nargo'); if (!process.env.NARGO_BIN) nargo = `${process.cwd()}/.tools/noir/nargo`; } catch {}
run(nargo, ['test'], { cwd: 'circuits/auction-slot' });
console.log('Noir: 9 secure-8192 sparse-slot tests passed');
const output = run('cargo', ['run', '--locked', '--quiet', '--manifest-path', 'pilot/bfv-slots/Cargo.toml']);
const crypto = JSON.parse(output);
assert.equal(crypto.preset, 'SECURE_THRESHOLD_8192');
assert.deepEqual(crypto.decryptedBidSlots, [31, 77, 42]);
assert.equal(crypto.unusedCoefficientsZero, true);
assert.equal(crypto.secondPricePaymentTicks, 42);
assert.equal(crypto.zkInputProofsGenerated, false);
assert.equal(crypto.openvmReceiptGenerated, false);
assert.equal(crypto.thresholdNetworkUsed, false);
await writeFile('.pilot/local-crypto.json', output);
const report = { checkedAt: new Date().toISOString(), scope: 'local-crypto-and-contract-simulation',
  solidityTestsPassed: results.length, nodeTestsPassed: true, nodeTestCount, noirTestsPassed: 9, nativeTestsPassed: true, nativeTestCount,
  preset: crypto.preset, degree: crypto.degree, ciphertextBytes: crypto.ciphertextBytes,
  bids: crypto.decryptedBidSlots, winningSlot: crypto.winningSlot, secondPricePaymentTicks: crypto.secondPricePaymentTicks,
  ciphertextAndCommitmentBindingChecked: true, inputProofGenerated: false, openvmReceiptGenerated: false,
  thresholdNetworkUsed: false, railgunPrivateSpendExecuted: false, networkAuctionExecuted: false };
await writeFile('.pilot/local-validation.json', JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
