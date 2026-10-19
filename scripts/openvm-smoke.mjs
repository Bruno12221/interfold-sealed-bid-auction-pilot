import { spawnSync } from 'node:child_process';
import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve, join } from 'node:path';
import assert from 'node:assert/strict';
import { proveApplication } from './openvm-application-proof.mjs';

const bundle = process.argv[2];
if (!bundle) throw new Error('Usage: node scripts/openvm-smoke.mjs BUNDLE_DIRECTORY [--prove-app]');
const base = resolve('pilot/auction-compute');
let tool = process.env.CARGO_OPENVM_BIN || join(base, '.tools/openvm/bin/cargo-openvm');
try { await access(tool); } catch { tool = 'cargo-openvm'; }
const out = resolve('.pilot/openvm');
await mkdir(out, { recursive: true, mode: 0o700 });
const env = { ...process.env, OPENVM_BUILD_LOCKED: '1',
  RUSTFLAGS: `${process.env.RUSTFLAGS ?? ''} --cfg crisp_openvm --cfg crisp_fhe_optimized` };
try { await access(join(base, '.tools/rustup/settings.toml')); if (!process.env.RUSTUP_HOME) env.RUSTUP_HOME = join(base, '.tools/rustup'); } catch {}
function run(action, args) {
  console.log(`OpenVM: ${action}`);
  const result = spawnSync(tool, ['openvm', ...args], { encoding: 'utf8', env, maxBuffer: 16 * 1024 * 1024 });
  if (result.error) throw result.error;
  const log = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
  return { result, log };
}
async function step(action, args) {
  const { result, log } = run(action, args);
  await writeFile(join(out, `${action}.log`), log);
  if (result.status !== 0) throw new Error(`OpenVM ${action} failed; see ${join(out, `${action}.log`)}`);
  return log;
}
const framed = await readFile(join(bundle, 'input.bin'));
if (framed.length > 30_000_000 || framed.length < 4) throw new Error('Invalid framed input size');
const count = framed.readUInt32LE(0);
if (count < 3 || count > 65 || count % 2 === 0) throw new Error('Expected header and two passes over 1–32 ciphertexts');
let offset = 4;
const input = [];
for (let i = 0; i < count; ++i) {
  if (offset + 8 > framed.length) throw new Error('Truncated item length');
  const length = framed.readBigUInt64LE(offset); offset += 8;
  if (length > BigInt(framed.length - offset)) throw new Error('Truncated guest item');
  input.push('0x01' + framed.subarray(offset, offset + Number(length)).toString('hex'));
  offset += Number(length);
}
if (offset !== framed.length) throw new Error('Trailing framed input data');
const cliInput = join(out, 'cli-input.json');
await writeFile(cliInput, JSON.stringify({ input }));
const manifest = join(base, 'guest/Cargo.toml');
const config = join(base, 'guest/openvm.toml');
const exe = join(out, 'build/interfold-auction-guest.vmexe');
await step('build', ['build', '--manifest-path', manifest, '--config', config,
  '--target-dir', join(base, '.tools/guest-target'), '--output-dir', join(out, 'build')]);
const execution = await step('execute', ['run', '--manifest-path', manifest, '--config', config, '--exe', exe, '--input', cliInput]);
const values = execution.match(/Execution output: (\[[^\n]*\])/);
if (!values) throw new Error('Missing guest public output');
const journal = await readFile(join(bundle, 'journal.bin'));
assert.equal(journal.length, 288);
const expected = createHash('sha256').update(journal).digest();
assert.deepEqual(Buffer.from(JSON.parse(values[1])), expected);
const report = { checkedAt: new Date().toISOString(), guestBuilt: true, guestExecuted: true,
  publicJournalDigestMatches: true, journalSha256: expected.toString('hex'),
  executableSha256: createHash('sha256').update(await readFile(exe)).digest('hex'),
  applicationProofVerified: false, evmReceiptGenerated: false, inputProofGenerated: false, thresholdNetworkUsed: false };
if (process.argv.includes('--prove-app')) {
  const keys = join(out, 'keys');
  await step('keygen', ['keygen', '--manifest-path', manifest, '--config', config, '--app-only', '--output-dir', keys]);
  const verified = await proveApplication({ manifest, exe, keys, input: cliInput,
    journal: resolve(bundle, 'journal.bin'), output: process.env.OPENVM_PROOF_OUTPUT || join(out, 'application-proof') });
  report.applicationProofVerified = true;
  report.exactExecutableCommitmentVerified = true;
  report.applicationExecutableCommitment = verified.applicationExecutableCommitment;
  report.applicationProofSha256 = verified.applicationProofSha256;
  report.caveat = 'Application STARK proof only. Real EVM receipt requires recursive aggregation/Halo2 setup, exact image identity and on-chain verification.';
}
await writeFile(join(out, 'validation.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
