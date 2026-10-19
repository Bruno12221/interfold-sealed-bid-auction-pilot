import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { CIRCUIT_DIR, PINNED_INTERFOLD_COMMIT, REPO_DIR, assertPinnedSource, setup } from './setup.mjs';

// Every file written by nargo/bb inherits owner-only permissions, including the
// raw (non-zero-knowledge) ACVM witness and any diagnostics with private values.
process.umask(0o077);
const [privateWitness, statement, requestedDestination] = process.argv.slice(2);
if (!privateWitness || !statement || !requestedDestination || process.argv.length !== 5) {
  throw new Error('Usage: node circuits/auction-input/prove.mjs PRIVATE_JSON STATEMENT_JSON NEW_PRIVATE_DIRECTORY');
}
const destination = resolve(requestedDestination);
if (existsSync(destination)) throw new Error('Proof destination must be new');
const nargo = resolve(REPO_DIR, '.tools/noir/nargo');
const bb = resolve(REPO_DIR, '.tools/barretenberg/5.2.0/bb');
const circuit = resolve(CIRCUIT_DIR, 'target/auction_input.json');
const crs = resolve(REPO_DIR, '.tools/barretenberg/5.2.0/crs');
const hash = bytes => '0x' + createHash('sha256').update(bytes).digest('hex');
const runVersion = command => spawnSync(command, ['--version'], { encoding: 'utf8' });
if (!runVersion(nargo).stdout.startsWith('nargo version = 1.0.0-beta.26\n')) throw new Error('Unexpected Nargo version');
if (runVersion(bb).stdout.trim() !== '5.2.0') throw new Error('Unexpected Barretenberg version');
setup();
assertPinnedSource();
// Python's JSON parser preserves exact 59-bit coefficients, unlike JSON.parse.
const prepared = spawnSync('python3', [resolve(CIRCUIT_DIR, 'prepare-witness.py'),
  resolve(privateWitness), resolve(statement), destination], { encoding: 'utf8' });
if (prepared.status !== 0) throw new Error('Private witness preparation failed; diagnostics suppressed');
chmodSync(destination, 0o700);
mkdirSync(crs, { recursive: true });

const phases = {};
function run(phase, command, args, expectSuccess = true) {
  const logPath = resolve(destination, phase + '.log');
  const log = openSync(logPath, 'wx', 0o600);
  const start = Date.now();
  const result = spawnSync(command, args, {
    cwd: CIRCUIT_DIR, stdio: ['ignore', log, log],
    env: { ...process.env, HARDWARE_CONCURRENCY: '2' },
  });
  closeSync(log);
  phases[phase] = { seconds: (Date.now() - start) / 1000, exitCode: result.status };
  if (result.error || result.signal || result.status !== (expectSuccess ? 0 : 1)) {
    throw new Error(`Unexpected ${phase} outcome; private log retained`);
  }
}

run('compile', nargo, ['compile']);
run('execute', nargo, ['execute', '-p', resolve(destination, 'Prover'), resolve(destination, 'witness')]);
run('gates', bb, ['gates', '-b', circuit, '-t', 'evm']);
const proofDir = resolve(destination, 'evm-proof');
mkdirSync(proofDir, { mode: 0o700 });
run('prove', bb, ['prove', '-b', circuit, '-w', resolve(destination, 'witness.gz'),
  '-o', proofDir, '-t', 'evm', '--write_vk', '--verify', '--slow_low_memory',
  '--storage_budget', '8g', '-c', crs]);

const proof = readFileSync(resolve(proofDir, 'proof'));
const actualPublicInputs = readFileSync(resolve(proofDir, 'public_inputs'));
const expectedLimbs = JSON.parse(readFileSync(resolve(destination, 'public-inputs.json'), 'utf8'));
const expectedPublicInputs = Buffer.concat(expectedLimbs.map(value => Buffer.from(BigInt(value).toString(16).padStart(64, '0'), 'hex')));
if (!actualPublicInputs.equals(expectedPublicInputs)) throw new Error('Proof public inputs differ from exact statement');
const verifyArgs = ['verify', '-p', resolve(proofDir, 'proof'), '-i', resolve(proofDir, 'public_inputs'),
  '-k', resolve(proofDir, 'vk'), '-t', 'evm', '-c', crs];
run('verify', bb, verifyArgs);

const tamperedProof = Buffer.from(proof);
// bb5.2.0 EVM ZK layout: 8 pairing limbs, 10 curve commitments,
// one Libra sum, then the first sumcheck scalar. Change its low bit while
// preserving all curve points, so rejection exercises the proof relation.
tamperedProof[959] ^= 1;
writeFileSync(resolve(destination, 'tampered-proof'), tamperedProof, { flag: 'wx', mode: 0o600 });
run('reject-tampered-proof', bb, verifyArgs.map(value => value === resolve(proofDir, 'proof') ? resolve(destination, 'tampered-proof') : value), false);
const tamperedInputs = Buffer.from(actualPublicInputs);
// Change the low bit of the context high limb (public input 8), preserving
// canonical u128 encoding while holding the proof and every other word fixed.
tamperedInputs[8 * 32 + 31] ^= 1;
writeFileSync(resolve(destination, 'tampered-public-inputs'), tamperedInputs, { flag: 'wx', mode: 0o600 });
run('reject-changed-statement', bb, verifyArgs.map(value => value === resolve(proofDir, 'public_inputs') ? resolve(destination, 'tampered-public-inputs') : value), false);
run('solidity-verifier', bb, ['write_solidity_verifier', '-k', resolve(proofDir, 'vk'),
  '-o', resolve(destination, 'AuctionInputHonkVerifier.sol'), '-t', 'evm']);

const compiled = JSON.parse(readFileSync(circuit, 'utf8'));
const evidence = {
  schemaVersion: 1, interfoldCommit: PINNED_INTERFOLD_COMMIT,
  nargoVersion: '1.0.0-beta.26', bbVersion: '5.2.0', verifierTarget: 'evm',
  zeroKnowledge: true, publicInputCount: 26, proofBytes: proof.length,
  bytecodeSha256: hash(Buffer.from(compiled.bytecode, 'base64')),
  vkSha256: hash(readFileSync(resolve(proofDir, 'vk'))),
  proofSha256: hash(proof), statementSha256: hash(readFileSync(resolve(destination, 'statement.bin'))),
  validProofVerified: true, tamperedProofRejected: true, changedStatementRejected: true,
  serializationBindingProofVerified: false, composedInputProofReady: false,
  phases,
};
writeFileSync(resolve(destination, 'validation.json'), JSON.stringify(evidence, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
console.log(JSON.stringify(evidence));
