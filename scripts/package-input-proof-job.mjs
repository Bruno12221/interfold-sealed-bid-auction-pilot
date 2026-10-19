import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { copyFile, lstat, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AbiCoder, ZeroAddress, getAddress, getBytes, keccak256 } from 'ethers';
import { CHAIN_ID, PROTOCOL } from './config.mjs';
import { PINNED_OPENVM } from './lib/verifier-stack.mjs';
import { SECURE_PARAMS_HASH } from './lib/program-plan.mjs';
import { setupArtifactUrls } from './package-root-handoff.mjs';

const REVISION = '59a69b8b0cbee7011ac978e4cc07707ee3681944';
const WORKER_FILES = ['Cargo.toml', 'Cargo.lock', 'LICENSE.md', 'NOTICE.md', 'README.md', 'fetch-setup.py', 'src/main.rs'];
const ARTIFACTS = ['app.pk', 'guest.vmexe', 'aggregation.pk', 'identity.json', 'verifier.bytecode.json'];
const NAMES = ['chainId', 'program', 'interfold', 'auction', 'context', 'e3Id', 'committeePublicKey', 'paramsHash', 'slot', 'bidder', 'maxTick', 'ciphertextHash', 'ciphertextCommitment'];
const TYPES = ['uint256', 'address', 'address', 'address', 'bytes32', 'uint256', 'bytes32', 'bytes32', 'uint256', 'address', 'uint256', 'bytes32', 'bytes32'];
const CONFIG_FIELDS = ['app_pk', 'executable', 'aggregation_pk', 'verifier_artifact', 'halo2_pk', 'halo2_params_dir', 'verifier_sha256', 'app_commit', 'segment_memory_bytes'];
const HEX_HASH = /^[0-9a-f]{64}$/;

function exact(value, names, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).sort().join() !== [...names].sort().join()) throw new Error(`Unexpected ${label} fields; refusing unknown data`);
}

async function fingerprint(path, maximum = 64 * 1024 * 1024) {
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink() || info.size > maximum) throw new Error(`Not a bounded regular public file: ${path}`);
  const digest = createHash('sha256');
  for await (const bytes of createReadStream(path)) digest.update(bytes);
  return { bytes: info.size, sha256: digest.digest('hex') };
}

async function json(path) {
  await fingerprint(path, 1024 * 1024);
  return JSON.parse(await readFile(path, 'utf8'));
}

async function publicInput(statementPath, publicBundle) {
  const statement = await json(statementPath);
  exact(statement, NAMES, 'public statement');
  for (const name of ['chainId', 'e3Id', 'slot', 'maxTick']) {
    if (typeof statement[name] !== 'string' || !/^(0|[1-9][0-9]*)$/.test(statement[name])) throw new Error('Noncanonical public statement integer');
  }
  if (statement.chainId !== String(CHAIN_ID) || getAddress(statement.interfold) !== PROTOCOL
    || statement.paramsHash !== SECURE_PARAMS_HASH || statement.maxTick !== '100' || BigInt(statement.slot) >= 32n
    || ['program', 'auction', 'bidder'].some(name => getAddress(statement[name]) === ZeroAddress)) throw new Error('Unexpected public input domain');
  const encoded = Buffer.from(getBytes(AbiCoder.defaultAbiCoder().encode(TYPES, NAMES.map(name => statement[name]))));
  const journalPath = join(publicBundle, 'statement.bin'), inputPath = join(publicBundle, 'input.bin');
  await fingerprint(journalPath, 416); await fingerprint(inputPath, 1_001_000);
  if (!encoded.equals(await readFile(journalPath))) throw new Error('Public statement journal differs');
  const framed = await readFile(inputPath);
  if (framed.length < 436 || framed.readUInt32LE(0) !== 2 || framed.readBigUInt64LE(4) !== 416n
    || !framed.subarray(12, 428).equals(encoded)) throw new Error('Unexpected public binding input framing');
  const ctLength = framed.readBigUInt64LE(428);
  if (ctLength <= 0n || ctLength > 1_000_000n || BigInt(framed.length) !== 436n + ctLength
    || keccak256(framed.subarray(436)) !== statement.ciphertextHash) throw new Error('Public ciphertext length/hash differs');
  return { statement, inputPath, journalPath };
}

async function trustedArtifacts(handoff) {
  const original = await json(join(handoff, 'bundle-manifest.json'));
  if (original.schemaVersion !== 1 || original.openvmRevision !== REVISION || original.openvmVersion !== '2.0.2') throw new Error('Wrong original public handoff');
  const names = ['SETUP-SOURCES.json', 'jobs/binding/config.template.json', ...ARTIFACTS.map(name => 'jobs/binding/' + name)];
  for (const name of names) {
    const expected = original.files?.[name];
    if (!expected || !HEX_HASH.test(expected.sha256 ?? '') || JSON.stringify(await fingerprint(join(handoff, name))) !== JSON.stringify(expected)) throw new Error(`Trusted handoff artifact differs: ${name}`);
  }
  const setup = await json(join(handoff, 'SETUP-SOURCES.json'));
  const urls = setupArtifactUrls();
  if (setup.schemaVersion !== 1 || setup.openvmVersion !== '2.0.2') throw new Error('Wrong setup manifest');
  exact(setup.artifacts, Object.keys(urls), 'public setup artifact list');
  for (const [name, url] of Object.entries(urls)) {
    const entry = setup.artifacts[name];
    exact(entry, ['url', 'bytes', 'sha256'], 'public setup entry');
    if (entry.url !== url || !HEX_HASH.test(entry.sha256 ?? '') || !Number.isSafeInteger(entry.bytes)
      || entry.bytes < 1 || entry.bytes > 11_000_000_000) throw new Error('Unexpected setup artifact identity');
  }
  const config = await json(join(handoff, 'jobs/binding/config.template.json'));
  exact(config, CONFIG_FIELDS, 'public worker configuration');
  const identity = await json(join(handoff, 'jobs/binding/identity.json'));
  exact(identity, ['app_commit'], 'prepared identity');
  exact(identity.app_commit, ['app_exe_commit', 'app_vm_commit'], 'application commitments');
  if (identity.app_commit.app_exe_commit !== PINNED_OPENVM.bindingExeCommit || identity.app_commit.app_vm_commit !== PINNED_OPENVM.vmCommit
    || JSON.stringify(config.app_commit) !== JSON.stringify(identity.app_commit)) throw new Error('Wrong binding executable/VM identity');
  const verifier = original.files['jobs/binding/verifier.bytecode.json'].sha256;
  if (verifier !== PINNED_OPENVM.verifierArtifactSha256.slice(2) || config.verifier_sha256 !== verifier
    || setup.artifacts['halo2/src/v2.0-base/verifier.bytecode.json'].sha256 !== verifier) throw new Error('Wrong pinned verifier');
  if (!Number.isSafeInteger(config.segment_memory_bytes) || config.segment_memory_bytes <= 0 || config.segment_memory_bytes > 2147483648) throw new Error('Unexpected application segment memory limit');
  return { original, setup, config, identity };
}

// Only these explicitly named public files are read/copied. No directory traversal,
// encryption witness, private Noir proving directory or old proof checkpoint is copied.
export async function packageInputProofJob({ output, statement, publicBundle, trustedHandoff, worker,
  runner = fileURLToPath(new URL('./lib/input-proof-job.py', import.meta.url)),
  instructions = fileURLToPath(new URL('../docs/INPUT-PROOF-JOB.md', import.meta.url)) }) {
  const input = await publicInput(statement, publicBundle);
  const trusted = await trustedArtifacts(trustedHandoff);
  if (!(await readFile(join(worker, 'src/main.rs'), 'utf8')).includes('"prove-app"')) throw new Error('Worker does not support staged application proving');
  output = resolve(output);
  await mkdir(output, { mode: 0o700 });
  const files = {};
  async function put(name, source, content) {
    const target = join(output, name);
    await mkdir(dirname(target), { recursive: true, mode: 0o700 });
    const before = source ? await fingerprint(source) : null;
    if (source) await copyFile(source, target, 1);
    else await writeFile(target, content, { flag: 'wx', mode: 0o600 });
    files[name] = await fingerprint(target);
    if (before && JSON.stringify(before) !== JSON.stringify(files[name])) throw new Error('Public source changed while packaging');
  }
  for (const name of WORKER_FILES) await put('worker/' + name, join(worker, name));
  await put('run-proof.py', runner);
  await put('README.md', instructions);
  await put('run-ubuntu.sh', null, LAUNCHER);
  await put('SETUP-SOURCES.json', join(trustedHandoff, 'SETUP-SOURCES.json'));
  for (const name of ARTIFACTS) {
    await put('job/' + name, join(trustedHandoff, 'jobs/binding', name));
    if (files['job/' + name].sha256 !== trusted.original.files['jobs/binding/' + name].sha256) throw new Error('Trusted artifact changed while packaging');
  }
  await put('job/statement.json', statement);
  await put('job/input.bin', input.inputPath);
  await put('job/journal.bin', input.journalPath);
  const config = { ...trusted.config, app_pk: 'job/app.pk', executable: 'job/guest.vmexe', aggregation_pk: 'job/aggregation.pk',
    verifier_artifact: 'job/verifier.bytecode.json', halo2_pk: '@SETUP@/halo2.pk', halo2_params_dir: '@SETUP@/params' };
  await put('job/config.template.json', null, JSON.stringify(config, null, 2) + '\n');
  const manifest = { schemaVersion: 1, scope: 'public-input-binding-proof-job', createdAt: new Date().toISOString(),
    openvmVersion: '2.0.2', openvmRevision: REVISION, app_commit: trusted.identity.app_commit,
    stages: ['prove-app', 'aggregate-stark', 'prove-root', 'compress-root', 'verify-seal'],
    publicInputDescription: 'The exact public 416-byte statement and framed BFV ciphertext. No encryption randomness, private key or private witness is included.',
    knownAnswer: { program: input.statement.program, programAddressConditionalOnUnchangedNonce: true,
      contextIsSynthetic: true, liveAuctionProof: false, requiresRegenerationIfProgramAddressChanges: true },
    checkpointReuse: 'No old proof/root checkpoint included. New stages authenticate this exact journal and configured application identity.',
    files };
  await writeFile(join(output, 'bundle-manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return { output, files: Object.keys(files).length + 1, bytes: Object.values(files).reduce((n, f) => n + f.bytes, 0),
    manifestSha256: (await fingerprint(join(output, 'bundle-manifest.json'))).sha256,
    journalSha256: files['job/journal.bin'].sha256, program: input.statement.program, liveAuctionProof: false };
}

const LAUNCHER = `#!/usr/bin/env bash
set -euo pipefail
umask 077
input_proof_directory="$(cd -- "$(dirname -- "\${BASH_SOURCE[0]}")" && pwd -P)"
cd "$input_proof_directory"
input_proof_setup=()
input_proof_resume=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --setup) [[ $# -ge 2 ]] || exit 2; input_proof_setup=(--setup "$2"); shift 2 ;;
    --resume) input_proof_resume=(--resume); shift ;;
    *) printf '%s\\n' 'Usage: bash run-ubuntu.sh [--setup EXISTING_SETUP] [--resume]' >&2; exit 2 ;;
  esac
done
python3 run-proof.py configure --bundle-only
if [[ \${#input_proof_resume[@]} -eq 0 ]]; then
  input_proof_privilege=()
  if [[ "$(id -u)" != 0 ]]; then input_proof_privilege=(sudo); fi
  "\${input_proof_privilege[@]}" apt-get update
  "\${input_proof_privilege[@]}" apt-get install -y build-essential pkg-config libssl-dev clang cmake git curl ca-certificates python3 procps util-linux
  python3 -c 'import sys; assert sys.version_info >= (3, 9), "Python3.9+ required"'
  if [[ -f "$HOME/.cargo/env" ]]; then source "$HOME/.cargo/env"; fi
  if ! command -v rustup >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none
    source "$HOME/.cargo/env"
  fi
  rustup toolchain install 1.93.0 --profile minimal
  { date --iso-8601=seconds; uname -a; lscpu; free -h; df -h .; rustc +1.93.0 --version; cargo +1.93.0 --version; } > host-info.txt
  cargo +1.93.0 build --locked --release --jobs 4 --manifest-path worker/Cargo.toml --target-dir target 2>&1 | tee build.log
  python3 -u run-proof.py configure "\${input_proof_setup[@]}"
fi
python3 -u run-proof.py run --threads 4 "\${input_proof_resume[@]}"
python3 run-proof.py archive
`;

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length > 3) throw new Error('Usage: node scripts/package-input-proof-job.mjs [NEW_OUTPUT_DIRECTORY]');
  const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
  console.log(JSON.stringify(await packageInputProofJob({ output: process.argv[2] || join(root, '.pilot/Ubuntu-InputProof-20261018'),
    statement: join(root, '.pilot/release-known-answer-20261018/statement.json'),
    publicBundle: join(root, '.pilot/release-known-answer-20261018/binding-public-bundle'),
    trustedHandoff: join(root, '.pilot/halo2-handoff-20261018'), worker: join(root, 'pilot/openvm-prover') }), null, 2));
}
