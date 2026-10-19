import { readFile, writeFile, rename, mkdir } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { resolve, dirname, relative } from 'node:path';
import { createHash } from 'node:crypto';
import { ContractFactory, keccak256, toUtf8Bytes } from 'ethers';
import { sepoliaProvider } from './config.mjs';
import { linkCreationBytecode, assertRuntimeMatchesArtifact, PINNED_OPENVM } from './lib/verifier-stack.mjs';

// Public source verification only. No signer, private key, transaction or
// application/proving input is read. `prepare` never submits sources.
const [command = 'prepare'] = process.argv.slice(2);
if (!['prepare', 'submit', 'check'].includes(command) || process.argv.length > 3) {
  throw new Error('Usage: node scripts/verify-verifiers-sourcify.mjs prepare|submit|check');
}
const deploymentPath = resolve('deployments/verifiers-sepolia.json');
const reportPath = resolve('deployments/verifier-source-verification.json');
const inputDirectory = resolve('.pilot/verifier-sourcify-inputs');
const API = 'https://sourcify.dev/server';
const headers = { 'Content-Type': 'application/json',
  'User-Agent': 'interfold-sepolia-pilot/1.0 (+https://sepolia.etherscan.io/address/0xabF398A8e62CD68137987C4b99C0f24a5FDcd97a)' };
const run = promisify(execFile);
const hash = bytes => '0x' + createHash('sha256').update(bytes).digest('hex');
const deployment = JSON.parse(await readFile(deploymentPath, 'utf8'));
if (deployment.chainId !== 11155111 || deployment.forkTest || Object.keys(deployment.contracts ?? {}).length !== 8
    || deployment.status !== 'verifiers-deployed-fixture-validated-program-deferred') {
  throw new Error('Expected all eight completed live Sepolia verifier deployments');
}
let report;
try { report = JSON.parse(await readFile(reportPath, 'utf8')); }
catch (error) {
  if (error.code !== 'ENOENT') throw error;
  report = { schemaVersion: 1, chainId: 11155111, publicSourcesOnly: true, contracts: {} };
}

async function save() {
  report.updatedAt = new Date().toISOString();
  await writeFile(reportPath + '.tmp', JSON.stringify(report, null, 2) + '\n');
  await rename(reportPath + '.tmp', reportPath);
}

async function artifactFor(label) {
  const contract = deployment.contracts[label];
  const bytes = await readFile(resolve(dirname(deploymentPath), contract.artifactPath));
  if (hash(bytes) !== contract.artifactSha256) throw new Error(`${label}: deployed compiler artifact changed`);
  return JSON.parse(bytes.toString('utf8'));
}

const libraries = { RelationsLib: deployment.contracts.relations.address,
  ZKTranscriptLib: deployment.contracts.zkTranscript.address };
const forgeInputs = new Map();

async function normalInput(label, artifact) {
  const metadata = typeof artifact.metadata === 'string' ? JSON.parse(artifact.metadata) : artifact.metadata;
  const targets = Object.entries(metadata.settings.compilationTarget);
  if (targets.length !== 1) throw new Error(`${label}: ambiguous compilation target`);
  const [source, name] = targets[0];
  const identifier = `${source}:${name}`;
  if (!forgeInputs.has(identifier)) forgeInputs.set(identifier, (async () => {
    const { stdout } = await run('forge', ['verify-contract', '--show-standard-json-input', '--chain', '11155111',
      '--compiler-version', metadata.compiler.version, deployment.contracts[label].address, identifier],
    { encoding: 'utf8', maxBuffer: 10 * 1024 * 1024, timeout: 90_000 });
    return JSON.parse(stdout);
  })());
  const input = structuredClone(await forgeInputs.get(identifier));
  for (const [path, expected] of Object.entries(metadata.sources)) {
    if (!path.startsWith('src/') || typeof input.sources[path]?.content !== 'string'
        || keccak256(toUtf8Bytes(input.sources[path].content)) !== expected.keccak256) {
      throw new Error(`${label}: public source bytes differ from frozen metadata: ${path}`);
    }
  }
  input.sources = Object.fromEntries(Object.keys(metadata.sources).map(path => [path, input.sources[path]]));
  input.settings = structuredClone(metadata.settings);
  delete input.settings.compilationTarget;
  input.settings.outputSelection = { '*': { '*': ['metadata', 'evm.bytecode.object', 'evm.deployedBytecode.object'] } };
  // These deployments were linked after compilation. Keep the original empty
  // libraries settings so metadata remains exact. Sourcify explicitly supports
  // extracting manual link addresses from on-chain bytecode; the report also
  // records them, and our independent runtime check compares each exact address.
  return { stdJsonInput: input, compilerVersion: metadata.compiler.version, contractIdentifier: identifier };
}

async function rawInput(artifact) {
  const paths = {
    'Halo2Verifier.sol': '0xff719f1af2f4caf06f0e7f33e2d62cf4d7ea6a888adf6f5f3c73b38b106ced79',
    'OpenVmHalo2Verifier.sol': '0x04cdb92efe1fbf5a64699b44d4ae9974e19b2b873ad942aa224820480246923b',
    'interfaces/IOpenVmHalo2Verifier.sol': '0x6ef185babd0e4d369f2409b87053a5352ac2ba8a669ea8315949663cd34c23a5',
  };
  const sources = {};
  for (const [path, expected] of Object.entries(paths)) {
    const bytes = await readFile(resolve('.tools/openvm-setup/halo2/src/v2.0-base', path));
    if (hash(bytes) !== expected) throw new Error(`Pinned OpenVM source differs: ${path}`);
    sources[`src/v2.0-base/${path}`] = { content: bytes.toString('utf8') };
  }
  if (artifact.sol_compiler_version !== '0.8.19') throw new Error('Raw OpenVM verifier compiler differs');
  // Exact paths and options from pinned OpenVM SDK crates/sdk/src/solidity.rs,
  // generate_halo2_verifier_solidity_with_version_name(..., "v2.0-base").
  return { compilerVersion: '0.8.19+commit.7dd6d404',
    contractIdentifier: 'src/v2.0-base/OpenVmHalo2Verifier.sol:OpenVmHalo2Verifier',
    stdJsonInput: { language: 'Solidity', sources, settings: JSON.parse(artifact.sol_compiler_options) } };
}

async function prepare() {
  const provider = await sepoliaProvider();
  await mkdir(inputDirectory, { recursive: true });
  try {
    for (const [label, contract] of Object.entries(deployment.contracts)) {
      const artifact = await artifactFor(label);
      const transaction = deployment.transactions.find(item => item.label === label);
      if (!transaction || transaction.status !== 'confirmed') throw new Error(`${label}: unconfirmed deployment`);
      const code = await provider.getCode(contract.address);
      if (keccak256(code) !== contract.runtimeCodeHash) throw new Error(`${label}: runtime hash differs`);
      const isRaw = label === 'halo2';
      if (isRaw) {
        if (contract.artifactSha256 !== PINNED_OPENVM.verifierArtifactSha256
            || keccak256(code) !== PINNED_OPENVM.rawRuntimeCodeHash) throw new Error('Unpinned raw Halo2 verifier');
      } else assertRuntimeMatchesArtifact(artifact, code, libraries);
      const bytecode = isRaw ? '0x' + artifact.bytecode : linkCreationBytecode(artifact, libraries);
      const factory = new ContractFactory(isRaw ? [] : artifact.abi, bytecode);
      const expected = await factory.getDeployTransaction(...contract.constructorArgs);
      const sent = await provider.getTransaction(transaction.hash);
      if (!sent || sent.data.toLowerCase() !== expected.data.toLowerCase()) throw new Error(`${label}: creation bytecode differs`);
      let payload;
      try { payload = isRaw ? await rawInput(artifact) : await normalInput(label, artifact); }
      catch (error) {
        if (!isRaw) throw error;
        report.contracts[label] = { address: contract.address, status: 'unsupported-local-source-preparation',
          reason: error.message, pinnedCreationAndRuntimeIndependentlyMatched: true };
        await save();
        continue;
      }
      payload.creationTransactionHash = transaction.hash;
      const encoded = JSON.stringify(payload, null, 2) + '\n';
      const inputSha256 = hash(encoded);
      const previous = report.contracts[label];
      if (previous?.inputSha256 && previous.inputSha256 !== inputSha256) throw new Error(`${label}: prepared input changed`);
      const inputPath = resolve(inputDirectory, label + '.json');
      await writeFile(inputPath, encoded);
      report.contracts[label] = { ...previous, address: contract.address, creationTransactionHash: transaction.hash,
        compilerVersion: payload.compilerVersion, contractIdentifier: payload.contractIdentifier,
        inputPath: relative(process.cwd(), inputPath), inputSha256, sourcePaths: Object.keys(payload.stdJsonInput.sources),
        resolvedLibraries: label === 'encryptionVerifier' ? libraries : {},
        manualLinkingPreservesOriginalMetadata: label === 'encryptionVerifier',
        pinnedCreationAndRuntimeIndependentlyMatched: true,
        status: previous?.status ?? 'prepared', url: `https://repo.sourcify.dev/11155111/${contract.address}` };
      await save();
      console.log(`${label}: prepared ${payload.compilerVersion} ${payload.contractIdentifier}`);
    }
  } finally { provider.destroy(); }
}

async function request(path, options = {}) {
  const response = await fetch(API + path, { ...options, headers, signal: AbortSignal.timeout(45_000) });
  let body;
  try { body = await response.json(); } catch { body = { message: 'Non-JSON Sourcify response' }; }
  if (response.status === 429 || response.status >= 500) {
    // Persist and stop; a later invocation can retry after the server's delay.
    const error = new Error(`Sourcify HTTP ${response.status}; retry later`);
    error.response = body; error.retryAfter = response.headers.get('Retry-After'); throw error;
  }
  return { status: response.status, body };
}

async function check() {
  for (const [label, item] of Object.entries(report.contracts)) {
    if (item.status === 'verified' || item.status === 'verification-failed' || item.status.startsWith('unsupported')) continue;
    try {
      const response = item.verificationId
        ? await request(`/v2/verify/${encodeURIComponent(item.verificationId)}`)
        : item.submission?.status === 409 ? await request(`/v2/contract/11155111/${item.address}`) : null;
      if (!response) continue;
      item.lastCheckAt = new Date().toISOString();
      item.result = response;
      const result = item.verificationId ? response.body.contract : response.body;
      if (response.body.error) item.status = 'verification-failed';
      else if (result?.runtimeMatch && result?.creationMatch) item.status = 'verified';
      else item.status = response.body.isJobCompleted ? 'verification-incomplete' : 'pending';
      console.log(`${label}: ${item.status}${result?.runtimeMatch ? ` (runtime ${result.runtimeMatch}; creation ${result.creationMatch})` : ''}`);
      await save();
    } catch (error) {
      item.lastRequestError = error.message;
      item.retryAfter = error.retryAfter;
      await save(); throw error;
    }
  }
}

try {
  if (command !== 'check') await prepare();
  if (command === 'submit') {
    for (const [label, item] of Object.entries(report.contracts)) {
      if (item.verificationId || item.status === 'verified' || item.submission?.status === 409 || item.status.startsWith('unsupported')) continue;
      const bytes = await readFile(item.inputPath);
      if (hash(bytes) !== item.inputSha256) throw new Error(`${label}: prepared public input changed`);
      item.status = 'submitting'; await save();
      const response = await request(`/v2/verify/11155111/${item.address}`, { method: 'POST', body: bytes });
      item.submission = response;
      item.verificationId = response.body.verificationId;
      item.status = item.verificationId ? 'pending' : response.status === 409 ? 'already-verified-check-required' : 'submission-failed';
      await save();
      console.log(`${label}: ${item.status}${item.verificationId ? ` ${item.verificationId}` : ''}`);
    }
    await check();
  } else if (command === 'check') await check();
  report.allEightSourcesVerified = Object.keys(report.contracts).length === 8
    && Object.values(report.contracts).every(item => item.status === 'verified');
  await save();
} catch (error) {
  report.lastError = error.message;
  if (error.response) report.lastErrorResponse = error.response;
  if (error.retryAfter) report.retryAfter = error.retryAfter;
  await save();
  console.error(`Source verification stopped: ${error.message}`);
  process.exitCode = 1;
}
