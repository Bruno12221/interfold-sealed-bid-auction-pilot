import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { AbiCoder, ZeroAddress, getAddress, id, isHexString, keccak256 } from 'ethers';

export const PINNED_OPENVM = Object.freeze({
  vmCommit: '0x009034802c4d22df352e22772fc613453a77e387b95479ef296bbef78edc588a',
  bindingExeCommit: '0x004ab89ac541e865a9e923b17383576c96451d9e3f2cba48c268265e780be415',
  computeExeCommit: '0x003e89acda47eb25b207e4284781fa9f0f900201af2457c47f7a41c5f4fdfede',
  verifierArtifactSha256: '0x6f2dac7ec5dd42fbff0d5a1e5ba99e3b53c005d94dc699b5dc4c50b0bd891b99',
  rawRuntimeCodeHash: '0xc164e9a2f1317f2babaccd3b14efe13a172225dbee3ffff0f95d5afda7b6b99c',
});

export const ACIR_SHA256 = '0xeb4c1699b4f25cf4bf86709095cb51c06d31acbf6cee16d6b7ce304770319eb6';

const ARTIFACT_PATHS = Object.freeze({
  RelationsLib: 'out/AuctionInputHonkVerifier.sol/RelationsLib.json',
  ZKTranscriptLib: 'out/AuctionInputHonkVerifier.sol/ZKTranscriptLib.json',
  HonkVerifier: 'out/AuctionInputHonkVerifier.sol/HonkVerifier.json',
  AuctionInputVerifier: 'out/AuctionInputVerifier.sol/AuctionInputVerifier.json',
  OpenVmReceiptVerifier: 'out/OpenVmReceiptVerifier.sol/OpenVmReceiptVerifier.json',
  AuctionPoseidon: 'out/AuctionPoseidon.sol/AuctionPoseidon.json',
});

const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const sha256 = bytes => '0x' + createHash('sha256').update(bytes).digest('hex');

export function assertVerifierNetworkMode(clientVersion, rpcUrl, fork) {
  const anvil = String(clientVersion).toLowerCase().includes('anvil');
  if (!fork && anvil) throw new Error('Anvil requires --fork-test; refusing a live-labeled fork record');
  if (fork) {
    const url = new URL(rpcUrl);
    if (!['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) || !anvil) {
      throw new Error('Fork test requires local Anvil');
    }
  }
}

export async function loadVerifierStackArtifacts(root = process.cwd(), artifactPaths = ARTIFACT_PATHS) {
  if (!object(artifactPaths) || Object.keys(artifactPaths).sort().join() !== Object.keys(ARTIFACT_PATHS).sort().join()
    || Object.values(artifactPaths).some(path => typeof path !== 'string' || !path)) {
    throw new Error('Expected the complete named compiler artifact set');
  }
  const entries = await Promise.all(Object.entries(artifactPaths).map(async ([name, path]) => {
    const artifactPath = resolve(root, path);
    const bytes = await readFile(artifactPath);
    const artifact = JSON.parse(bytes.toString('utf8'));
    if (!object(artifact) || !Array.isArray(artifact.abi)) throw new Error(`${name}: malformed build artifact`);
    bytecodeSection(artifact, 'bytecode');
    bytecodeSection(artifact, 'deployedBytecode');
    return [name, { ...artifact, artifactPath, artifactSha256: sha256(bytes), artifactBytes: bytes }];
  }));
  const artifactPath = resolve(root, 'test/fixtures/openvm-receipts/verifier.bytecode.json');
  const bytes = await readFile(artifactPath);
  const artifactSha256 = sha256(bytes);
  if (artifactSha256 !== PINNED_OPENVM.verifierArtifactSha256) {
    throw new Error('Raw Halo2 verifier artifact SHA-256 differs from the pinned OpenVM setup');
  }
  const raw = JSON.parse(bytes.toString('utf8'));
  if (raw.sol_compiler_version !== '0.8.19' || typeof raw.bytecode !== 'string'
      || !/^[0-9a-fA-F]+$/.test(raw.bytecode) || raw.bytecode.length !== 19_781 * 2) {
    throw new Error('Malformed pinned raw Halo2 verifier artifact');
  }
  entries.push(['rawHalo2', {
    abi: ['function verify(bytes publicValues,bytes proofData,bytes32 appExeCommit,bytes32 appVmCommit) view'],
    bytecode: '0x' + raw.bytecode,
    artifactPath,
    artifactSha256,
    expectedRuntimeCodeHash: PINNED_OPENVM.rawRuntimeCodeHash,
  }]);
  return Object.fromEntries(entries);
}

function bytecodeSection(artifact, field) {
  if (!object(artifact)) throw new Error('Malformed compiler artifact');
  const section = artifact[field];
  const value = typeof section === 'string' ? section : section?.object;
  if (typeof value !== 'string' || !value.startsWith('0x') || value.length <= 2 || value.length % 2 !== 0) {
    throw new Error(`Missing or malformed ${field} bytecode`);
  }
  if (typeof section !== 'string' && !object(section)) throw new Error(`Malformed ${field} section`);
  return { code: value.slice(2), references: typeof section === 'string' ? {} : section.linkReferences ?? {} };
}

function linkedBytecode(artifact, field, libraries) {
  const { code, references } = bytecodeSection(artifact, field);
  if (!object(libraries)) throw new Error('Libraries must be a name-to-address map');
  if (!object(references)) throw new Error(`Malformed ${field} link references`);
  const ranges = [];
  const librarySources = new Map();
  for (const [source, names] of Object.entries(references)) {
    if (!source || !object(names)) throw new Error(`Malformed ${field} library source references`);
    for (const [name, positions] of Object.entries(names)) {
      if (!name || !Array.isArray(positions) || positions.length === 0) {
        throw new Error(`Malformed link references for ${name}`);
      }
      if (librarySources.has(name) && librarySources.get(name) !== source) {
        throw new Error(`Ambiguous library name ${name}`);
      }
      librarySources.set(name, source);
      if (!Object.hasOwn(libraries, name)) throw new Error(`Missing library address: ${name}`);
      let address;
      try { address = getAddress(libraries[name]); }
      catch { throw new Error(`Invalid library address: ${name}`); }
      if (address === ZeroAddress) throw new Error(`Invalid zero library address: ${name}`);
      const placeholder = `__$${id(`${source}:${name}`).slice(2, 36)}$__`;
      for (const position of positions) {
        const range = checkedRange(position, code.length / 2, 20, `library ${name}`);
        if (code.slice(range.start * 2, range.end * 2).toLowerCase() !== placeholder.toLowerCase()) {
          throw new Error(`Unexpected library placeholder: ${name}`);
        }
        ranges.push({ ...range, replacement: address.slice(2).toLowerCase() });
      }
    }
  }
  assertNoOverlap(ranges, `${field} library`);
  let linked = code;
  // All replacements have the same width, preserving every compiler offset.
  for (const { start, end, replacement } of ranges) {
    linked = linked.slice(0, start * 2) + replacement + linked.slice(end * 2);
  }
  if (!/^[0-9a-fA-F]+$/.test(linked)) throw new Error(`Unresolved or malformed ${field} bytecode placeholders`);
  return { code: linked.toLowerCase(), ranges };
}

function checkedRange(position, codeLength, requiredLength, label) {
  if (!object(position) || !Number.isSafeInteger(position.start) || position.start < 0
      || position.length !== requiredLength || position.start > codeLength - position.length) {
    throw new Error(`Malformed or out-of-bounds ${label} reference`);
  }
  return { start: position.start, end: position.start + position.length };
}

function assertNoOverlap(ranges, label) {
  const ordered = [...ranges].sort((a, b) => a.start - b.start);
  for (let i = 1; i < ordered.length; ++i) {
    if (ordered[i].start < ordered[i - 1].end) throw new Error(`Overlapping ${label} references`);
  }
}

/// Link compiler-listed library locations only; unused shared-map entries are harmless.
export function linkCreationBytecode(artifact, libraries = {}) {
  return '0x' + linkedBytecode(artifact, 'bytecode', libraries).code;
}

/// Compare every runtime byte except exact compiler-listed immutable locations.
/// Raw OpenVM bytecode has no compiler mask: its entire runtime hash must match.
export function assertRuntimeMatchesArtifact(artifact, actualCode, libraries = {}) {
  if (!isHexString(actualCode) || actualCode.length <= 2 || actualCode.length % 2 !== 0) {
    throw new Error('Missing or malformed actual runtime bytecode');
  }
  if (artifact?.expectedRuntimeCodeHash !== undefined) {
    if (artifact.expectedRuntimeCodeHash !== PINNED_OPENVM.rawRuntimeCodeHash
        || artifact.artifactSha256 !== PINNED_OPENVM.verifierArtifactSha256) {
      throw new Error('Unpinned raw Halo2 runtime assertion');
    }
    if (keccak256(actualCode) !== artifact.expectedRuntimeCodeHash) throw new Error('Raw Halo2 runtime bytecode differs');
    return true;
  }
  const linked = linkedBytecode(artifact, 'deployedBytecode', libraries);
  let expected = linked.code;
  const libraryRanges = [...linked.ranges];
  // Solidity libraries embed their own deployment address in an initial
  // PUSH20/ADDRESS/EQ guard. Solc does not report that constructor patch as an
  // immutable reference. Compare it to the explicitly supplied library address;
  // never mask it or derive the expected address from untrusted runtime bytes.
  if (expected.startsWith('73' + '0'.repeat(40) + '3014')) {
    const target = artifact.metadata?.settings?.compilationTarget;
    if (!object(target) || Object.keys(target).length !== 1) throw new Error('Missing compiler library identity');
    const name = Object.values(target)[0];
    if (typeof name !== 'string' || !Object.hasOwn(libraries, name)) {
      throw new Error(`Missing deployed self-address for library ${name}`);
    }
    let address;
    try { address = getAddress(libraries[name]); }
    catch { throw new Error(`Invalid deployed self-address for library ${name}`); }
    if (address === ZeroAddress) throw new Error(`Invalid zero deployed self-address for library ${name}`);
    expected = '73' + address.slice(2).toLowerCase() + expected.slice(42);
    libraryRanges.push({ start: 1, end: 21 });
  }
  let actual = actualCode.slice(2).toLowerCase();
  if (actual.length !== expected.length) throw new Error('Runtime bytecode length differs');
  const immutableReferences = artifact.deployedBytecode.immutableReferences ?? {};
  if (!object(immutableReferences)) throw new Error('Malformed immutable references');
  const immutableRanges = [];
  for (const [name, positions] of Object.entries(immutableReferences)) {
    if (!Array.isArray(positions) || positions.length === 0) throw new Error(`Malformed immutable references: ${name}`);
    for (const position of positions) {
      immutableRanges.push(checkedRange(position, expected.length / 2, 32, `immutable ${name}`));
    }
  }
  assertNoOverlap(immutableRanges, 'immutable');
  assertNoOverlap([...immutableRanges, ...libraryRanges], 'immutable/library');
  let maskedExpected = expected;
  for (const { start, end } of immutableRanges) {
    maskedExpected = maskedExpected.slice(0, start * 2) + '0'.repeat((end - start) * 2) + maskedExpected.slice(end * 2);
    actual = actual.slice(0, start * 2) + '0'.repeat((end - start) * 2) + actual.slice(end * 2);
  }
  if (actual !== maskedExpected) throw new Error('Runtime bytecode differs outside compiler immutable locations');
  return true;
}

export function receiptImageId(halo2Address, exeCommit, vmCommit) {
  const address = getAddress(halo2Address);
  const field = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  for (const [name, value] of [['executable', exeCommit], ['VM', vmCommit]]) {
    if (!isHexString(value, 32) || BigInt(value) === 0n || BigInt(value) >= field) {
      throw new Error(`Invalid ${name} application commitment`);
    }
  }
  if (address === ZeroAddress) throw new Error('Invalid zero Halo2 verifier address');
  return keccak256(AbiCoder.defaultAbiCoder().encode(
    ['bytes32', 'address', 'bytes32', 'bytes32'],
    [id('INTERFOLD_OPENVM_RECEIPT_V1'), address, exeCommit, vmCommit],
  ));
}
