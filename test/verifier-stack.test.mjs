import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdir, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { AbiCoder, id, keccak256, toBeHex } from 'ethers';
import {
  ACIR_SHA256, PINNED_OPENVM, loadVerifierStackArtifacts, linkCreationBytecode,
  assertRuntimeMatchesArtifact, receiptImageId, assertVerifierNetworkMode,
} from '../scripts/lib/verifier-stack.mjs';

const SOURCE = 'contracts/Fixture.sol';
const LIBRARY = 'FixtureLib';
const ADDRESS = '0x1234567890123456789012345678901234567890';
const PLACEHOLDER = `__$${id(`${SOURCE}:${LIBRARY}`).slice(2, 36)}$__`;

test('fork mode cannot masquerade as a live deployment or target a remote node', () => {
  assert.throws(() => assertVerifierNetworkMode('anvil/v1', 'http://localhost:18545', false), /requires --fork-test/);
  assert.throws(() => assertVerifierNetworkMode('anvil/v1', 'https://example.test', true), /local Anvil/);
  assert.throws(() => assertVerifierNetworkMode('Geth/v1', 'http://127.0.0.1:8545', true), /local Anvil/);
  for (const url of ['http://127.0.0.1:18545', 'http://localhost:8545', 'http://[::1]:8545']) {
    assert.doesNotThrow(() => assertVerifierNetworkMode('anvil/v1', url, true));
  }
  assert.doesNotThrow(() => assertVerifierNetworkMode('erigon/v3', 'https://ethereum-sepolia.publicnode.com', false));
});

function fixture() {
  return {
    abi: [],
    bytecode: { object: '0x6000' + PLACEHOLDER + '6001',
      linkReferences: { [SOURCE]: { [LIBRARY]: [{ start: 2, length: 20 }] } } },
    deployedBytecode: { object: '0x6000' + PLACEHOLDER + '7f' + '00'.repeat(32) + '00',
      linkReferences: { [SOURCE]: { [LIBRARY]: [{ start: 2, length: 20 }] } },
      immutableReferences: { 12: [{ start: 23, length: 32 }] } },
  };
}

function runtime(immutable = 'ab'.repeat(32)) {
  return '0x6000' + ADDRESS.slice(2) + '7f' + immutable + '00';
}

test('loads full current Foundry artifacts and the exact pinned original Halo2 JSON', async () => {
  const artifacts = await loadVerifierStackArtifacts();
  assert.deepEqual(Object.keys(artifacts).sort(), ['RelationsLib', 'ZKTranscriptLib', 'HonkVerifier',
    'AuctionInputVerifier', 'OpenVmReceiptVerifier', 'AuctionPoseidon', 'rawHalo2'].sort());
  assert.equal(artifacts.rawHalo2.artifactSha256, PINNED_OPENVM.verifierArtifactSha256);
  assert.equal(artifacts.rawHalo2.expectedRuntimeCodeHash, PINNED_OPENVM.rawRuntimeCodeHash);
  assert.equal(artifacts.rawHalo2.bytecode.length, 2 + 19_781 * 2);
  assert.equal(artifacts.rawHalo2.abi.length, 1);
  for (const artifact of Object.values(artifacts)) {
    assert.match(artifact.artifactSha256, /^0x[0-9a-f]{64}$/);
    assert.ok(artifact.artifactPath.startsWith('/'));
    assert.ok(Array.isArray(artifact.abi));
  }
  assert.deepEqual(artifacts.HonkVerifier.artifactBytes, await readFile(artifacts.HonkVerifier.artifactPath));
  assert.equal(ACIR_SHA256, '0xeb4c1699b4f25cf4bf86709095cb51c06d31acbf6cee16d6b7ce304770319eb6');
  const honk = linkCreationBytecode(artifacts.HonkVerifier, { RelationsLib: ADDRESS, ZKTranscriptLib: ADDRESS });
  assert.match(honk, /^0x[0-9a-f]+$/);
  assert.equal(honk.length, artifacts.HonkVerifier.bytecode.object.length);
});

test('rejects altered raw verifier artifact before allowing deployment', async () => {
  const folder = await mkdtemp(join(tmpdir(), 'interfold-verifier-stack-'));
  try {
    const builds = await loadVerifierStackArtifacts();
    for (const [name, artifact] of Object.entries(builds)) {
      if (name === 'rawHalo2') continue;
      const relative = name === 'RelationsLib' || name === 'ZKTranscriptLib' || name === 'HonkVerifier'
        ? `out/AuctionInputHonkVerifier.sol/${name}.json` : `out/${name}.sol/${name}.json`;
      const target = join(folder, relative);
      await mkdir(dirname(target), { recursive: true });
      await writeFile(target, await readFile(artifact.artifactPath));
    }
    const rawPath = join(folder, 'test/fixtures/openvm-receipts/verifier.bytecode.json');
    await mkdir(dirname(rawPath), { recursive: true });
    await writeFile(rawPath, (await readFile(builds.rawHalo2.artifactPath)).toString() + '\n');
    await assert.rejects(loadVerifierStackArtifacts(folder), /SHA-256 differs/);
  } finally { await rm(folder, { recursive: true, force: true }); }
});

test('loads a complete frozen artifact set without a disposable Foundry cache', async () => {
  const folder = await mkdtemp(join(tmpdir(), 'interfold-frozen-stack-'));
  try {
    const originals = await loadVerifierStackArtifacts();
    const paths = {};
    for (const [name, artifact] of Object.entries(originals)) {
      const target = join(folder, name === 'rawHalo2'
        ? 'test/fixtures/openvm-receipts/verifier.bytecode.json' : `frozen/${name}.json`);
      await mkdir(dirname(target), { recursive: true });
      await writeFile(target, await readFile(artifact.artifactPath));
      if (name !== 'rawHalo2') paths[name] = target;
    }
    const frozen = await loadVerifierStackArtifacts(folder, paths);
    for (const name of Object.keys(originals)) assert.equal(frozen[name].artifactSha256, originals[name].artifactSha256);
    await assert.rejects(loadVerifierStackArtifacts(folder, { ...paths, Extra: '/tmp/not-an-artifact' }), /complete named/);
    const { HonkVerifier, ...missing } = paths;
    await assert.rejects(loadVerifierStackArtifacts(folder, missing), /complete named/);
  } finally { await rm(folder, { recursive: true, force: true }); }
});

test('links compiler-listed creation positions and permits one shared library map', () => {
  const artifact = fixture();
  assert.equal(linkCreationBytecode(artifact, { [LIBRARY]: ADDRESS, UnusedLibrary: ADDRESS }),
    '0x6000' + ADDRESS.slice(2) + '6001');
  assert.equal(artifact.bytecode.object, '0x6000' + PLACEHOLDER + '6001', 'input artifact mutated');
  assert.equal(linkCreationBytecode({ bytecode: '0x60016000' }), '0x60016000');
});

test('rejects missing, malformed and zero library addresses', () => {
  assert.throws(() => linkCreationBytecode(fixture()), /Missing library address/);
  assert.throws(() => linkCreationBytecode(fixture(), { [LIBRARY]: '0x12' }), /Invalid library address/);
  assert.throws(() => linkCreationBytecode(fixture(), { [LIBRARY]: toBeHex(0, 20) }), /zero library address/);
  assert.throws(() => linkCreationBytecode(fixture(), []), /name-to-address map/);
});

test('rejects bad offsets, lengths, overlaps, wrong placeholders and hidden placeholders', () => {
  for (const position of [{ start: -1, length: 20 }, { start: 1.5, length: 20 },
    { start: 2, length: 19 }, { start: 10, length: 20 }]) {
    const artifact = fixture();
    artifact.bytecode.linkReferences[SOURCE][LIBRARY] = [position];
    assert.throws(() => linkCreationBytecode(artifact, { [LIBRARY]: ADDRESS }), /reference/);
  }
  const duplicate = fixture();
  duplicate.bytecode.linkReferences[SOURCE][LIBRARY].push({ start: 2, length: 20 });
  assert.throws(() => linkCreationBytecode(duplicate, { [LIBRARY]: ADDRESS }), /Overlapping/);
  const wrong = fixture();
  wrong.bytecode.object = wrong.bytecode.object.replace(PLACEHOLDER, '__$' + 'a'.repeat(34) + '$__');
  assert.throws(() => linkCreationBytecode(wrong, { [LIBRARY]: ADDRESS }), /Unexpected library placeholder/);
  const hidden = fixture();
  hidden.bytecode.linkReferences = {};
  assert.throws(() => linkCreationBytecode(hidden, { [LIBRARY]: ADDRESS }), /Unresolved or malformed/);
  assert.throws(() => linkCreationBytecode({ bytecode: { object: '0x600', linkReferences: {} } }), /malformed/);
});

test('runtime comparison masks only exact immutable ranges and preserves links/opcodes', () => {
  const artifact = fixture();
  assert.equal(assertRuntimeMatchesArtifact(artifact, runtime(), { [LIBRARY]: ADDRESS }), true);
  assert.equal(assertRuntimeMatchesArtifact(artifact, runtime('ff'.repeat(32)), { [LIBRARY]: ADDRESS }), true);
  assert.throws(() => assertRuntimeMatchesArtifact(artifact, runtime().slice(0, -2), { [LIBRARY]: ADDRESS }), /length differs/);
  assert.throws(() => assertRuntimeMatchesArtifact(artifact, runtime().replace('0x6000', '0x6001'), { [LIBRARY]: ADDRESS }), /outside compiler immutable/);
  assert.throws(() => assertRuntimeMatchesArtifact(artifact, runtime().replace(ADDRESS.slice(2), '11'.repeat(20)),
    { [LIBRARY]: ADDRESS }), /outside compiler immutable/);
  assert.throws(() => assertRuntimeMatchesArtifact(artifact, runtime().slice(0, -2) + '01', { [LIBRARY]: ADDRESS }), /outside compiler immutable/);
  assert.throws(() => assertRuntimeMatchesArtifact(artifact, '0x', { [LIBRARY]: ADDRESS }), /actual runtime/);
});

test('rejects malformed or overlapping immutable masks', () => {
  for (const positions of [[{ start: 23, length: 31 }], [{ start: 25, length: 32 }],
    [{ start: 23, length: 32 }, { start: 23, length: 32 }], [{ start: 0, length: 32 }]]) {
    const artifact = fixture();
    artifact.deployedBytecode.immutableReferences = { 12: positions };
    assert.throws(() => assertRuntimeMatchesArtifact(artifact, runtime(), { [LIBRARY]: ADDRESS }), /reference/);
  }
});

test('raw verifier runtime checks cannot be replaced with an arbitrary expected hash', async () => {
  const { rawHalo2 } = await loadVerifierStackArtifacts();
  const rawRuntime = '0x' + rawHalo2.bytecode.slice(2 + 32 * 2);
  assert.equal(keccak256(rawRuntime), PINNED_OPENVM.rawRuntimeCodeHash);
  assert.equal(assertRuntimeMatchesArtifact(rawHalo2, rawRuntime), true);
  assert.throws(() => assertRuntimeMatchesArtifact(rawHalo2, '0x6000'), /Raw Halo2 runtime bytecode differs/);
  assert.throws(() => assertRuntimeMatchesArtifact({ ...rawHalo2, expectedRuntimeCodeHash: keccak256('0x6000') }, '0x6000'),
    /Unpinned raw Halo2 runtime assertion/);
});

test('Solidity library runtime self-address is compared exactly rather than masked', async () => {
  const { RelationsLib, ZKTranscriptLib } = await loadVerifierStackArtifacts();
  for (const [name, artifact] of Object.entries({ RelationsLib, ZKTranscriptLib })) {
    const expected = artifact.deployedBytecode.object;
    assert.ok(expected.startsWith('0x73' + '0'.repeat(40) + '3014'));
    const actual = '0x73' + ADDRESS.slice(2) + expected.slice(44);
    assert.equal(assertRuntimeMatchesArtifact(artifact, actual, { [name]: ADDRESS }), true);
    assert.throws(() => assertRuntimeMatchesArtifact(artifact, actual), /Missing deployed self-address/);
    assert.throws(() => assertRuntimeMatchesArtifact(artifact, actual, { [name]: toBeHex(123, 20) }), /outside compiler immutable/);
    assert.throws(() => assertRuntimeMatchesArtifact(artifact, expected, { [name]: ADDRESS }), /outside compiler immutable/);
  }
});

test('receipt image matches upstream ABI domain and changes with every identity component', () => {
  const { bindingExeCommit, computeExeCommit, vmCommit } = PINNED_OPENVM;
  const image = receiptImageId(ADDRESS, bindingExeCommit, vmCommit);
  const expected = keccak256(AbiCoder.defaultAbiCoder().encode(['bytes32', 'address', 'bytes32', 'bytes32'],
    [id('INTERFOLD_OPENVM_RECEIPT_V1'), ADDRESS, bindingExeCommit, vmCommit]));
  assert.equal(image, expected);
  assert.notEqual(receiptImageId(toBeHex(123, 20), bindingExeCommit, vmCommit), image);
  assert.notEqual(receiptImageId(ADDRESS, computeExeCommit, vmCommit), image);
  assert.notEqual(receiptImageId(ADDRESS, bindingExeCommit, toBeHex(BigInt(vmCommit) ^ 1n, 32)), image);
  assert.throws(() => receiptImageId(ADDRESS, toBeHex(0, 32), vmCommit), /Invalid executable/);
  assert.throws(() => receiptImageId(ADDRESS, bindingExeCommit, '0x1234'), /Invalid VM/);
  assert.throws(() => receiptImageId(toBeHex(0, 20), bindingExeCommit, vmCommit), /zero Halo2/);
  assert.throws(() => receiptImageId(ADDRESS, toBeHex(2n ** 256n - 1n, 32), vmCommit), /Invalid executable/);
});
