import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { Interface, keccak256, toBeHex } from 'ethers';
import { verifyRelease } from '../scripts/lib/release.mjs';
import { PROTOCOL } from '../scripts/config.mjs';

test('example cannot become a runnable release', async () => {
  await assert.rejects(verifyRelease('pilot/release-manifest.example.json', { getNetwork: async () => ({ chainId: 11155111n }) },
    { auction: '0x63B12dda13bF51e0FF8BDEc4C9DaaF03786792C3', resultSource: '0x8A5465A0E50cd28c0D4f4370b644e90e042feF58', program: null }), /program/);
});

test('release checks artifacts, program pins, known answers and tampered-proof rejection', async () => {
  const folder = await mkdtemp(join(tmpdir(), 'interfold-release-test-'));
  try {
    const addr = n => toBeHex(n, 20);
    const hash = value => '0x' + createHash('sha256').update(value).digest('hex');
    const release = { schemaVersion: 1, chainId: 11155111, auction: addr(1), resultSource: addr(2), program: addr(3) };
    const names = ['inputVerifier', 'computeVerifier', 'dataAvailabilityVerifier'];
    const getters = ['inputVerifier', 'receiptVerifier', 'availabilityVerifier'];
    const pins = ['inputVerifierCodeHash', 'receiptVerifierCodeHash', 'availabilityVerifierCodeHash'];
    const functions = ['function auctionEscrow() view returns(address)', 'function resultSource() view returns(address)',
      'function imageId() view returns(bytes32)', 'function inputCircuitId() view returns(bytes32)',
      'function paramsHash() view returns(bytes32)', 'function interfold() view returns(address)',
      'function poseidon() view returns(address)', 'function poseidonCodeHash() view returns(bytes32)', ...getters.map(x => `function ${x}() view returns(address)`),
      ...pins.map(x => `function ${x}() view returns(bytes32)`)];
    const iface = new Interface(functions);
    const values = { auctionEscrow: release.auction, resultSource: release.resultSource, imageId: toBeHex(123, 32),
      inputCircuitId: toBeHex(456, 32), paramsHash: keccak256('0x1234'), interfold: PROTOCOL,
      poseidon: addr(20), poseidonCodeHash: keccak256('0x1234') };
    release.paramsHash = values.paramsHash;
    release.poseidon = { address: values.poseidon, runtimeCodeHash: values.poseidonCodeHash };
    for (let i = 0; i < names.length; ++i) {
      const field = names[i];
      const artifact = `${field} build artifact`;
      await writeFile(join(folder, `${field}.json`), artifact);
      release[field] = { address: addr(10 + i), runtimeCodeHash: keccak256('0x1234'), artifactPath: `${field}.json`, artifactSha256: hash(artifact) };
      values[getters[i]] = addr(10 + i); values[pins[i]] = release[field].runtimeCodeHash;
    }
    release.computeVerifier.imageId = values.imageId;
    release.inputVerifier.circuitId = values.inputCircuitId;
    const inputIface = new Interface(['function circuitId() view returns(bytes32)',
      'function verify(bytes,(uint256 chainId,address program,address interfold,address auction,bytes32 context,uint256 e3Id,bytes32 committeePublicKey,bytes32 paramsHash,uint256 slot,address bidder,uint256 maxTick,bytes32 ciphertextHash,bytes32 ciphertextCommitment)) view returns(bool)']);
    const computeIface = new Interface(['function verify(bytes,bytes32,bytes32) view']);
    const daIface = new Interface(['function verifyDataAvailability(bytes32,bytes) view returns((bytes32 contentHash,uint32 blockNumber,uint128 leafIndex))']);
    const protocolIface = new Interface(['function paramSetRegistry(uint8) view returns(bytes)']);
    const statement = [11155111, release.program, values.interfold, release.auction, toBeHex(5, 32), 7,
      toBeHex(6, 32), values.paramsHash, 0, addr(99), 100, toBeHex(8, 32), toBeHex(9, 32)];
    const data = (field, proof) => field === 'inputVerifier' ? inputIface.encodeFunctionData('verify', [proof, statement])
      : field === 'computeVerifier' ? computeIface.encodeFunctionData('verify', [proof, values.imageId, toBeHex(10, 32)])
      : daIface.encodeFunctionData('verifyDataAvailability', [toBeHex(11, 32), proof]);
    const cases = { cases: names.map(field => ({ to: release[field].address, from: release.program,
      validCalldata: data(field, '0xaaaa'), tamperedCalldata: data(field, '0xbbbb') })) };
    async function saveCases() {
      await writeFile(join(folder, 'known.json'), JSON.stringify(cases));
      release.knownAnswerProof = { path: 'known.json', sha256: hash(JSON.stringify(cases)) };
      await writeFile(path, JSON.stringify(release));
    }
    const path = join(folder, 'release.json');
    await saveCases();
    let acceptTampered = false, wrongCode = false, inputReturnsFalse = false;
    const provider = { getNetwork: async () => ({ chainId: 11155111n }), getCode: async () => wrongCode ? '0xab' : '0x1234',
      call: async tx => {
        if (tx.to.toLowerCase() === PROTOCOL.toLowerCase()) return protocolIface.encodeFunctionResult('paramSetRegistry', ['0x1234']);
        if (tx.to.toLowerCase() === release.program) {
          const parsed = iface.parseTransaction(tx);
          return iface.encodeFunctionResult(parsed.name, [values[parsed.name]]);
        }
        if (tx.to.toLowerCase() === release.inputVerifier.address && tx.data === inputIface.encodeFunctionData('circuitId')) {
          return inputIface.encodeFunctionResult('circuitId', [values.inputCircuitId]);
        }
        const field = names.find(x => release[x].address === tx.to.toLowerCase());
        if (tx.data === data(field, '0xaaaa') || acceptTampered) {
          if (field === 'inputVerifier') return inputIface.encodeFunctionResult('verify', [!inputReturnsFalse]);
          if (field === 'computeVerifier') return '0x';
          return daIface.encodeFunctionResult('verifyDataAvailability', [[toBeHex(11, 32), 1, 0]]);
        }
        throw Object.assign(new Error('invalid proof'), { code: 'CALL_EXCEPTION' });
      } };
    assert.equal((await verifyRelease(path, provider, release)).operationalChecksPassed, true);
    acceptTampered = true;
    await assert.rejects(verifyRelease(path, provider, release), /Tampered proof/);
    acceptTampered = false; inputReturnsFalse = true;
    await assert.rejects(verifyRelease(path, provider, release), /proof was rejected/);
    inputReturnsFalse = false;
    cases.cases[0].validCalldata = inputIface.encodeFunctionData('circuitId');
    await saveCases();
    await assert.rejects(verifyRelease(path, provider, release));
    cases.cases[0].validCalldata = data('inputVerifier', '0xaaaa');
    cases.cases[0].tamperedCalldata = inputIface.encodeFunctionData('verify', ['0xbbbb', [...statement.slice(0, 8), 1, ...statement.slice(9)]]);
    await saveCases();
    await assert.rejects(verifyRelease(path, provider, release), /public statement unchanged/);
    cases.cases[0].tamperedCalldata = data('inputVerifier', '0xbbbb');
    await saveCases();
    wrongCode = true;
    await assert.rejects(verifyRelease(path, provider, release), /runtime/);
    wrongCode = false;
    await writeFile(join(folder, 'inputVerifier.json'), 'different build artifact');
    await assert.rejects(verifyRelease(path, provider, release), /SHA-256/);
  } finally { await rm(folder, { recursive: true, force: true }); }
});
