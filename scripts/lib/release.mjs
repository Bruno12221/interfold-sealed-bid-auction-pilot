import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { Contract, Interface, ZeroAddress, getAddress, isHexString, keccak256 } from 'ethers';
import { PROTOCOL } from '../config.mjs';

const specs = [
  ['inputVerifier', 'inputVerifier', 'inputVerifierCodeHash'],
  ['computeVerifier', 'receiptVerifier', 'receiptVerifierCodeHash'],
  ['dataAvailabilityVerifier', 'availabilityVerifier', 'availabilityVerifierCodeHash'],
];
const proofInterfaces = {
  inputVerifier: new Interface(['function verify(bytes proof,(uint256 chainId,address program,address interfold,address auction,bytes32 context,uint256 e3Id,bytes32 committeePublicKey,bytes32 paramsHash,uint256 slot,address bidder,uint256 maxTick,bytes32 ciphertextHash,bytes32 ciphertextCommitment) statement) view returns(bool)']),
  computeVerifier: new Interface(['function verify(bytes seal,bytes32 imageId,bytes32 journalDigest) view']),
  dataAvailabilityVerifier: new Interface(['function verifyDataAvailability(bytes32 expectedContentHash,bytes proof) view returns((bytes32 contentHash,uint32 blockNumber,uint128 leafIndex))']),
};
const requireAddress = (a, label) => {
  if (!a || getAddress(a) === ZeroAddress) throw new Error(`${label}: nonzero address required`);
  return getAddress(a);
};
const requireHash = (hash, label) => {
  if (!/^0x[0-9a-f]{64}$/i.test(hash ?? '') || BigInt(hash) === 0n) throw new Error(`${label}: nonzero hash required`);
  return hash.toLowerCase();
};

async function verifyFile(base, path, expected) {
  if (typeof path !== 'string' || !path) throw new Error('Release artifact path is missing');
  const digest = createHash('sha256').update(await readFile(resolve(base, path))).digest('hex');
  if (digest !== requireHash(expected, path).slice(2)) throw new Error(`Release artifact SHA-256 differs: ${path}`);
  return digest;
}

/// Operational checks for a reproducibly built release. These checks do not audit circuits.
export async function verifyRelease(path, provider, expected) {
  const release = JSON.parse(await readFile(path, 'utf8'));
  if (release.schemaVersion !== 1 || release.chainId !== 11155111) throw new Error('Wrong release schema or chain');
  if ((await provider.getNetwork()).chainId !== 11155111n) throw new Error('Wrong RPC chain');
  for (const field of ['auction', 'resultSource', 'program']) {
    if (requireAddress(release[field], field) !== requireAddress(expected[field], field)) throw new Error(`Release ${field} differs from deployment`);
  }
  const program = new Contract(release.program, [
    ...specs.flatMap(([, getter, hashGetter]) => [`function ${getter}() view returns(address)`, `function ${hashGetter}() view returns(bytes32)`]),
    'function imageId() view returns(bytes32)', 'function auctionEscrow() view returns(address)',
    'function resultSource() view returns(address)', 'function inputCircuitId() view returns(bytes32)',
    'function paramsHash() view returns(bytes32)', 'function interfold() view returns(address)',
    'function poseidon() view returns(address)', 'function poseidonCodeHash() view returns(bytes32)',
  ], provider);
  if (getAddress(await program.auctionEscrow()) !== getAddress(release.auction)
      || getAddress(await program.resultSource()) !== getAddress(release.resultSource)) throw new Error('Program escrow/source wiring differs');
  const verifiers = new Map();
  for (const [field, getter, hashGetter] of specs) {
    const item = release[field];
    const addr = requireAddress(item?.address, field);
    const hash = requireHash(item?.runtimeCodeHash, field);
    if (getAddress(await program[getter]()) !== addr || (await program[hashGetter]()).toLowerCase() !== hash) {
      throw new Error(`Program pin differs: ${field}`);
    }
    const code = await provider.getCode(addr);
    if (code === '0x' || keccak256(code) !== hash) throw new Error(`Verifier runtime differs: ${field}`);
    await verifyFile(dirname(path), item.artifactPath, item.artifactSha256);
    verifiers.set(addr.toLowerCase(), field);
  }
  if (requireHash(release.computeVerifier.imageId, 'imageId') !== (await program.imageId()).toLowerCase()) throw new Error('Guest image identity differs');
  const inputVerifier = new Contract(release.inputVerifier.address, ['function circuitId() view returns(bytes32)'], provider);
  const circuitId = requireHash(release.inputVerifier.circuitId, 'inputCircuitId');
  if (circuitId !== (await inputVerifier.circuitId()).toLowerCase() || circuitId !== (await program.inputCircuitId()).toLowerCase()) throw new Error('Input circuit identity differs');
  if (requireHash(release.paramsHash, 'paramsHash') !== (await program.paramsHash()).toLowerCase()) throw new Error('Secure parameters differ');
  if (getAddress(await program.interfold()) !== PROTOCOL) throw new Error('Program uses a different Interfold deployment');
  const protocol = new Contract(PROTOCOL, ['function paramSetRegistry(uint8) view returns(bytes)'], provider);
  if (keccak256(await protocol.paramSetRegistry(2)) !== release.paramsHash.toLowerCase()) throw new Error('Program parameters differ from live secure-8192 registry');
  const poseidon = requireAddress(release.poseidon?.address, 'poseidon');
  const poseidonHash = requireHash(release.poseidon?.runtimeCodeHash, 'poseidon runtime');
  if (getAddress(await program.poseidon()) !== poseidon || (await program.poseidonCodeHash()).toLowerCase() !== poseidonHash
      || keccak256(await provider.getCode(poseidon)) !== poseidonHash) throw new Error('Poseidon runtime differs');
  await verifyFile(dirname(path), release.knownAnswerProof?.path, release.knownAnswerProof?.sha256);
  const knownAnswers = JSON.parse(await readFile(resolve(dirname(path), release.knownAnswerProof.path), 'utf8'));
  if (!Array.isArray(knownAnswers.cases) || knownAnswers.cases.length !== 3) throw new Error('Three verifier known-answer cases required');
  for (const item of knownAnswers.cases) {
    const to = requireAddress(item.to, 'known-answer verifier');
    const field = verifiers.get(to.toLowerCase());
    if (!field || !isHexString(item.validCalldata) || getAddress(item.from) !== getAddress(release.program)
        || !isHexString(item.tamperedCalldata) || item.validCalldata === item.tamperedCalldata) {
      throw new Error('Invalid verifier known-answer case');
    }
    verifiers.delete(to.toLowerCase());
    const iface = proofInterfaces[field];
    const signature = field === 'dataAvailabilityVerifier' ? 'verifyDataAvailability' : 'verify';
    const valid = iface.decodeFunctionData(signature, item.validCalldata);
    const tampered = iface.decodeFunctionData(signature, item.tamperedCalldata);
    if (iface.encodeFunctionData(signature, valid).toLowerCase() !== item.validCalldata.toLowerCase()
        || iface.encodeFunctionData(signature, tampered).toLowerCase() !== item.tamperedCalldata.toLowerCase()) throw new Error('Noncanonical proof calldata');
    const proofIndex = field === 'dataAvailabilityVerifier' ? 1 : 0;
    if (valid[proofIndex] === '0x' || valid[proofIndex] === tampered[proofIndex]) throw new Error('Known-answer tampering must change the proof');
    const sameStatement = [...valid]; sameStatement[proofIndex] = tampered[proofIndex];
    if (iface.encodeFunctionData(signature, sameStatement).toLowerCase() !== item.tamperedCalldata.toLowerCase()) throw new Error('Tampered case must keep the public statement unchanged');
    if (field === 'inputVerifier') {
      const s = valid[1];
      if (s.chainId !== 11155111n || getAddress(s.program) !== getAddress(release.program) || getAddress(s.auction) !== getAddress(release.auction)
          || getAddress(s.interfold) !== getAddress(await program.interfold()) || s.paramsHash.toLowerCase() !== release.paramsHash.toLowerCase()) throw new Error('Known-answer input domain differs');
    }
    if (field === 'computeVerifier' && valid[1].toLowerCase() !== release.computeVerifier.imageId.toLowerCase()) throw new Error('Known-answer guest identity differs');
    function accepted(returned) {
      if (field === 'computeVerifier') return returned === '0x';
      const decoded = iface.decodeFunctionResult(signature, returned);
      if (field === 'inputVerifier') return decoded[0] === true;
      return decoded[0].contentHash.toLowerCase() === valid[0].toLowerCase() && decoded[0].blockNumber > 0n;
    }
    const tx = { to, from: release.program, data: item.validCalldata };
    const actual = await provider.call(tx);
    if (!accepted(actual)) throw new Error('Known-answer proof was rejected');
    let tamperRejected = false;
    try {
      const invalid = await provider.call({ ...tx, data: item.tamperedCalldata });
      tamperRejected = !accepted(invalid);
    } catch (error) { if (error.code === 'CALL_EXCEPTION') tamperRejected = true; else throw error; }
    if (!tamperRejected) throw new Error('Tampered proof was accepted by a release verifier');
  }
  return { verifiedAt: new Date().toISOString(), operationalChecksPassed: true, independentSecurityAudit: false };
}
