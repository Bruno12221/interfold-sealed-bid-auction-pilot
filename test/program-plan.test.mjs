import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AbiCoder, Interface, ZeroAddress, getAddress, getCreateAddress, id, keccak256, toBeHex } from 'ethers';
import { CHAIN_ID, DEPLOYER, PROTOCOL } from '../scripts/config.mjs';
import { ACIR_SHA256, PINNED_OPENVM, receiptImageId } from '../scripts/lib/verifier-stack.mjs';
import { DA_PINS, SECURE_PARAMS_HASH, STACK_LABELS, buildProgramPlan, launchTiming,
  parseDeadlineIso, validateProgramSnapshot } from '../scripts/lib/program-plan.mjs';
import { parseProgramPlanArguments } from '../scripts/prepare-program.mjs';

// Public paramSetRegistry(2) bytes read from the pinned Sepolia protocol on 2026-10-18.
const PARAMS = '0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000010366400000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000800000000db40010000000000000000000000000000000000000000000000000800000000d540010000000000000000000000000000000000000000000000000800000000cbc001000000000000000000000000000000000000000000000000000000000000002931373732333033393934333739383837383330353436303935353537303731313731373437383430300000000000000000000000000000000000000000000000';
const CONFIGURATION_TYPE = 'tuple(address interfold,address auctionEscrow,address resultSource,address inputVerifier,address receiptVerifier,address availabilityVerifier,address poseidon,bytes32 paramsHash,bytes32 inputCircuitId,bytes32 imageId,uint64 biddingEnds,uint64 settlementDeadline)';
const ARTIFACT = { abi: [`constructor(${CONFIGURATION_TYPE} config)`], bytecode: { object: '0x6000' } };
const NOW = Number(parseDeadlineIso('2026-10-18T08:00:00Z'));
const iso = timestamp => new Date(Number(timestamp) * 1000).toISOString();
const address = number => getAddress(toBeHex(number, 20));

function fixture() {
  const foundation = { chainId: CHAIN_ID, deployer: DEPLOYER, interfold: PROTOCOL,
    auction: { address: address(101), runtimeCodeHash: id('auction') },
    resultSource: { address: address(102), runtimeCodeHash: id('source') },
    demoNFT: { address: address(103), runtimeCodeHash: id('nft') } };
  const contracts = Object.fromEntries(STACK_LABELS.map((label, i) => [label,
    { address: address(201 + i), runtimeCodeHash: id(label) }]));
  const computeImage = receiptImageId(contracts.halo2.address, PINNED_OPENVM.computeExeCommit, PINNED_OPENVM.vmCommit);
  const bindingImage = receiptImageId(contracts.halo2.address, PINNED_OPENVM.bindingExeCommit, PINNED_OPENVM.vmCommit);
  const inputCircuitId = keccak256(AbiCoder.defaultAbiCoder().encode(Array(5).fill('bytes32'), [
    id('interfold.auction.input.secure8192.composed.v1'), contracts.encryptionVerifier.runtimeCodeHash,
    contracts.bindingReceipt.runtimeCodeHash, ACIR_SHA256, bindingImage,
  ]));
  const stack = { schemaVersion: 1, chainId: CHAIN_ID, deployer: DEPLOYER, interfold: PROTOCOL,
    status: 'verifiers-deployed-fixture-validated-program-deferred', forkTest: false,
    programDeployed: false, sourceBound: false, contracts,
    knownAnswers: { fixtureKnownAnswersPassed: true, inputCircuitId, bindingImageId: bindingImage,
      checks: [{ label: 'compute', imageId: computeImage }] } };
  const runtimeCodeHashes = Object.fromEntries([foundation.auction, foundation.resultSource, foundation.demoNFT,
    ...Object.values(contracts), ...Object.values(DA_PINS)].map(x => [x.address.toLowerCase(), x.runtimeCodeHash]));
  runtimeCodeHashes[PROTOCOL.toLowerCase()] = id('protocol');
  const snapshot = { chainId: CHAIN_ID, block: { number: 123, hash: id('block'), timestamp: NOW }, runtimeCodeHashes,
    predictedProgramHasCode: false, nonces: { latest: 12, pending: 12, finalLatest: 12, finalPending: 12 },
    foundation: { program: ZeroAddress, sourceReady: false, binder: DEPLOYER, state: '0', bidCount: '0',
      totalCreditsWei: '0', balanceWei: '0', seller: DEPLOYER, nft: foundation.demoNFT.address,
      tokenId: '1', nftOwner: DEPLOYER, resultSource: foundation.resultSource.address },
    protocol: { owner: address(301), requestsPaused: false, paramSet2: PARAMS, nextE3Id: '31',
      maxDurationSeconds: '2592000', randomnessRequestTimeoutSeconds: '936', sortitionSubmissionWindowSeconds: '180',
      timeouts: { dkgWindowSeconds: '1200', computeWindowSeconds: '604800', decryptionWindowSeconds: '21600' } },
    identities: { inputCircuitId, computeImageId: computeImage, computeExeCommit: PINNED_OPENVM.computeExeCommit,
      computeVmCommit: PINNED_OPENVM.vmCommit, computeHalo2: contracts.halo2.address,
      bindingImageId: bindingImage, bindingExeCommit: PINNED_OPENVM.bindingExeCommit,
      bindingVmCommit: PINNED_OPENVM.vmCommit, bindingHalo2: contracts.halo2.address,
      encryptionVerifier: contracts.encryptionVerifier.address, bindingVerifier: contracts.bindingReceipt.address },
    availabilityWiring: { verifierBridge: DA_PINS.bridge.address, verifierVectorx: DA_PINS.vectorx.address, bridgeVectorx: DA_PINS.vectorx.address } };
  return { foundation, stack, snapshot, artifact: ARTIFACT, artifactSha256: id('program-artifact') };
}

test('parses explicit whole-second ISO dates without locale assumptions or calendar normalization', () => {
  assert.equal(parseDeadlineIso('2026-10-18T10:00:00+02:00'), BigInt(NOW));
  assert.equal(parseDeadlineIso('2026-10-18T08:00:00.000Z'), BigInt(NOW));
  for (const invalid of ['2026-10-18', '2026-10-18T08:00:00', '2026-02-30T08:00:00Z',
    '2026-10-18T24:00:00Z', '2026-10-18T08:00:00.001Z', '2026-10-18T08:00:00+24:00', 'yesterday']) {
    assert.throws(() => parseDeadlineIso(invalid), /ISO|Invalid/);
  }
});

test('reads CLI flags without assuming any launch dates and tags examples explicitly', () => {
  assert.deepEqual(parseProgramPlanArguments([]), {});
  assert.deepEqual(parseProgramPlanArguments(['--example-only', '--bidding-end', 'end', '--settlement-deadline', 'settle',
    '--settlement-margin-seconds', '3600']), { exampleOnly: true, biddingEndIso: 'end', settlementDeadlineIso: 'settle', settlementMarginSeconds: '3600' });
  for (const args of [['--bad'], ['constructor', 'x'], ['--bidding-end'], ['--example-only', '--example-only'],
    ['--bidding-end', 'x', '--bidding-end', 'y'], ['--bidding-end', '--example-only']]) assert.throws(() => parseProgramPlanArguments(args), /Usage|Duplicate/);
});

test('default plan checks identities but never invents deadlines or deployment calldata', async () => {
  const input = fixture();
  assert.equal(keccak256(PARAMS), SECURE_PARAMS_HASH);
  const plan = await buildProgramPlan(input);
  assert.equal(plan.status, 'waiting-for-explicit-launch-deadlines');
  assert.equal(plan.deadlineSelection, 'not-selected');
  assert.equal(plan.unsignedDeployment, null);
  assert.equal(plan.configuration.biddingEnds, null);
  assert.equal(plan.configuration.availabilityVerifier, DA_PINS.verifier.address);
  assert.equal(plan.dependencies.length, 14);
  assert.equal(plan.predictedProgramAddress, getCreateAddress({ from: DEPLOYER, nonce: 12 }));
  assert.equal(plan.executableNow, false);
  assert.equal(plan.releaseGate.operationalChecksPassed, false);
  assert.equal(plan.actualProgramDomainKnownAnswer.status, 'missing');
  assert.ok(plan.deferredRequirements.includes('explicitBiddingEndAndSettlementDeadline'));
});

test('explicit example produces exact unsigned constructor and future registration/binding calldata with gates retained', async () => {
  const input = fixture();
  const end = NOW + 86400, settlement = end + 604800 + 21600 + 3600;
  const plan = await buildProgramPlan({ ...input, biddingEndIso: iso(end), settlementDeadlineIso: iso(settlement), exampleOnly: true });
  assert.equal(plan.exampleOnly, true);
  assert.equal(plan.deadlineSelection, 'illustrative-not-user-selected');
  assert.deepEqual([plan.signed, plan.broadcast, plan.executableNow, plan.readyForCombinedAuction], [false, false, false, false]);
  assert.deepEqual([plan.unsignedDeployment.from, plan.unsignedDeployment.nonce, plan.unsignedDeployment.chainId,
    plan.unsignedDeployment.value], [DEPLOYER, 12, CHAIN_ID, '0']);
  const [decoded] = AbiCoder.defaultAbiCoder().decode([CONFIGURATION_TYPE], '0x' + plan.unsignedDeployment.data.slice(6));
  assert.equal(decoded.interfold, PROTOCOL);
  assert.equal(decoded.auctionEscrow, input.foundation.auction.address);
  assert.equal(decoded.receiptVerifier, input.stack.contracts.computeReceipt.address);
  assert.equal(decoded.availabilityVerifier, getAddress(DA_PINS.verifier.address));
  assert.equal(decoded.imageId, input.snapshot.identities.computeImageId);
  assert.equal(decoded.inputCircuitId, input.snapshot.identities.inputCircuitId);
  assert.equal(decoded.biddingEnds, BigInt(end));
  assert.equal(decoded.settlementDeadline, BigInt(settlement));
  assert.equal(plan.registration.from, input.snapshot.protocol.owner);
  assert.equal(plan.registration.executableNow, false);
  assert.equal(new Interface(['function registerE3Program(address)']).decodeFunctionData('registerE3Program', plan.registration.data)[0], plan.predictedProgramAddress);
  assert.equal(new Interface(['function bindProgram(address)']).decodeFunctionData('bindProgram', plan.sourceBinding.data)[0], plan.predictedProgramAddress);
  assert.ok(plan.sourceBinding.requires.includes('verifyReleaseSuccessIncludingActualProgramDomainProofAndDA'));
  assert.equal(plan.sourceBinding.oneTimeIrreversibleBinding, true);
});

test('timing enforces full protocol windows and labels additional margins as local policy', () => {
  const p = fixture().snapshot.protocol;
  const end = NOW + 2316 + 3600, settlement = end + 626400 + 3600;
  const options = { biddingEndIso: iso(end), settlementDeadlineIso: iso(settlement) };
  const timing = launchTiming(p, NOW, options);
  assert.equal(timing.fullComputeAndDecryptionWindowSeconds, '626400');
  assert.equal(timing.source, 'current-protocol-defaults-not-yet-frozen');
  assert.match(timing.policy, /not protocol requirements or an ETA/);
  assert.equal(timing.settlementHeadroomAfterFullProtocolWindowSeconds, '3600');
  assert.throws(() => launchTiming(p, NOW, { biddingEndIso: iso(end) }), /both/);
  assert.throws(() => launchTiming(p, NOW, { ...options, biddingEndIso: iso(end - 1) }), /committee reservation/);
  assert.throws(() => launchTiming(p, NOW, { ...options, settlementDeadlineIso: iso(settlement - 1) }), /full compute/);
  assert.throws(() => launchTiming(p, NOW, { ...options, launchMarginSeconds: 0 }), /positive/);
  assert.throws(() => launchTiming(p, NOW, { biddingEndIso: iso(NOW + 2592000), settlementDeadlineIso: iso(NOW + 3300000) }), /maximum request lifecycle/);
});

test('rejects changed nonce, pending transactions and occupied CREATE address', () => {
  for (const key of ['pending', 'finalLatest', 'finalPending']) {
    const input = fixture(); input.snapshot.nonces[key]++;
    assert.throws(() => validateProgramSnapshot(input), /nonce changed|pending/);
  }
  for (const value of [-1, NaN, Number.MAX_SAFE_INTEGER + 1, '12']) {
    const input = fixture(); input.snapshot.nonces.latest = value;
    assert.throws(() => validateProgramSnapshot(input), /nonce changed/);
  }
  const occupied = fixture(); occupied.snapshot.predictedProgramHasCode = true;
  assert.throws(() => validateProgramSnapshot(occupied), /already has code/);
});

test('rejects any pinned foundation, verifier or existing DA runtime change and bridge rewiring', () => {
  const original = fixture();
  for (const key of Object.keys(original.snapshot.runtimeCodeHashes).filter(x => x !== PROTOCOL.toLowerCase())) {
    const input = fixture(); input.snapshot.runtimeCodeHashes[key] = id('changed-runtime');
    assert.throws(() => validateProgramSnapshot(input), /Runtime differs/);
  }
  for (const key of ['verifierBridge', 'verifierVectorx', 'bridgeVectorx']) {
    const input = fixture(); input.snapshot.availabilityWiring[key] = address(999);
    assert.throws(() => validateProgramSnapshot(input), /bridge wiring/);
  }
});

test('rejects a bound, funded or nonempty foundation and wrong NFT ownership', () => {
  for (const [key, value] of Object.entries({ program: address(999), sourceReady: true, binder: address(999), state: '1',
    bidCount: '1', totalCreditsWei: '1', balanceWei: '1', seller: address(999), nft: address(999),
    tokenId: '2', nftOwner: address(999), resultSource: address(999) })) {
    const input = fixture(); input.snapshot.foundation[key] = value;
    assert.throws(() => validateProgramSnapshot(input), /Foundation/);
  }
});

test('rejects fork records, incomplete stacks, wrong domains and unreviewed parameters', () => {
  for (const change of [x => { x.stack.forkTest = true; }, x => { x.stack.programDeployed = true; },
    x => { delete x.stack.contracts.poseidon; }, x => { x.snapshot.chainId = 1; },
    x => { x.stack.interfold = address(999); }, x => { x.stack.knownAnswers.fixtureKnownAnswersPassed = false; },
    x => { x.snapshot.protocol.paramSet2 = '0x1234'; }, x => { x.snapshot.protocol.owner = ZeroAddress; }]) {
    const input = fixture(); change(input);
    assert.throws(() => validateProgramSnapshot(input));
  }
});

test('independently recomputes input identity and rejects image, ACIR composition or receipt wiring mismatches', () => {
  for (const key of ['inputCircuitId', 'computeImageId', 'computeExeCommit', 'computeVmCommit', 'bindingImageId', 'bindingExeCommit', 'bindingVmCommit']) {
    const input = fixture(); input.snapshot.identities[key] = id('changed-identity');
    assert.throws(() => validateProgramSnapshot(input), /identity|image/);
  }
  for (const key of ['computeHalo2', 'bindingHalo2', 'encryptionVerifier', 'bindingVerifier']) {
    const input = fixture(); input.snapshot.identities[key] = address(999);
    assert.throws(() => validateProgramSnapshot(input), /wiring/);
  }
  const forgedCircuit = fixture();
  forgedCircuit.snapshot.identities.inputCircuitId = forgedCircuit.stack.knownAnswers.inputCircuitId = id('consistent-but-wrong');
  assert.throws(() => validateProgramSnapshot(forgedCircuit), /Input circuit identity/);
});
