import { AbiCoder, ContractFactory, Interface, ZeroAddress, getAddress, getCreateAddress, id, keccak256 } from 'ethers';
import { CHAIN_ID, DEPLOYER, PROTOCOL } from '../config.mjs';
import { ACIR_SHA256, PINNED_OPENVM, receiptImageId } from './verifier-stack.mjs';

export const SECURE_PARAMS_HASH = '0x1b2620f6a5919d5ee19a51f34026369816f479efd0404b56585ad37d31c52317';
export const STACK_LABELS = ['halo2', 'bindingReceipt', 'computeReceipt', 'relations', 'zkTranscript', 'encryptionVerifier', 'inputVerifier', 'poseidon'];
// Existing deployed dependencies, pinned by pilot/avail/lib.mjs and the prior Sepolia audit.
// Reading their Ethereum code/wiring does not contact Avail or publish any data.
export const DA_PINS = Object.freeze({
  verifier: { address: '0x6D373da705B443EF76e37cb96275623818c50657', runtimeCodeHash: '0x20f8b240265bea5d95067d4192997390573ed1bd55738eda0b7c64b9e8609dbd' },
  bridge: { address: '0x967F7DdC4ec508462231849AE81eeaa68Ad01389', runtimeCodeHash: '0x78168a9262adad7fa623076295d940f37c0f84c04c1d302e43a75b132f0d5793' },
  vectorx: { address: '0xe542dB219a7e2b29C7AEaEAce242c9a2Cd528F96', runtimeCodeHash: '0x184390dbe2dec22a44d6660b99d4b33e43e4a977793a7954485fcb2cb8cd4986' },
});

const same = (a, b) => getAddress(a) === getAddress(b);
const hash = (v, label) => {
  if (!/^0x[0-9a-f]{64}$/i.test(v ?? '') || BigInt(v) === 0n) throw new Error(`Invalid ${label}`);
  return v.toLowerCase();
};
function uint(value, label) {
  if (typeof value === 'number' && !Number.isSafeInteger(value)) throw new Error(`Invalid ${label}`);
  if (typeof value === 'boolean' || !/^(0|[1-9][0-9]*)$/.test(String(value))) throw new Error(`Invalid ${label}`);
  return BigInt(value);
}

/** Require an explicit ISO8601 timestamp with seconds and a timezone; never assume local time. */
export function parseDeadlineIso(value, label = 'deadline') {
  const match = typeof value === 'string' && value.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.000)?(Z|[+-]\d{2}:\d{2})$/);
  if (!match) throw new Error(`${label} must be an ISO timestamp with whole seconds and an explicit timezone`);
  const [, year, month, day, hour, minute, second, zone] = match;
  const parts = [year, month, day, hour, minute, second].map(Number);
  const calendar = new Date(Date.UTC(parts[0], parts[1] - 1, parts[2], parts[3], parts[4], parts[5]));
  if (parts[0] < 1970 || calendar.getUTCFullYear() !== parts[0] || calendar.getUTCMonth() !== parts[1] - 1
    || calendar.getUTCDate() !== parts[2] || calendar.getUTCHours() !== parts[3]
    || calendar.getUTCMinutes() !== parts[4] || calendar.getUTCSeconds() !== parts[5]
    || (zone !== 'Z' && (Number(zone.slice(1, 3)) > 23 || Number(zone.slice(4)) > 59))) throw new Error(`Invalid ${label} calendar date`);
  const millis = Date.parse(value);
  if (!Number.isSafeInteger(millis) || millis < 0 || millis % 1000 !== 0) throw new Error(`Invalid ${label}`);
  return BigInt(millis / 1000);
}

export function launchTiming(protocol, timestamp, { biddingEndIso, settlementDeadlineIso,
  settlementMarginSeconds = 3600, launchMarginSeconds = 3600 } = {}) {
  const now = uint(timestamp, 'block timestamp');
  const t = protocol.timeouts;
  const dkg = uint(t.dkgWindowSeconds, 'DKG window');
  const compute = uint(t.computeWindowSeconds, 'compute window');
  const decrypt = uint(t.decryptionWindowSeconds, 'decryption window');
  const committee = dkg + uint(protocol.randomnessRequestTimeoutSeconds, 'randomness timeout')
    + uint(protocol.sortitionSubmissionWindowSeconds, 'sortition window');
  const margin = uint(settlementMarginSeconds, 'settlement margin');
  const launchMargin = uint(launchMarginSeconds, 'launch margin');
  if (margin === 0n || launchMargin === 0n) throw new Error('Planning margins must be positive');
  const maxDuration = uint(protocol.maxDurationSeconds, 'maximum request duration');
  const result = { source: 'current-protocol-defaults-not-yet-frozen',
    dkgWindowSeconds: String(dkg), computeWindowSeconds: String(compute), decryptionWindowSeconds: String(decrypt),
    committeeReservationSeconds: String(committee), fullComputeAndDecryptionWindowSeconds: String(compute + decrypt),
    launchMarginSeconds: String(launchMargin), settlementMarginSeconds: String(margin), maxDurationSeconds: String(maxDuration),
    deadlinesSupplied: false, biddingEnds: null, settlementDeadline: null,
    policy: 'Local planning policy requires committee reservation plus launch margin before close, and full compute/decryption windows plus settlement margin after close. The margins are not protocol requirements or an ETA.',
    requestLifecycleRule: 'max(inputWindowEnd-requestTime,committeeReservation)+computeWindow+decryptionWindow<=maxDuration',
    refreshBeforeRequest: true };
  if (biddingEndIso === undefined && settlementDeadlineIso === undefined) return result;
  if (biddingEndIso === undefined || settlementDeadlineIso === undefined) throw new Error('Supply both explicit ISO deadlines');
  const end = parseDeadlineIso(biddingEndIso, 'bidding end');
  const settlement = parseDeadlineIso(settlementDeadlineIso, 'settlement deadline');
  if (end >= 1n << 64n || settlement >= 1n << 64n || end <= now || settlement <= end) throw new Error('Deadlines must be future ordered uint64 timestamps');
  if (end - now < committee + launchMargin) throw new Error('Bidding end lacks the committee reservation and local launch margin');
  if (settlement - end < compute + decrypt + margin) throw new Error('Settlement deadline lacks full compute/decryption windows and local settlement margin');
  const lifecycle = (end - now > committee ? end - now : committee) + compute + decrypt;
  if (lifecycle > maxDuration) throw new Error('Input window exceeds the protocol maximum request lifecycle at this snapshot');
  return { ...result, deadlinesSupplied: true, biddingEnds: String(end), settlementDeadline: String(settlement),
    biddingEndIso: new Date(Number(end) * 1000).toISOString(), settlementDeadlineIso: new Date(Number(settlement) * 1000).toISOString(),
    requestLifecycleSecondsAtSnapshot: String(lifecycle), settlementHeadroomAfterFullProtocolWindowSeconds: String(settlement - end - compute - decrypt) };
}

export function validateProgramSnapshot({ foundation, stack, snapshot }) {
  if (foundation.chainId !== CHAIN_ID || stack.schemaVersion !== 1 || stack.chainId !== CHAIN_ID
    || Number(snapshot.chainId) !== CHAIN_ID || !same(foundation.interfold, PROTOCOL)
    || !same(stack.interfold, PROTOCOL) || !same(foundation.deployer, DEPLOYER) || !same(stack.deployer, DEPLOYER)) throw new Error('Wrong Sepolia deployment or signer domain');
  if (stack.forkTest || stack.status !== 'verifiers-deployed-fixture-validated-program-deferred'
    || stack.programDeployed !== false || stack.sourceBound !== false || stack.knownAnswers?.fixtureKnownAnswersPassed !== true) throw new Error('A completed real verifier stack with deferred program is required');
  if (Object.keys(stack.contracts ?? {}).length !== STACK_LABELS.length || STACK_LABELS.some(x => !stack.contracts[x])) throw new Error('Incomplete verifier stack');
  const codePins = [...['auction', 'resultSource', 'demoNFT'].map(x => ({ label: x, ...foundation[x] })),
    ...STACK_LABELS.map(x => ({ label: x, ...stack.contracts[x] })),
    ...Object.entries(DA_PINS).map(([x, p]) => ({ label: `availability-${x}`, ...p }))];
  for (const pin of codePins) {
    const actual = snapshot.runtimeCodeHashes[getAddress(pin.address).toLowerCase()];
    if (!actual || actual !== hash(pin.runtimeCodeHash, `${pin.label} runtime hash`)) throw new Error(`Runtime differs: ${pin.label}`);
  }
  if (!snapshot.runtimeCodeHashes[getAddress(PROTOCOL).toLowerCase()]) throw new Error('Missing Interfold code');
  const f = snapshot.foundation;
  if (!same(f.program, ZeroAddress) || f.sourceReady !== false || !same(f.binder, DEPLOYER)
    || uint(f.state, 'auction state') !== 0n || uint(f.bidCount, 'bid count') !== 0n
    || uint(f.totalCreditsWei, 'credits') !== 0n || uint(f.balanceWei, 'auction balance') !== 0n
    || !same(f.seller, DEPLOYER) || !same(f.nft, foundation.demoNFT.address)
    || uint(f.tokenId, 'NFT token') !== 1n || !same(f.nftOwner, f.seller)
    || !same(f.resultSource, foundation.resultSource.address)) throw new Error('Foundation must remain unbound, empty, Created, and seller-owned');
  const n = snapshot.nonces;
  for (const key of ['latest', 'pending', 'finalLatest', 'finalPending']) if (!Number.isSafeInteger(n[key]) || n[key] < 0 || n[key] !== n.latest) throw new Error('Deployer nonce changed or has pending transactions');
  const predicted = getCreateAddress({ from: DEPLOYER, nonce: n.latest });
  if (snapshot.predictedProgramHasCode !== false) throw new Error('Predicted program address already has code');
  const paramsHash = keccak256(snapshot.protocol.paramSet2);
  if (paramsHash !== SECURE_PARAMS_HASH) throw new Error('Protocol parameter set2 differs from reviewed secure8192 parameters');
  if (same(snapshot.protocol.owner, ZeroAddress)) throw new Error('Missing registration authority');
  const v = snapshot.identities;
  const computedImage = receiptImageId(stack.contracts.halo2.address, PINNED_OPENVM.computeExeCommit, PINNED_OPENVM.vmCommit);
  const bindingImage = receiptImageId(stack.contracts.halo2.address, PINNED_OPENVM.bindingExeCommit, PINNED_OPENVM.vmCommit);
  const circuitId = keccak256(AbiCoder.defaultAbiCoder().encode(['bytes32', 'bytes32', 'bytes32', 'bytes32', 'bytes32'], [
    id('interfold.auction.input.secure8192.composed.v1'), stack.contracts.encryptionVerifier.runtimeCodeHash,
    stack.contracts.bindingReceipt.runtimeCodeHash, ACIR_SHA256, bindingImage,
  ]));
  if (hash(v.inputCircuitId, 'input circuit ID') !== circuitId
    || hash(stack.knownAnswers.inputCircuitId, 'recorded input circuit ID') !== circuitId) throw new Error('Input circuit identity differs');
  const recorded = stack.knownAnswers.checks?.find(x => x.label === 'compute');
  if (v.computeImageId !== computedImage || recorded?.imageId !== computedImage || v.bindingImageId !== bindingImage
    || stack.knownAnswers.bindingImageId !== bindingImage || !same(v.computeHalo2, stack.contracts.halo2.address)
    || !same(v.bindingHalo2, stack.contracts.halo2.address) || v.computeExeCommit !== PINNED_OPENVM.computeExeCommit
    || v.bindingExeCommit !== PINNED_OPENVM.bindingExeCommit || v.computeVmCommit !== PINNED_OPENVM.vmCommit
    || v.bindingVmCommit !== PINNED_OPENVM.vmCommit || !same(v.encryptionVerifier, stack.contracts.encryptionVerifier.address)
    || !same(v.bindingVerifier, stack.contracts.bindingReceipt.address)) throw new Error('Verifier image or composed wiring differs');
  const w = snapshot.availabilityWiring;
  if (!same(w.verifierBridge, DA_PINS.bridge.address) || !same(w.verifierVectorx, DA_PINS.vectorx.address)
    || !same(w.bridgeVectorx, DA_PINS.vectorx.address)) throw new Error('Existing availability bridge wiring differs');
  return { predicted, paramsHash, computedImage, inputCircuitId: v.inputCircuitId,
    codePins: codePins.map(({ label, address, runtimeCodeHash }) => ({ label, address, runtimeCodeHash })) };
}

export async function buildProgramPlan({ foundation, stack, snapshot, artifact, artifactSha256, ...timingOptions }) {
  const checked = validateProgramSnapshot({ foundation, stack, snapshot });
  const timing = launchTiming(snapshot.protocol, snapshot.block.timestamp, timingOptions);
  const configuration = { interfold: PROTOCOL, auctionEscrow: foundation.auction.address, resultSource: foundation.resultSource.address,
    inputVerifier: stack.contracts.inputVerifier.address, receiptVerifier: stack.contracts.computeReceipt.address,
    availabilityVerifier: DA_PINS.verifier.address, poseidon: stack.contracts.poseidon.address,
    paramsHash: checked.paramsHash, inputCircuitId: checked.inputCircuitId, imageId: checked.computedImage,
    biddingEnds: timing.biddingEnds, settlementDeadline: timing.settlementDeadline };
  let deployment = null;
  if (timing.deadlinesSupplied) {
    const tx = await new ContractFactory(artifact.abi, artifact.bytecode.object ?? artifact.bytecode).getDeployTransaction(configuration);
    deployment = { from: DEPLOYER, nonce: snapshot.nonces.latest, chainId: CHAIN_ID, value: '0', data: tx.data };
  }
  const register = new Interface(['function registerE3Program(address)']);
  const bind = new Interface(['function bindProgram(address)']);
  const deferred = ['programDeployment', 'actualProgramDomainKnownAnswer', 'fullVerifierReleaseChecks', 'operatorRegistration',
    'dataAvailabilityPublicationAndBridgeProofs', 'independentRailgunBroadcasterAndPrivateFunding'];
  if (!timing.deadlinesSupplied) deferred.unshift('explicitBiddingEndAndSettlementDeadline');
  return { schemaVersion: 1, scope: 'unsigned-program-launch-preparation', checkedAt: new Date().toISOString(),
    readOnly: true, signed: false, broadcast: false, executableNow: false, readyForCombinedAuction: false,
    exampleOnly: timingOptions.exampleOnly === true,
    deadlineSelection: !timing.deadlinesSupplied ? 'not-selected' : timingOptions.exampleOnly ? 'illustrative-not-user-selected' : 'explicit-ISO-arguments',
    status: timing.deadlinesSupplied ? 'unsigned-deployment-prepared-launch-gated' : 'waiting-for-explicit-launch-deadlines',
    chainId: CHAIN_ID, block: snapshot.block, deployer: DEPLOYER, currentNonce: snapshot.nonces.latest,
    predictedProgramAddress: checked.predicted, addressPredictionConditionalOnUnchangedNonce: true,
    configuration, timing, dependencies: checked.codePins,
    protocolSnapshot: { address: PROTOCOL, owner: snapshot.protocol.owner, requestsPaused: snapshot.protocol.requestsPaused,
      nextE3Id: String(snapshot.protocol.nextE3Id), parameterSet: 2, paramsHash: checked.paramsHash,
      runtimeCodeHash: snapshot.runtimeCodeHashes[getAddress(PROTOCOL).toLowerCase()] },
    programArtifactSha256: hash(artifactSha256, 'program artifact SHA256'),
    unsignedDeployment: deployment,
    registration: { executableNow: false, unsigned: true, to: PROTOCOL, from: snapshot.protocol.owner, value: '0',
      data: register.encodeFunctionData('registerE3Program', [checked.predicted]), requires: ['deployedAndRuntimeVerifiedProgram', 'operatorReviewAndAuthority'] },
    sourceBinding: { executableNow: false, unsigned: true, to: foundation.resultSource.address, from: DEPLOYER, value: '0',
      data: bind.encodeFunctionData('bindProgram', [checked.predicted]), oneTimeIrreversibleBinding: true,
      requires: ['programDeployment', 'operatorRegistration', 'verifyReleaseSuccessIncludingActualProgramDomainProofAndDA', 'finalDependencyAndDeadlineRecheck'] },
    actualProgramDomainKnownAnswer: { status: 'missing', fixtureProofsDoNotSatisfyThisGate: true },
    releaseGate: { verifyReleaseUnchanged: true, operationalChecksPassed: false },
    operator: { registrationAuthority: snapshot.protocol.owner, deployerIsRegistrationAuthority: same(snapshot.protocol.owner, DEPLOYER),
      requestsPaused: snapshot.protocol.requestsPaused },
    deferredRequirements: deferred,
    advisories: ['Refresh nonce, code hashes, chain state, deadlines and timeout defaults immediately before any later signing.',
      'The predicted address is not a nonce reservation. A transaction from the deployer changes it.',
      'Avail publication work remains deferred; only existing Ethereum dependency code and immutable wiring were read.',
      'This tool never signs, broadcasts, deploys, registers, binds, requests an E3 or opens the escrow.',
      ...(snapshot.protocol.requestsPaused ? ['Interfold requests are currently paused.'] : [])] };
}
