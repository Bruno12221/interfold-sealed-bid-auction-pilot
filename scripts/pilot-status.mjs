import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { Contract, ZeroAddress, formatEther, keccak256 } from 'ethers';
import { sepoliaProvider, PROTOCOL, DEPLOYER, CHAIN_ID, protocolAbi } from './config.mjs';
import { verifyRelease } from './lib/release.mjs';

const deployment = JSON.parse(await readFile('deployments/sepolia.json', 'utf8'));
const provider = await sepoliaProvider();
const blockers = [];
const advisories = [];
const report = { checkedAt: new Date().toISOString(), readOnly: true, chainId: CHAIN_ID, readyForCombinedAuction: false };
try {
  const block = await provider.getBlock('latest');
  const atBlock = { blockTag: block.number };
  const protocol = new Contract(PROTOCOL, [...protocolAbi, 'function nexte3Id() view returns(uint256)',
    'function paramSetRegistry(uint8) view returns(bytes)', 'function maxDuration() view returns(uint256)',
    'function ciphernodeRegistry() view returns(address)', 'function markFailedGracePeriod() view returns(uint256)',
    'function getTimeoutConfig() view returns(tuple(uint256 dkgWindow,uint256 computeWindow,uint256 decryptionWindow))',
    'function getE3TimeoutConfig(uint256) view returns(tuple(uint256 dkgWindow,uint256 computeWindow,uint256 decryptionWindow))',
    'function getDeadlines(uint256) view returns(tuple(uint256 dkgDeadline,uint256 computeDeadline,uint256 decryptionDeadline))',
  ], provider);
  const source = new Contract(deployment.resultSource.address, ['function program() view returns(address)', 'function isReady() view returns(bool)'], provider);
  const auction = new Contract(deployment.auction.address, [
    'function state() view returns(uint8)', 'function bidCount() view returns(uint256)',
    'function biddingEnds() view returns(uint64)', 'function settlementDeadline() view returns(uint64)',
    'function seller() view returns(address)', 'function nft() view returns(address)',
    'function tokenId() view returns(uint256)', 'function winner() view returns(address)',
    'function e3Id() view returns(uint256)', 'function totalCredits() view returns(uint256)',
  ], provider);
  const [paused, owner, nextE3, params, program, sourceReady, state, bidCount, balance,
    timeoutConfig, maxDuration, registryAddress, failureGrace, seller, nftAddress, tokenId,
    winner, auctionE3Id, auctionBiddingEnds, auctionSettlementDeadline, totalCredits, auctionBalance] = await Promise.all([
    protocol.requestsPaused(atBlock), protocol.owner(atBlock), protocol.nexte3Id(atBlock), protocol.paramSetRegistry(2, atBlock),
    source.program(atBlock), source.isReady(atBlock), auction.state(atBlock), auction.bidCount(atBlock), provider.getBalance(DEPLOYER, block.number),
    protocol.getTimeoutConfig(atBlock), protocol.maxDuration(atBlock), protocol.ciphernodeRegistry(atBlock),
    protocol.markFailedGracePeriod(atBlock), auction.seller(atBlock), auction.nft(atBlock), auction.tokenId(atBlock),
    auction.winner(atBlock), auction.e3Id(atBlock), auction.biddingEnds(atBlock), auction.settlementDeadline(atBlock),
    auction.totalCredits(atBlock), provider.getBalance(deployment.auction.address, block.number),
  ]);
  const registry = new Contract(registryAddress, ['function randomnessRequestTimeout() view returns(uint256)',
    'function sortitionSubmissionWindow() view returns(uint256)'], provider);
  const nft = new Contract(nftAddress, ['function ownerOf(uint256) view returns(address)'], provider);
  const [randomnessTimeout, sortitionWindow, nftOwner] = await Promise.all([
    registry.randomnessRequestTimeout(atBlock), registry.sortitionSubmissionWindow(atBlock), nft.ownerOf(tokenId, atBlock),
  ]);
  const encodeTimeouts = value => ({ dkgWindowSeconds: String(value.dkgWindow),
    computeWindowSeconds: String(value.computeWindow), decryptionWindowSeconds: String(value.decryptionWindow) });
  const stateName = ['Created', 'Bidding', 'Settled', 'Cancelled'][Number(state)] ?? 'Unknown';
  const sameAddress = (a, b) => a.toLowerCase() === b.toLowerCase();
  const expectedNftOwner = state === 1n ? deployment.auction.address
    : state === 2n && winner !== ZeroAddress ? winner : seller;
  const ownershipMatchesState = sameAddress(nftOwner, expectedNftOwner);
  const committeeReservation = randomnessTimeout + sortitionWindow + timeoutConfig.dkgWindow;
  report.interfold = { blockNumber: block.number, chainTimestamp: block.timestamp, protocol: PROTOCOL,
    owner, requestsPaused: paused, nextE3Id: String(nextE3), secureParamsHash: keccak256(params),
    sourceReady, program, auctionState: stateName, bidCount: Number(bidCount), sellerBalanceEth: formatEther(balance),
    timeoutConfig: encodeTimeouts(timeoutConfig), requestTiming: { maxDurationSeconds: String(maxDuration),
      registry: registryAddress, randomnessRequestTimeoutSeconds: String(randomnessTimeout),
      sortitionSubmissionWindowSeconds: String(sortitionWindow), committeeReservationSeconds: String(committeeReservation),
      maximumInputReservationSeconds: String(maxDuration - timeoutConfig.computeWindow - timeoutConfig.decryptionWindow),
      lifecycleRule: 'max(inputWindowEnd - requestTime, committeeReservation) + computeWindow + decryptionWindow <= maxDuration',
      timeoutConfigFrozenAtRequest: true, markFailedGracePeriodSeconds: String(failureGrace),
      failureGraceExtendsPublicationDeadlines: false } };
  report.auction = { address: deployment.auction.address, state: stateName, e3Id: String(auctionE3Id),
    biddingEnds: String(auctionBiddingEnds), settlementDeadline: String(auctionSettlementDeadline),
    bidCount: Number(bidCount), totalCreditsWei: String(totalCredits), balanceEth: formatEther(auctionBalance),
    nft: { address: nftAddress, tokenId: String(tokenId), owner: nftOwner, seller, winner,
      heldByAuction: sameAddress(nftOwner, deployment.auction.address),
      expectedOwnerAtStateTransition: expectedNftOwner, ownershipMatchesState,
      check: state > 1n ? 'Final-state recipient may legitimately transfer the NFT again.'
        : 'Created requires seller ownership; Bidding requires auction escrow ownership.' } };
  if (state > 3n) blockers.push('Auction returned an unknown state');
  if (state <= 1n && !ownershipMatchesState) blockers.push(`NFT ownership does not match auction state ${stateName}`);
  if (!sameAddress(nftAddress, deployment.demoNFT.address) || tokenId !== 1n) blockers.push('Auction NFT differs from the deployed demo NFT #1');
  let applicableTimeouts = timeoutConfig;
  let timeoutSource = 'latest-protocol-config-not-yet-frozen';
  if (state !== 0n && state <= 3n) {
    const [frozen, deadlines] = await Promise.all([
      protocol.getE3TimeoutConfig(auctionE3Id, atBlock), protocol.getDeadlines(auctionE3Id, atBlock),
    ]);
    applicableTimeouts = frozen;
    timeoutSource = 'frozen-auction-e3-config';
    report.auction.e3Timing = { timeoutConfig: encodeTimeouts(frozen),
      deadlines: Object.fromEntries(['dkgDeadline', 'computeDeadline', 'decryptionDeadline'].map(name => [name, String(deadlines[name])])),
      secondsUntilDeadline: Object.fromEntries(['dkgDeadline', 'computeDeadline', 'decryptionDeadline']
        .map(name => [name, deadlines[name] === 0n ? null : String(deadlines[name] - BigInt(block.timestamp))])) };
  }
  try {
    const artifact = JSON.parse(await readFile('out/IInterfoldRead.sol/IInterfoldRead.json', 'utf8'));
    const read = new Contract(PROTOCOL, artifact.abi, provider);
    const prefix = (nextE3 >> 96n) << 96n, counter = nextE3 - prefix;
    report.interfold.recentE3s = [];
    for (let offset = counter < 8n ? counter : 8n; offset > 0n; --offset) {
      const id = nextE3 - offset;
      const [round, stage] = await Promise.all([read.getE3(id, atBlock), read.getE3Stage(id, atBlock)]);
      report.interfold.recentE3s.push({ e3Id: String(id), program: round.e3Program, parameterSet: Number(round.paramSet),
        stage: ['None', 'Requested', 'CommitteeFinalized', 'KeyPublished', 'CiphertextReady', 'Complete', 'Failed'][Number(stage)],
        inputWindowEnd: String(round.inputWindow[1]), committeeKeyPublished: BigInt(round.committeePublicKey) !== 0n });
    }
    report.interfold.secure8192CompletedInRecentSample = report.interfold.recentE3s.some(x => x.parameterSet === 2 && x.stage === 'Complete');
  } catch (error) { report.interfold.recentE3CheckError = error.shortMessage ?? error.message; }
  if (paused) blockers.push('Interfold requests are paused');
  if (program === ZeroAddress) blockers.push('No deployed, registered auction program is bound to the result source');
  else {
    report.interfold.programRegistered = await protocol.e3Programs(program, atBlock);
    if (!report.interfold.programRegistered) blockers.push('Auction program is not registered by the Interfold owner');
    const p = new Contract(program, ['function biddingEnds() view returns(uint64)', 'function settlementDeadline() view returns(uint64)'], provider);
    report.interfold.biddingEnds = String(await p.biddingEnds(atBlock));
    report.interfold.settlementDeadline = String(await p.settlementDeadline(atBlock));
    if (BigInt(report.interfold.biddingEnds) <= BigInt(block.timestamp)) blockers.push('Program bidding deadline has passed');
  }
  const configuredEnd = state !== 0n ? auctionBiddingEnds : BigInt(report.interfold.biddingEnds ?? 0);
  const configuredSettlement = state !== 0n ? auctionSettlementDeadline : BigInt(report.interfold.settlementDeadline ?? 0);
  const hasDeadlines = configuredEnd > 0n && configuredSettlement > configuredEnd;
  const fullProtocolWindow = applicableTimeouts.computeWindow + applicableTimeouts.decryptionWindow;
  const settlementWindow = hasDeadlines ? configuredSettlement - configuredEnd : null;
  const headroom = hasDeadlines ? settlementWindow - fullProtocolWindow : null;
  report.settlementTimingAdvisory = { timeoutSource, biddingEnds: hasDeadlines ? String(configuredEnd) : null,
    settlementDeadline: hasDeadlines ? String(configuredSettlement) : null,
    fullProtocolWindowSeconds: String(fullProtocolWindow), settlementWindowSeconds: settlementWindow === null ? null : String(settlementWindow),
    headroomAfterFullProtocolWindowSeconds: headroom === null ? null : String(headroom),
    allowsFullProtocolWindowAndSettlementMargin: headroom === null ? null : headroom > 0n,
    note: 'Planning advisory, not a protocol requirement or ETA. Full compute and decryption windows need extra transaction margin because escrow settlement is rejected at its deadline.' };
  try {
    const stack = JSON.parse(await readFile('deployments/verifiers-sepolia.json', 'utf8'));
    const contracts = await Promise.all(Object.entries(stack.contracts).map(async ([name, item]) => ({
      name, address: item.address, runtimeMatches: keccak256(await provider.getCode(item.address, block.number)) === item.runtimeCodeHash,
    })));
    report.verifierStack = { status: stack.status, contracts,
      allEightRuntimesMatch: contracts.length === 8 && contracts.every(item => item.runtimeMatches),
      fixtureKnownAnswersCheckedAt: stack.knownAnswers?.checkedAt ?? null,
      fixtureKnownAnswersPassed: stack.knownAnswers?.fixtureKnownAnswersPassed === true,
      actualProgramReleaseReady: false, programDeploymentDeferred: stack.programDeployed === false };
    if (!report.verifierStack.allEightRuntimesMatch) blockers.push('Reusable verifier stack is incomplete or a runtime differs');
  } catch (error) {
    report.verifierStack = { status: error.code === 'ENOENT' ? 'not-deployed' : 'check-failed', actualProgramReleaseReady: false };
  }
  if (headroom !== null && headroom <= 0n) advisories.push('Configured settlement deadline does not leave margin after the full protocol compute and decryption windows; choose deadlines from measured workload and intended timeout tolerance');
  if (!sourceReady) blockers.push('Auction result source reports not ready');
  if (state > 1n) blockers.push('The deployed auction is already finalized');
  const path = process.env.PILOT_RELEASE_MANIFEST;
  if (!path) blockers.push('No generated input/compute/DA verifier release manifest or known-answer proofs supplied');
  else {
    try { report.release = await verifyRelease(path, provider, { auction: deployment.auction.address, resultSource: deployment.resultSource.address, program }); }
    catch (error) { blockers.push(`Release checks failed: ${error.shortMessage ?? error.message}`); }
  }
  try {
    const railgun = JSON.parse(await readFile('pilot/railgun/.local/preflight.json', 'utf8'));
    const ageMs = Date.now() - Date.parse(railgun.observedAt);
    report.railgun = { observedAt: railgun.observedAt, ageSeconds: Math.round(ageMs / 1000), fundingReady: railgun.fundingReady,
      broadcaster: railgun.broadcasters?.result?.status ?? null,
      indexerBlockLag: railgun.graphql?.blockLag ?? null };
    if (!Number.isFinite(ageMs) || ageMs < -60000 || ageMs > 10 * 60 * 1000) blockers.push('Railgun preflight is stale; rerun it');
    if (!railgun.fundingReady) blockers.push('Railgun funding preflight has not established a usable independent Sepolia broadcaster');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    blockers.push('Railgun live preflight has not been run');
  }
  report.blockers = blockers;
  report.advisories = advisories;
  report.readyForCombinedAuction = blockers.length === 0;
  report.caveat = 'Operational readiness does not constitute a cryptographic audit or guarantee committee/broadcaster liveness.';
  await mkdir('.pilot', { recursive: true, mode: 0o700 });
  await writeFile('.pilot/status.json', JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report, null, 2));
  if (!report.readyForCombinedAuction) process.exitCode = 2;
} finally { provider.destroy(); }
