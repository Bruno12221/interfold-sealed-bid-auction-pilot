import { readFile, mkdir, open, rename } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Contract, getAddress, getCreateAddress, keccak256 } from 'ethers';
import { CHAIN_ID, DEPLOYER, PROTOCOL, sepoliaProvider } from './config.mjs';
import { buildProgramPlan, DA_PINS, STACK_LABELS } from './lib/program-plan.mjs';

export function parseProgramPlanArguments(args) {
  const names = { '--bidding-end': 'biddingEndIso', '--settlement-deadline': 'settlementDeadlineIso',
    '--settlement-margin-seconds': 'settlementMarginSeconds', '--launch-margin-seconds': 'launchMarginSeconds' };
  const result = {};
  for (let i = 0; i < args.length; ++i) {
    if (args[i] === '--example-only') {
      if (result.exampleOnly) throw new Error('Duplicate --example-only');
      result.exampleOnly = true; continue;
    }
    const key = Object.hasOwn(names, args[i]) ? names[args[i]] : undefined, value = args[i + 1];
    if (!key || value === undefined || value.startsWith('--') || Object.hasOwn(result, key)) throw new Error('Usage: node scripts/prepare-program.mjs [--bidding-end ISO --settlement-deadline ISO] [--example-only] [--settlement-margin-seconds N] [--launch-margin-seconds N]');
    result[key] = value;
    ++i;
  }
  return result;
}

export async function collectProgramSnapshot(provider, foundation, stack) {
  const network = await provider.getNetwork();
  if (network.chainId !== BigInt(CHAIN_ID)) throw new Error('Expected Sepolia chain11155111');
  const block = await provider.getBlock('latest');
  if (!block?.hash) throw new Error('Missing latest block');
  const at = { blockTag: block.number };
  const source = new Contract(foundation.resultSource.address, ['function program() view returns(address)',
    'function isReady() view returns(bool)', 'function binder() view returns(address)'], provider);
  const auction = new Contract(foundation.auction.address, ['function state() view returns(uint8)',
    'function bidCount() view returns(uint256)', 'function totalCredits() view returns(uint256)',
    'function seller() view returns(address)', 'function nft() view returns(address)', 'function tokenId() view returns(uint256)',
    'function resultSource() view returns(address)'], provider);
  const nft = new Contract(foundation.demoNFT.address, ['function ownerOf(uint256) view returns(address)'], provider);
  const protocol = new Contract(PROTOCOL, ['function owner() view returns(address)', 'function requestsPaused() view returns(bool)',
    'function paramSetRegistry(uint8) view returns(bytes)', 'function nexte3Id() view returns(uint256)',
    'function maxDuration() view returns(uint256)', 'function ciphernodeRegistry() view returns(address)',
    'function getTimeoutConfig() view returns(tuple(uint256 dkgWindow,uint256 computeWindow,uint256 decryptionWindow))'], provider);
  const addresses = [...new Set([PROTOCOL, foundation.auction.address, foundation.resultSource.address, foundation.demoNFT.address,
    ...STACK_LABELS.map(x => stack.contracts[x].address), ...Object.values(DA_PINS).map(x => x.address)].map(getAddress))];
  const [codeRows, latest, pending, bound, ready, binder, state, bids, credits, balance, seller, nftAddress, token,
    nftOwner, resultSource, owner, paused, params, nextE3, maxDuration, registryAddress, timeouts] = await Promise.all([
    Promise.all(addresses.map(async address => { const code = await provider.getCode(address, block.number); return [address.toLowerCase(), code === '0x' ? null : keccak256(code)]; })),
    provider.getTransactionCount(DEPLOYER, block.number), provider.getTransactionCount(DEPLOYER, 'pending'),
    source.program(at), source.isReady(at), source.binder(at), auction.state(at), auction.bidCount(at), auction.totalCredits(at),
    provider.getBalance(foundation.auction.address, block.number), auction.seller(at), auction.nft(at), auction.tokenId(at),
    nft.ownerOf(1n, at), auction.resultSource(at), protocol.owner(at), protocol.requestsPaused(at), protocol.paramSetRegistry(2, at),
    protocol.nexte3Id(at), protocol.maxDuration(at), protocol.ciphernodeRegistry(at), protocol.getTimeoutConfig(at),
  ]);
  const registry = new Contract(registryAddress, ['function randomnessRequestTimeout() view returns(uint256)',
    'function sortitionSubmissionWindow() view returns(uint256)'], provider);
  const receiptAbi = ['function imageId() view returns(bytes32)', 'function appExeCommit() view returns(bytes32)',
    'function appVmCommit() view returns(bytes32)', 'function verifier() view returns(address)'];
  const binding = new Contract(stack.contracts.bindingReceipt.address, receiptAbi, provider);
  const compute = new Contract(stack.contracts.computeReceipt.address, receiptAbi, provider);
  const input = new Contract(stack.contracts.inputVerifier.address, ['function circuitId() view returns(bytes32)',
    'function encryptionVerifier() view returns(address)', 'function bindingVerifier() view returns(address)'], provider);
  const da = new Contract(DA_PINS.verifier.address, ['function bridge() view returns(address)', 'function vectorx() view returns(address)'], provider);
  const bridge = new Contract(DA_PINS.bridge.address, ['function vectorx() view returns(address)'], provider);
  const [randomness, sortition, predictedCode, inputCircuitId, computeImageId, computeExe, computeVm, computeHalo,
    bindingImageId, bindingExe, bindingVm, bindingHalo, encryption, bindingVerifier, verifierBridge, verifierVectorx, bridgeVectorx] = await Promise.all([
    registry.randomnessRequestTimeout(at), registry.sortitionSubmissionWindow(at),
    provider.getCode(getCreateAddress({ from: DEPLOYER, nonce: latest }), block.number),
    input.circuitId(at), compute.imageId(at), compute.appExeCommit(at), compute.appVmCommit(at), compute.verifier(at),
    binding.imageId(at), binding.appExeCommit(at), binding.appVmCommit(at), binding.verifier(at),
    input.encryptionVerifier(at), input.bindingVerifier(at), da.bridge(at), da.vectorx(at), bridge.vectorx(at),
  ]);
  const [finalLatest, finalPending, sameBlock] = await Promise.all([
    provider.getTransactionCount(DEPLOYER, 'latest'), provider.getTransactionCount(DEPLOYER, 'pending'), provider.getBlock(block.number),
  ]);
  if (sameBlock?.hash !== block.hash) throw new Error('Snapshot block changed during preparation');
  return { chainId: CHAIN_ID, block: { number: block.number, hash: block.hash, timestamp: block.timestamp },
    runtimeCodeHashes: Object.fromEntries(codeRows), predictedProgramHasCode: predictedCode !== '0x',
    nonces: { latest, pending, finalLatest, finalPending },
    foundation: { program: bound, sourceReady: ready, binder, state: String(state), bidCount: String(bids),
      totalCreditsWei: String(credits), balanceWei: String(balance), seller, nft: nftAddress, tokenId: String(token), nftOwner, resultSource },
    protocol: { owner, requestsPaused: paused, paramSet2: params, nextE3Id: String(nextE3), maxDurationSeconds: String(maxDuration),
      registryAddress, randomnessRequestTimeoutSeconds: String(randomness), sortitionSubmissionWindowSeconds: String(sortition),
      timeouts: { dkgWindowSeconds: String(timeouts.dkgWindow), computeWindowSeconds: String(timeouts.computeWindow), decryptionWindowSeconds: String(timeouts.decryptionWindow) } },
    identities: { inputCircuitId, computeImageId, computeExeCommit: computeExe, computeVmCommit: computeVm, computeHalo2: computeHalo,
      bindingImageId, bindingExeCommit: bindingExe, bindingVmCommit: bindingVm, bindingHalo2: bindingHalo,
      encryptionVerifier: encryption, bindingVerifier },
    availabilityWiring: { verifierBridge, verifierVectorx, bridgeVectorx } };
}

async function savePlan(report) {
  await mkdir('.pilot', { recursive: true, mode: 0o700 });
  const path = resolve('.pilot/program-launch-plan.json');
  const temporary = path + `.${process.pid}.tmp`;
  const file = await open(temporary, 'wx', 0o600);
  try { await file.writeFile(JSON.stringify(report, null, 2) + '\n'); await file.sync(); } finally { await file.close(); }
  await rename(temporary, path);
  return path;
}

async function main() {
  const options = parseProgramPlanArguments(process.argv.slice(2));
  const foundation = JSON.parse(await readFile('deployments/sepolia.json', 'utf8'));
  const stack = JSON.parse(await readFile('deployments/verifiers-sepolia.json', 'utf8'));
  const artifactBytes = await readFile('out/AuctionE3Program.sol/AuctionE3Program.json');
  const artifact = JSON.parse(artifactBytes.toString('utf8'));
  const provider = await sepoliaProvider();
  try {
    const snapshot = await collectProgramSnapshot(provider, foundation, stack);
    const plan = await buildProgramPlan({ foundation, stack, snapshot, artifact,
      artifactSha256: '0x' + createHash('sha256').update(artifactBytes).digest('hex'), ...options });
    const path = await savePlan(plan);
    console.log(JSON.stringify({ path, status: plan.status, predictedProgramAddress: plan.predictedProgramAddress,
      unsignedDeploymentPrepared: plan.unsignedDeployment !== null, signed: false, broadcast: false,
      actualProgramDomainKnownAnswer: plan.actualProgramDomainKnownAnswer.status, deferredRequirements: plan.deferredRequirements }, null, 2));
  } finally { provider.destroy(); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { await main(); } catch (error) {
    const failure = { schemaVersion: 1, scope: 'unsigned-program-launch-preparation', checkedAt: new Date().toISOString(),
      readOnly: true, executableNow: false, signed: false, broadcast: false, status: 'rejected', error: error.shortMessage ?? error.message };
    await savePlan(failure); console.error(failure.error); process.exitCode = 1;
  }
}
