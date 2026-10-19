import { readFile, writeFile, rename, mkdir } from 'node:fs/promises';
import { dirname, resolve, relative } from 'node:path';
import { AbiCoder, Contract, ContractFactory, Interface, Wallet, ZeroAddress,
  getCreateAddress, getAddress, keccak256, formatEther, parseEther } from 'ethers';
import { sepoliaProvider, DEPLOYER, PROTOCOL } from './config.mjs';
import { loadVerifierStackArtifacts, linkCreationBytecode, assertRuntimeMatchesArtifact,
  receiptImageId, PINNED_OPENVM, ACIR_SHA256, assertVerifierNetworkMode } from './lib/verifier-stack.mjs';

const [command = 'plan', ...flags] = process.argv.slice(2);
if (!['plan', 'deploy', 'check'].includes(command) || flags.some(x => x !== '--fork-test')) {
  throw new Error('Usage: node scripts/deploy-verifiers.mjs plan|deploy|check [--fork-test]');
}
const fork = flags.includes('--fork-test');
const path = fork ? '.pilot/verifiers-fork.json' : 'deployments/verifiers-sepolia.json';
let provider;
const foundation = JSON.parse(await readFile('deployments/sepolia.json', 'utf8'));
const abi = AbiCoder.defaultAbiCoder();
const budget = parseEther('0.005');
let record;
const currentNonce = async tag => Number(BigInt(await provider.send('eth_getTransactionCount', [DEPLOYER, tag])));
const freshCode = address => provider.send('eth_getCode', [address, 'latest']);

async function checkFixtureHashes() {
  const { createHash } = await import('node:crypto');
  for (const [base, file] of [['test/fixtures/openvm-receipts', 'provenance.json'], ['test/fixtures/auction-input', 'provenance.json']]) {
    const provenance = JSON.parse(await readFile(`${base}/${file}`));
    const files = base.endsWith('openvm-receipts')
      ? ['binding', 'compute'].flatMap(job => ['seal', 'journal'].map(kind => provenance[job][kind]))
      : [{ path: 'proof.bin', sha256: provenance.proofSha256 }, { path: 'statement.bin', sha256: provenance.statementSha256 }];
    for (const item of files) {
      const bytes = await readFile(`${base}/${item.path}`);
      if (createHash('sha256').update(bytes).digest('hex') !== item.sha256.replace(/^0x/, '')) throw new Error('Known-answer fixture hash differs');
    }
  }
}

async function recordedArtifacts(artifacts, deployment) {
  const { createHash } = await import('node:crypto');
  const names = { bindingReceipt: 'OpenVmReceiptVerifier', computeReceipt: 'OpenVmReceiptVerifier',
    relations: 'RelationsLib', zkTranscript: 'ZKTranscriptLib', encryptionVerifier: 'HonkVerifier',
    inputVerifier: 'AuctionInputVerifier', poseidon: 'AuctionPoseidon' };
  for (const [label, name] of Object.entries(names)) {
    const item = deployment.contracts[label];
    const artifactPath = resolve(dirname(path), item.artifactPath);
    const bytes = await readFile(artifactPath);
    if ('0x' + createHash('sha256').update(bytes).digest('hex') !== item.artifactSha256) throw new Error('Recorded compiler artifact digest differs');
    artifacts[name] = { ...JSON.parse(bytes), artifactPath, artifactSha256: item.artifactSha256, artifactBytes: bytes };
  }
  return artifacts;
}

async function save() {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path + '.tmp', JSON.stringify(record, null, 2) + '\n', { mode: 0o600 });
  await rename(path + '.tmp', path);
}

async function disabledFoundation() {
  for (const field of ['auction', 'resultSource']) {
    if (keccak256(await provider.getCode(foundation[field].address)) !== foundation[field].runtimeCodeHash) {
      throw new Error(`Foundation runtime differs: ${field}`);
    }
  }
  const source = new Contract(foundation.resultSource.address,
    ['function program() view returns(address)', 'function isReady() view returns(bool)', 'function binder() view returns(address)'], provider);
  const auction = new Contract(foundation.auction.address,
    ['function state() view returns(uint8)', 'function bidCount() view returns(uint256)'], provider);
  const [program, ready, binder, state, bids, balance] = await Promise.all([
    source.program(), source.isReady(), source.binder(), auction.state(), auction.bidCount(),
    provider.getBalance(foundation.auction.address),
  ]);
  if (program !== ZeroAddress || ready || binder !== getAddress(DEPLOYER) || state !== 0n || bids !== 0n || balance !== 0n) {
    throw new Error('Expected the original disabled, unbound, empty auction');
  }
  return { sourceUnbound: true, sourceReady: false, auctionState: 'Created', bids: 0, auctionBalanceWei: '0' };
}

function buildSteps(artifacts, startNonce) {
  const labels = ['halo2', 'bindingReceipt', 'computeReceipt', 'relations', 'zkTranscript', 'encryptionVerifier', 'inputVerifier', 'poseidon'];
  const addresses = Object.fromEntries(labels.map((label, i) => [label, getCreateAddress({ from: DEPLOYER, nonce: startNonce + i })]));
  const libraries = { RelationsLib: addresses.relations, ZKTranscriptLib: addresses.zkTranscript };
  const bindingImage = receiptImageId(addresses.halo2, PINNED_OPENVM.bindingExeCommit, PINNED_OPENVM.vmCommit);
  const definitions = [
    ['halo2', 'rawHalo2', []],
    ['bindingReceipt', 'OpenVmReceiptVerifier', [addresses.halo2, PINNED_OPENVM.bindingExeCommit, PINNED_OPENVM.vmCommit]],
    ['computeReceipt', 'OpenVmReceiptVerifier', [addresses.halo2, PINNED_OPENVM.computeExeCommit, PINNED_OPENVM.vmCommit]],
    ['relations', 'RelationsLib', []], ['zkTranscript', 'ZKTranscriptLib', []],
    ['encryptionVerifier', 'HonkVerifier', []],
    ['inputVerifier', 'AuctionInputVerifier', [addresses.encryptionVerifier, addresses.bindingReceipt, ACIR_SHA256, bindingImage]],
    ['poseidon', 'AuctionPoseidon', []],
  ];
  return definitions.map(([label, artifactName, args], i) => {
    const artifact = artifacts[artifactName];
    const bytecode = artifactName === 'rawHalo2' ? artifact.bytecode : linkCreationBytecode(artifact, libraries);
    return { label, artifactName, artifact, factory: new ContractFactory(artifact.abi, bytecode), args,
      nonce: startNonce + i, address: addresses[label], libraries };
  });
}

async function runtimeCheck(step) {
  const code = await freshCode(step.address);
  if (step.artifactName === 'rawHalo2') {
    if (keccak256(code) !== PINNED_OPENVM.rawRuntimeCodeHash) throw new Error('Pinned raw Halo2 runtime differs');
  } else assertRuntimeMatchesArtifact(step.artifact, code, step.libraries);
  return keccak256(code);
}

async function knownAnswers(steps) {
  const address = Object.fromEntries(steps.map(x => [x.label, x.address]));
  const receiptAbi = ['function imageId() view returns(bytes32)', 'function appExeCommit() view returns(bytes32)',
    'function appVmCommit() view returns(bytes32)', 'function verifier() view returns(address)',
    'function verify(bytes,bytes32,bytes32) view'];
  const checks = [];
  async function reject(to, data) {
    try {
      const result = await provider.call({ to, from: DEPLOYER, data, gasLimit: 16_000_000n });
      if (result === '0x' || result.length !== 66 || abi.decode(['bool'], result)[0] !== false) {
        throw new Error('Tampered known answer accepted');
      }
    } catch (error) {
      if (error.code !== 'CALL_EXCEPTION') throw error;
    }
  }
  for (const job of ['binding', 'compute']) {
    const target = address[job + 'Receipt'];
    const c = new Contract(target, receiptAbi, provider);
    const exe = job === 'binding' ? PINNED_OPENVM.bindingExeCommit : PINNED_OPENVM.computeExeCommit;
    const image = receiptImageId(address.halo2, exe, PINNED_OPENVM.vmCommit);
    if (await c.imageId() !== image || await c.appExeCommit() !== exe || await c.appVmCommit() !== PINNED_OPENVM.vmCommit
      || await c.verifier() !== address.halo2) throw new Error(`${job} receipt configuration differs`);
    const seal = await readFile(`test/fixtures/openvm-receipts/${job}.seal.bin`);
    const journal = await readFile(`test/fixtures/openvm-receipts/${job}.journal.bin`);
    const { createHash } = await import('node:crypto');
    const digest = '0x' + createHash('sha256').update(journal).digest('hex');
    const valid = c.interface.encodeFunctionData('verify', [seal, image, digest]);
    if (await provider.call({ to: target, from: DEPLOYER, data: valid, gasLimit: 16_000_000n }) !== '0x') throw new Error('Unexpected receipt return');
    const changed = Buffer.from(seal); changed[96 + 0x41f] ^= 1;
    await reject(target, c.interface.encodeFunctionData('verify', [changed, image, digest]));
    await reject(target, c.interface.encodeFunctionData('verify', [seal, image, '0x' + (BigInt(digest) ^ 1n).toString(16).padStart(64, '0')]));
    checks.push({ label: job, validProofAccepted: true, modifiedProofRejected: true, wrongJournalRejected: true, imageId: image, journalDigest: digest });
  }
  const statementType = '(uint256,address,address,address,bytes32,uint256,bytes32,bytes32,uint256,address,uint256,bytes32,bytes32)';
  const statement = abi.decode([statementType], await readFile('test/fixtures/auction-input/statement.bin'))[0];
  const noir = await readFile('test/fixtures/auction-input/proof.bin');
  const binding = await readFile('test/fixtures/openvm-receipts/binding.seal.bin');
  const iface = new Interface([`function verify(bytes,${statementType}) view returns(bool)`]);
  const valid = iface.encodeFunctionData('verify', [abi.encode(['bytes', 'bytes'], [noir, binding]), statement]);
  const result = await provider.call({ to: address.inputVerifier, from: DEPLOYER, data: valid, gasLimit: 16_000_000n });
  if (result.length !== 66 || abi.decode(['bool'], result)[0] !== true) throw new Error('Real composed proof rejected');
  const changedNoir = Buffer.from(noir); changedNoir[959] ^= 1;
  await reject(address.inputVerifier, iface.encodeFunctionData('verify', [abi.encode(['bytes', 'bytes'], [changedNoir, binding]), statement]));
  const changedBinding = Buffer.from(binding); changedBinding[96 + 0x41f] ^= 1;
  await reject(address.inputVerifier, iface.encodeFunctionData('verify', [abi.encode(['bytes', 'bytes'], [noir, changedBinding]), statement]));
  checks.push({ label: 'composedInput', validProofAccepted: true, modifiedNoirRejected: true,
    modifiedBindingRejected: true, fixtureDomainOnly: true, actualProgramDomainProofVerified: false });
  const input = new Contract(address.inputVerifier, ['function circuitId() view returns(bytes32)',
    'function bindingImageId() view returns(bytes32)', 'function encryptionVerifier() view returns(address)',
    'function bindingVerifier() view returns(address)', 'function encryptionAcirSha256() view returns(bytes32)',
    'function encryptionVerifierCodeHash() view returns(bytes32)', 'function bindingVerifierCodeHash() view returns(bytes32)'], provider);
  if (await input.encryptionVerifier() !== address.encryptionVerifier || await input.bindingVerifier() !== address.bindingReceipt) throw new Error('Composed verifier wiring differs');
  const encryptionHash = keccak256(await freshCode(address.encryptionVerifier));
  const bindingHash = keccak256(await freshCode(address.bindingReceipt));
  const bindingImage = receiptImageId(address.halo2, PINNED_OPENVM.bindingExeCommit, PINNED_OPENVM.vmCommit);
  const expectedCircuit = keccak256(abi.encode(['bytes32', 'bytes32', 'bytes32', 'bytes32', 'bytes32'], [
    keccak256(Buffer.from('interfold.auction.input.secure8192.composed.v1')), encryptionHash, bindingHash, ACIR_SHA256, bindingImage,
  ]));
  if (await input.bindingImageId() !== bindingImage || await input.encryptionAcirSha256() !== ACIR_SHA256
    || await input.encryptionVerifierCodeHash() !== encryptionHash || await input.bindingVerifierCodeHash() !== bindingHash
    || await input.circuitId() !== expectedCircuit) throw new Error('Composed verifier circuit/ACIR/code identities differ');
  return { checkedAt: new Date().toISOString(), blockNumber: await provider.getBlockNumber(), checks,
    inputCircuitId: await input.circuitId(), bindingImageId: await input.bindingImageId(),
    fixtureKnownAnswersPassed: true, actualProgramReleaseReady: false };
}

async function secret() {
  if (process.env.PRIVATE_KEY) {
    const value = process.env.PRIVATE_KEY; delete process.env.PRIVATE_KEY; return value;
  }
  if (!process.stdin.isTTY) throw new Error('Run in a terminal for hidden key input');
  process.stdout.write('Disposable Sepolia key (hidden): ');
  process.stdin.setRawMode(true); process.stdin.resume();
  return new Promise((resolveKey, reject) => {
    let value = '';
    function finish() { process.stdin.off('data', onData); process.stdin.setRawMode(false); process.stdin.pause(); process.stdout.write('\n'); }
    function onData(chunk) {
      for (const c of chunk.toString()) {
        if (c === '\u0003') { finish(); reject(new Error('Cancelled')); return; }
        if (c === '\r' || c === '\n') { finish(); resolveKey(value.trim()); return; }
        if (c === '\u007f') value = value.slice(0, -1); else value += c;
      }
    }
    process.stdin.on('data', onData);
  });
}

try {
  provider = await sepoliaProvider();
  assertVerifierNetworkMode(await provider.send('web3_clientVersion', []),
    process.env.SEPOLIA_RPC_URL || 'https://ethereum-sepolia.publicnode.com', fork);
  let existing;
  try { existing = JSON.parse(await readFile(path, 'utf8')); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (command === 'deploy' && existing) throw new Error('Verifier deployment record already exists. Use check or inspect partial transactions before recovery.');
  let artifactPaths;
  if (existing && Object.keys(existing.contracts).length === 8) {
    artifactPaths = Object.fromEntries(Object.entries({ OpenVmReceiptVerifier: 'bindingReceipt', RelationsLib: 'relations',
      ZKTranscriptLib: 'zkTranscript', HonkVerifier: 'encryptionVerifier', AuctionInputVerifier: 'inputVerifier', AuctionPoseidon: 'poseidon' })
      .map(([name, label]) => [name, resolve(dirname(path), existing.contracts[label].artifactPath)]));
  }
  let artifacts = await loadVerifierStackArtifacts(process.cwd(), artifactPaths);
  await checkFixtureHashes();
  await disabledFoundation();
  if (existing) artifacts = await recordedArtifacts(artifacts, existing);
  const startNonce = existing?.startNonce ?? await currentNonce('latest');
  const steps = buildSteps(artifacts, startNonce);
  if (command === 'plan') {
    const plan = { schemaVersion: 1, chainId: 11155111, deployer: DEPLOYER, startNonce,
      maxTotalDeploymentSpendEthIncludingFoundation: '0.005', programDeploymentDeferredForImmutableDeadlines: true,
      steps: steps.map(s => ({ label: s.label, address: s.address, nonce: s.nonce,
        artifactPath: relative(process.cwd(), s.artifact.artifactPath), artifactSha256: s.artifact.artifactSha256, constructorArgs: s.args })),
      predictedNextProgramAddress: getCreateAddress({ from: DEPLOYER, nonce: startNonce + steps.length }),
      note: 'Program address prediction is conditional on the deployer nonce. This deploys only reusable verifiers; it never registers/binds a program, requests an E3 or opens an auction.' };
    await mkdir('.pilot', { recursive: true });
    await writeFile('.pilot/verifier-stack-plan.json', JSON.stringify(plan, null, 2) + '\n');
    console.log(JSON.stringify(plan, null, 2));
  } else if (command === 'check') {
    if (!existing) throw new Error('No verifier deployment record');
    for (const step of steps) {
      if (existing.contracts[step.label].address !== step.address) throw new Error('Recorded contract address differs from original nonce');
      const hash = await runtimeCheck(step);
      if (hash !== existing.contracts[step.label].runtimeCodeHash) throw new Error('Recorded runtime changed');
      const entry = existing.transactions.find(x => x.label === step.label);
      const [sent, receipt, tx] = await Promise.all([provider.getTransaction(entry.hash),
        provider.getTransactionReceipt(entry.hash), step.factory.getDeployTransaction(...step.args)]);
      if (!sent || !receipt || receipt.status !== 1 || receipt.contractAddress !== step.address
        || sent.from !== getAddress(DEPLOYER) || sent.nonce !== step.nonce || sent.to !== null
        || keccak256(sent.data) !== keccak256(tx.data) || entry.dataHash !== keccak256(tx.data)) throw new Error('Creation transaction differs from the recorded artifact/arguments');
      existing.contracts[step.label].creationTransactionMatchesArtifact = true;
    }
    existing.knownAnswers = await knownAnswers(steps);
    existing.foundation = await disabledFoundation();
    record = existing; await save();
    console.log('All deployed runtimes, identities and real known answers passed; source remains unbound.');
  } else {
    if (existing) throw new Error('Verifier deployment record already exists. Use check or inspect partial transactions before recovery.');
    if (await currentNonce('pending') !== startNonce) throw new Error('Pending deployer transactions exist');
    let signer;
    if (fork) { await provider.send('anvil_impersonateAccount', [DEPLOYER]); signer = await provider.getSigner(DEPLOYER); }
    else signer = new Wallet(await secret(), provider);
    if (getAddress(await signer.getAddress()) !== getAddress(DEPLOYER)) throw new Error('Wrong disposable Sepolia signer');
    record = { schemaVersion: 1, chainId: 11155111, deployer: DEPLOYER, interfold: PROTOCOL,
      createdAt: new Date().toISOString(), startNonce, status: 'deploying-verifiers-only', forkTest: fork,
      maxTotalDeploymentSpendEthIncludingFoundation: '0.005', contracts: {}, transactions: [],
      programDeployed: false, sourceBound: false, actualProgramReleaseReady: false };
    await save();
    let spent = parseEther(foundation.totalGasCostEth);
    for (const step of steps) {
      if (await currentNonce('pending') !== step.nonce) throw new Error('Deployer nonce changed during plan');
      if (await provider.getCode(step.address) !== '0x') throw new Error('Predicted deployment address already has code');
      const tx = await step.factory.getDeployTransaction(...step.args);
      const estimate = await provider.estimateGas({ ...tx, from: DEPLOYER });
      const gasLimit = estimate * 120n / 100n;
      const block = await provider.getBlock('latest');
      const fee = await provider.getFeeData();
      const priority = !fork && fee.maxPriorityFeePerGas > 1_000_000n ? fee.maxPriorityFeePerGas : 1_000_000n;
      const maxFee = !fork && fee.maxFeePerGas > 2_000_000n ? fee.maxFeePerGas : 2_000_000n;
      if (gasLimit >= block.gasLimit || spent + gasLimit * maxFee > budget
        || gasLimit * maxFee > await provider.getBalance(DEPLOYER)) throw new Error('Deployment exceeds live gas/balance/0.005 ETH aggregate budget');
      const transaction = { ...tx, type: 2, chainId: 11155111, nonce: step.nonce,
        gasLimit, maxFeePerGas: maxFee, maxPriorityFeePerGas: priority };
      const entry = { label: step.label, address: step.address, nonce: step.nonce,
        gasEstimate: String(estimate), gasLimit: String(gasLimit), dataHash: keccak256(tx.data), status: 'intent' };
      record.transactions.push(entry);
      let sent;
      if (fork) { await save(); sent = await signer.sendTransaction(transaction); entry.hash = sent.hash; }
      else {
        const signed = await signer.signTransaction(transaction);
        entry.hash = keccak256(signed); await save(); // Persist hash before broadcasting.
        sent = await provider.broadcastTransaction(signed);
      }
      entry.status = 'broadcast'; await save();
      console.log(`${step.label}: ${step.address} tx ${entry.hash}`);
      const receipt = await sent.wait(1, 180000);
      if (!receipt || receipt.status !== 1 || receipt.contractAddress !== step.address) throw new Error('Deployment failed or address differs');
      const cost = receipt.gasUsed * receipt.gasPrice; spent += cost;
      Object.assign(entry, { status: 'confirmed', blockNumber: receipt.blockNumber,
        gasUsed: String(receipt.gasUsed), feeEth: formatEther(cost) });
      // Freeze compiler outputs separately from the disposable Foundry cache.
      let artifactPath = step.artifact.artifactPath;
      if (!fork && step.artifactName !== 'rawHalo2') {
        const frozen = resolve('deployments/verifier-artifacts', step.artifactName + '.json');
        await mkdir(dirname(frozen), { recursive: true });
        try { await writeFile(frozen, step.artifact.artifactBytes, { flag: 'wx' }); }
        catch (error) {
          if (error.code !== 'EEXIST') throw error;
        }
        const { createHash } = await import('node:crypto');
        if ('0x' + createHash('sha256').update(await readFile(frozen)).digest('hex') !== step.artifact.artifactSha256) throw new Error('Frozen artifact differs');
        artifactPath = frozen;
      }
      record.contracts[step.label] = { address: step.address,
        constructorArgs: step.args, runtimeCodeHash: await runtimeCheck(step),
        artifactPath: relative(dirname(resolve(path)), artifactPath), artifactSha256: step.artifact.artifactSha256 };
      record.totalGasCostEthIncludingFoundation = formatEther(spent);
      await save();
    }
    record.knownAnswers = await knownAnswers(steps);
    record.foundation = await disabledFoundation();
    record.status = 'verifiers-deployed-fixture-validated-program-deferred';
    record.completedAt = new Date().toISOString();
    record.remainingWalletEth = formatEther(await provider.getBalance(DEPLOYER));
    record.nextProgramNonce = startNonce + steps.length;
    record.predictedNextProgramAddress = getCreateAddress({ from: DEPLOYER, nonce: record.nextProgramNonce });
    await save();
    console.log('Reusable verifier stack deployed and real fixture proofs verified. Program deadlines and one-time bind remain deferred.');
  }
} catch (error) {
  if (record) { record.status = 'stopped'; record.error = error.shortMessage || error.message; await save(); }
  console.error(`Verifier deployment stopped: ${error.shortMessage || error.message}`);
  process.exitCode = 1;
} finally { provider?.destroy(); }
