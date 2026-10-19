import { readFile, writeFile, rename, mkdir } from 'node:fs/promises';
import { Contract, ContractFactory, Wallet, formatEther, parseEther, keccak256 } from 'ethers';
import { sepoliaProvider, PROTOCOL, DEPLOYER, CHAIN_ID, EXPLORER } from './config.mjs';

const recordPath = 'deployments/sepolia.json';
try {
  await readFile(recordPath);
  throw new Error('Deployment record already exists. Inspect it before intentionally deploying another pilot.');
} catch (error) { if (error.code !== 'ENOENT') throw error; }

async function readPrivateKey() {
  if (process.env.PRIVATE_KEY) return process.env.PRIVATE_KEY;
  if (!process.stdin.isTTY) throw new Error('Supply PRIVATE_KEY or run in a terminal for hidden input.');
  process.stdout.write('Disposable Sepolia private key (hidden): ');
  process.stdin.setRawMode(true);
  process.stdin.resume();
  return new Promise((resolve, reject) => {
    let input = '';
    function finish() {
      process.stdin.off('data', onData);
      process.stdin.setRawMode(false);
      process.stdin.pause();
      process.stdout.write('\n');
    }
    function onData(data) {
      for (const char of data.toString()) {
        if (char === '\u0003') { finish(); reject(new Error('Cancelled.')); return; }
        if (char === '\r' || char === '\n') { finish(); resolve(input.trim()); return; }
        if (char === '\u007f') input = input.slice(0, -1);
        else input += char;
      }
    }
    process.stdin.on('data', onData);
  });
}

const provider = await sepoliaProvider();
let signer;
try { signer = new Wallet(await readPrivateKey(), provider); }
catch { throw new Error('Unable to load a valid private key. No transaction was sent.'); }
delete process.env.PRIVATE_KEY;
if (signer.address.toLowerCase() !== (process.env.EXPECTED_DEPLOYER || DEPLOYER).toLowerCase()) {
  throw new Error('Signer does not match EXPECTED_DEPLOYER.');
}
const budget = parseEther('0.005');
const initialBalance = await provider.getBalance(signer.address);
let spent = 0n;
const deployment = { chainId: CHAIN_ID, interfold: PROTOCOL, deployer: signer.address,
  createdAt: new Date().toISOString(), status: 'foundation-disabled', transactions: [],
  auctionType: 'second-price', revealAllBidsAfterClose: true,
  limits: { maxDeploymentSpendEth: '0.005', collateralEth: '0.001', tickEth: '0.00001', priceLevels: 101, maxBidders: 16 },
  warning: 'No auction E3 program or input proof circuit. Result source is unbound; opening and bidding are disabled.' };

await mkdir('deployments', { recursive: true });
async function save() {
  await writeFile(recordPath + '.tmp', JSON.stringify(deployment, null, 2) + '\n');
  await rename(recordPath + '.tmp', recordPath);
}
async function artifact(name) {
  return JSON.parse(await readFile(`out/${name}.sol/${name}.json`, 'utf8'));
}
async function options(transaction) {
  const estimate = await provider.estimateGas({ ...transaction, from: signer.address });
  const gasLimit = estimate * 120n / 100n;
  const fee = await provider.getFeeData();
  const maxFeePerGas = fee.maxFeePerGas ?? fee.gasPrice;
  const maxPriorityFeePerGas = fee.maxPriorityFeePerGas ?? 0n;
  if (maxFeePerGas === null || spent + gasLimit * maxFeePerGas > budget ||
      gasLimit * maxFeePerGas > await provider.getBalance(signer.address)) {
    throw new Error('Transaction exceeds remaining 0.005 ETH deployment budget or wallet balance.');
  }
  return { gasLimit, maxFeePerGas, maxPriorityFeePerGas };
}
async function record(label, tx) {
  // Persist the broadcast hash before waiting, so an interruption cannot hide a sent transaction.
  deployment.transactions.push({ label, hash: tx.hash, url: `${EXPLORER}/tx/${tx.hash}` });
  await save();
  console.log(`${label}: ${EXPLORER}/tx/${tx.hash}`);
  const receipt = await tx.wait(1);
  if (receipt.status !== 1) throw new Error(`${label} reverted.`);
  spent += receipt.gasUsed * receipt.gasPrice;
  const entry = deployment.transactions.at(-1);
  Object.assign(entry, { blockNumber: receipt.blockNumber, gasUsed: receipt.gasUsed.toString(), feeEth: formatEther(receipt.gasUsed * receipt.gasPrice) });
  await save();
  return receipt;
}
async function deploy(label, name, args) {
  const build = await artifact(name);
  const factory = new ContractFactory(build.abi, build.bytecode.object, signer);
  const transaction = await factory.getDeployTransaction(...args);
  const contract = await factory.deploy(...args, await options(transaction));
  const address = await contract.getAddress();
  deployment[label] = { address, constructorArgs: args.map(x => typeof x === 'bigint' ? x.toString() : x), url: `${EXPLORER}/address/${address}` };
  await record(label, contract.deploymentTransaction());
  const code = await provider.getCode(address);
  if (code === '0x') throw new Error(`${label}: no deployed code.`);
  deployment[label].runtimeCodeHash = keccak256(code);
  await save();
  return contract;
}

try {
  console.log(`Sepolia deployer ${signer.address}; balance ${formatEther(initialBalance)} ETH; spend cap 0.005 ETH.`);
  const source = await deploy('resultSource', 'InterfoldResultSource', [PROTOCOL, signer.address]);
  const nft = await deploy('demoNFT', 'DemoNFT', []);
  const mintTx = await nft.mint.populateTransaction();
  await record('mintDemoNFT', await nft.mint(await options(mintTx)));
  const auction = await deploy('auction', 'SealedBidAuction', [signer.address, await nft.getAddress(), 1n,
    parseEther('0.001'), parseEther('0.00001'), 101, 16, await source.getAddress()]);
  const [ready, boundProgram, nftOwner] = await Promise.all([source.isReady(), source.program(), nft.ownerOf(1)]);
  if (ready || boundProgram !== '0x0000000000000000000000000000000000000000' || nftOwner !== signer.address) {
    throw new Error('Post-deployment invariant failed.');
  }
  deployment.verified = { resultSourceReady: ready, boundProgram, demoNFTOwner: nftOwner,
    auctionAddress: await auction.getAddress(), auctionETHBalance: formatEther(await provider.getBalance(await auction.getAddress())) };
  deployment.totalGasCostEth = formatEther(spent);
  deployment.remainingWalletEth = formatEther(await provider.getBalance(signer.address));
  await save();
  console.log(`Pilot foundation deployed; auction disabled. Gas cost ${formatEther(spent)} ETH.`);
} catch (error) {
  // Avoid dumping provider errors/transaction objects, which may contain sensitive metadata.
  console.error(`Deployment stopped: ${error.shortMessage || error.message}`);
  process.exitCode = 1;
} finally { provider.destroy(); }
