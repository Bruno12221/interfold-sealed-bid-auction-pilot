import { readFile, writeFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
import { Contract, ContractFactory, formatEther, keccak256 } from 'ethers';
import { sepoliaProvider, CHAIN_ID } from './config.mjs';

const deployment = JSON.parse(await readFile('deployments/sepolia.json', 'utf8'));
assert.equal(deployment.chainId, CHAIN_ID);
const provider = await sepoliaProvider();
const contracts = {};
for (const [label, name] of [['resultSource', 'InterfoldResultSource'], ['demoNFT', 'DemoNFT'], ['auction', 'SealedBidAuction']]) {
  const info = deployment[label];
  const build = JSON.parse(await readFile(`out/${name}.sol/${name}.json`, 'utf8'));
  const factory = new ContractFactory(build.abi, build.bytecode.object);
  const expected = await factory.getDeployTransaction(...info.constructorArgs);
  const sent = await provider.getTransaction(deployment.transactions.find(t => t.label === label).hash);
  assert.equal(sent.data.toLowerCase(), expected.data.toLowerCase(), `${label}: creation bytecode differs from local build`);
  assert.equal(keccak256(await provider.getCode(info.address)), info.runtimeCodeHash, `${label}: runtime code hash mismatch`);
  contracts[label] = new Contract(info.address, build.abi, provider);
}
const { resultSource, demoNFT, auction } = contracts;
assert.equal(await resultSource.isReady(), false);
assert.equal(await resultSource.program(), '0x0000000000000000000000000000000000000000');
assert.equal(await resultSource.binder(), deployment.deployer);
assert.equal(await auction.seller(), deployment.deployer);
assert.equal(await auction.nft(), deployment.demoNFT.address);
assert.equal(await auction.resultSource(), deployment.resultSource.address);
assert.equal(await auction.collateralWei(), 1000000000000000n);
assert.equal(await auction.tickWei(), 10000000000000n);
assert.equal(await auction.priceLevels(), 101n);
assert.equal(await auction.maxBidders(), 16n);
assert.equal(await auction.state(), 0n);
assert.equal(await auction.bidCount(), 0n);
assert.equal(await auction.totalCredits(), 0n);
assert.equal(await demoNFT.ownerOf(1), deployment.deployer);
assert.equal(await provider.getBalance(deployment.auction.address), 0n);

async function assertReverts(data, value, errorName) {
  try {
    await provider.call({ to: deployment.auction.address, from: deployment.deployer, data, value });
    throw new Error(`Expected ${errorName} but simulation succeeded.`);
  } catch (error) {
    assert.equal(error.code, 'CALL_EXCEPTION');
    assert.equal(auction.interface.parseError(error.data).name, errorName);
  }
}
const now = (await provider.getBlock('latest')).timestamp;
await assertReverts(auction.interface.encodeFunctionData('open', [0, now + 3600, now + 7200]), 0n, 'ResultSourceNotReady');
await assertReverts(auction.interface.encodeFunctionData('submitBid', [0, '0x01', '0x' + '00'.repeat(32)]),
  1000000000000000n, 'InvalidState');
const report = { checkedAt: new Date().toISOString(), blockNumber: await provider.getBlockNumber(),
  chainId: CHAIN_ID, creationBytecodeMatchesBuild: true, runtimeHashesMatch: true,
  NFTStillOwnedBySeller: true, auctionState: 'Created', bidCount: 0,
  resultSourceReady: false, openingRejected: 'ResultSourceNotReady', biddingRejected: 'InvalidState',
  depositBalanceETH: '0.0', walletBalanceETH: formatEther(await provider.getBalance(deployment.deployer)) };
await writeFile('deployments/onchain-check.json', JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
provider.destroy();
