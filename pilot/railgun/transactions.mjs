import fs from 'node:fs/promises';
import path from 'node:path';
import { Contract, JsonRpcProvider, Wallet, getAddress, ZeroAddress, keccak256 } from 'ethers';
import { NETWORK_CONFIG, NetworkName, TXIDVersion, calculateGasPrice, getEVMGasTypeForTransaction } from '@railgun-community/shared-models';
import { initializeSDK, createOrLoadWallet, loadSDKProvider, SDK, NETWORK_NAME } from './sdk.mjs';
import { CHAIN_ID, CONTRACTS, DEFAULT_COLLATERAL_WEI } from './config.mjs';
import { ROOT, LOCAL, readPrivate, writePrivate, rpc, grossForNet, fundingPlan } from './lib.mjs';
import { contractState, preflight } from './preflight.mjs';
import { validateFundingWindow, validateShieldSpend } from './funding-guards.mjs';
const TXID = TXIDVersion.V2_PoseidonMerkle;
const bounded = async (work, ms, message) => {
  let timer;
  try { return await Promise.race([work, new Promise((_resolve, reject) => { timer = setTimeout(() => reject(new Error(message)), ms); })]); }
  finally { clearTimeout(timer); }
};

export async function assertReleaseReady(rpcUrl, manifestFile = process.env.PILOT_RELEASE_MANIFEST) {
  if (!manifestFile) throw new Error('PILOT_RELEASE_MANIFEST is required before any funding broadcast');
  if (Number(BigInt(await rpc(rpcUrl, 'eth_chainId'))) !== CHAIN_ID) throw new Error('Funding requires Sepolia RPC chain ID 11155111');
  const { verifyRelease } = await import('../../scripts/lib/release.mjs');
  const deployment = JSON.parse(await fs.readFile(path.join(ROOT, '../../deployments/sepolia.json'), 'utf8'));
  const provider = new JsonRpcProvider(rpcUrl, CHAIN_ID);
  try {
    const source = new Contract(deployment.resultSource.address, ['function isReady() view returns(bool)', 'function program() view returns(address)'], provider);
    const program = await source.program();
    if (!await source.isReady() || program === ZeroAddress) throw new Error('Auction result source has no ready, bound program');
    const interfold = new Contract(deployment.interfold, ['function e3Programs(address) view returns(bool)'], provider);
    if (!await interfold.e3Programs(program)) throw new Error('Auction E3 program is not registered by Interfold');
    const auction = new Contract(deployment.auction.address, ['function state() view returns(uint8)', 'function biddingEnds() view returns(uint64)', 'function collateralWei() view returns(uint256)'], provider);
    const app = new Contract(program, ['function biddingEnds() view returns(uint64)'], provider);
    const [state, auctionBiddingEnds, programBiddingEnds, head, auctionCollateralWei] = await Promise.all([auction.state(), auction.biddingEnds(), app.biddingEnds(), provider.getBlock('latest'), auction.collateralWei()]);
    const fundingWindow = validateFundingWindow({ state, auctionBiddingEnds, programBiddingEnds, timestamp: head.timestamp, auctionCollateralWei, plannedCollateralWei: process.env.RAILGUN_COLLATERAL_WEI || DEFAULT_COLLATERAL_WEI });
    const release = await verifyRelease(manifestFile, provider, { auction: deployment.auction.address, resultSource: deployment.resultSource.address, program });
    return { ...release, fundingWindow };
  } finally { provider.destroy(); }
}

async function usingSDK(config, fn, { shieldOnly = false } = {}) {
  const state = await readPrivate();
  const head = Number(BigInt(await rpc(config.rpcUrl, 'eth_blockNumber')));
  const context = await initializeSDK({ ...config, shieldOnly });
  try {
    await createOrLoadWallet(state, head);
    await loadSDKProvider(config.rpcUrl);
    return await fn(state, context);
  } finally {
    await bounded(context.stop(), 8000, 'SDK shutdown exceeded 8 seconds').catch(() => {});
  }
}

const makePlan = (state, fees) => fundingPlan({ bidders: state.bidders, ...fees,
  collateralWei: process.env.RAILGUN_COLLATERAL_WEI,
  gasBudgetWei: process.env.RAILGUN_GAS_BUDGET_WEI,
  broadcasterBudgetWei: process.env.RAILGUN_BROADCASTER_BUDGET_WEI,
});

async function requireHealthyServices(config) {
  const report = await preflight(config);
  if (!report.contracts.ok || !report.graphql.ok || !report.poi.some(item => item.ok) || !report.broadcasters.result?.ok) throw new Error('Funding blocked: live contract, indexer, PPOI and usable WETH broadcaster checks must pass; see .local/preflight.json');
  return report;
}

export async function shieldPrepare(config, execute = false) {
  if (execute) {
    await assertReleaseReady(config.rpcUrl);
    await requireHealthyServices(config);
  }
  const from = process.env.RAILGUN_FUNDER_ADDRESS;
  if (!from) throw new Error('RAILGUN_FUNDER_ADDRESS is required to estimate the public shield transaction');
  getAddress(from);
  return usingSDK(config, async state => {
    if (execute && (state.shieldTransactionHash || state.shieldIntent)) throw new Error('A shield transaction intent already exists; reconcile its recorded hash before any further action');
    const fees = await contractState(config.rpcUrl);
    const plan = makePlan(state, fees);
    if (BigInt(plan.broadcasterFeeBudgetPerWithdrawalWei) <= 0n) throw new Error('Set a positive RAILGUN_BROADCASTER_BUDGET_WEI; minimum-only funding cannot cover broadcaster fees');
    const amount = { tokenAddress: CONTRACTS.weth, amount: BigInt(plan.grossShieldEthWei) };
    const { transaction } = await SDK.populateShieldBaseToken(TXID, NETWORK_NAME, state.railgun.address, state.shieldPrivateKey, amount);
    const provider = new JsonRpcProvider(config.rpcUrl, CHAIN_ID);
    try {
      const gasEstimate = await provider.estimateGas({ ...transaction, from });
      const feeData = await provider.getFeeData();
      const spend = validateShieldSpend({ value: transaction.value, gasLimit: gasEstimate * 120n / 100n, maxFeePerGas: feeData.maxFeePerGas });
      const prepared = { chainId: CHAIN_ID, createdAt: new Date().toISOString(), from, transaction: { ...transaction, chainId: CHAIN_ID, gasLimit: gasEstimate * 120n / 100n, maxFeePerGas: feeData.maxFeePerGas, maxPriorityFeePerGas: feeData.maxPriorityFeePerGas, type: 2 }, plan, maximumSpendWei: spend.maximumSpendWei, hardCapWei: spend.hardCapWei, broadcast: false };
      await writePrivate(path.join(LOCAL, 'shield-prepared.json'), prepared);
      if (!execute) return { prepared: true, gasEstimate: String(gasEstimate), grossShieldEthWei: plan.grossShieldEthWei, broadcast: false, localTransaction: path.join(LOCAL, 'shield-prepared.json') };
      if (!process.env.RAILGUN_FUNDER_PRIVATE_KEY) throw new Error('RAILGUN_FUNDER_PRIVATE_KEY required for shield-send; never stored by this tool');
      let signer;
      try { signer = new Wallet(process.env.RAILGUN_FUNDER_PRIVATE_KEY, provider); }
      catch { throw new Error('Invalid funder signing key; key value suppressed'); }
      if (signer.address.toLowerCase() !== from.toLowerCase()) throw new Error('Funder key does not match expected public address');
      const required = BigInt(spend.maximumSpendWei);
      if (await provider.getBalance(from) < required) throw new Error('Insufficient public test ETH for shield and gas');
      await assertReleaseReady(config.rpcUrl); // Recheck after SDK initialization and gas estimation.
      const nonce = await provider.getTransactionCount(from, 'pending');
      const signedTransaction = await signer.signTransaction({ ...prepared.transaction, nonce });
      const expectedHash = keccak256(signedTransaction);
      state.shieldIntent = { createdAt: new Date().toISOString(), status: 'prepared-before-broadcast', nonce, transactionHash: expectedHash, signedTransaction, maximumSpendWei: spend.maximumSpendWei };
      state.shieldTransactionHash = expectedHash;
      await writePrivate(path.join(LOCAL, 'wallets.private.json'), state);
      let sent;
      try {
        sent = await provider.broadcastTransaction(signedTransaction);
        if (sent.hash !== expectedHash) throw new Error('RPC returned an unexpected transaction hash');
        state.shieldIntent.status = 'submitted';
        await writePrivate(path.join(LOCAL, 'wallets.private.json'), state);
      } catch {
        state.shieldIntent.status = 'broadcast-uncertain';
        await writePrivate(path.join(LOCAL, 'wallets.private.json'), state);
        throw new Error('Shield broadcast status uncertain; inspect the persisted fixed-nonce transaction hash before retrying');
      }
      const receipt = await sent.wait(1, 180_000);
      state.shieldIntent.status = receipt.status === 1 ? 'confirmed' : 'reverted';
      await writePrivate(path.join(LOCAL, 'wallets.private.json'), state);
      await writePrivate(path.join(LOCAL, 'shield-receipt.json'), { transactionHash: sent.hash, blockNumber: receipt.blockNumber, status: receipt.status });
      return { broadcast: true, transactionHash: sent.hash, blockNumber: receipt.blockNumber, status: receipt.status, note: 'Private notes still require scan, PPOI and standby before spending' };
    } finally { provider.destroy(); }
  });
}

async function discoverBroadcaster(chain) {
  const { WakuBroadcasterClient, BroadcasterTransaction } = await import('@railgun-community/waku-broadcaster-client-node');
  const start = WakuBroadcasterClient.start(chain, {}, () => {}, { log: () => {}, error: () => {} });
  start.catch(() => {});
  const find = async () => {
    await start;
    for (;;) {
      const broadcaster = WakuBroadcasterClient.findBestBroadcaster(chain, CONTRACTS.weth, true);
      if (broadcaster) return broadcaster;
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  };
  try {
    const broadcaster = await bounded(find(), 35_000, 'No usable Sepolia WETH broadcaster offer within 35 seconds');
    return { broadcaster, BroadcasterTransaction, stop: () => WakuBroadcasterClient.stop() };
  } catch (error) {
    await bounded(WakuBroadcasterClient.stop(), 1000, 'Broadcaster shutdown timeout').catch(() => {});
    throw error;
  }
}

export async function unshieldPrepare(config, index, execute = false) {
  if (!Number.isInteger(index) || index < 0 || index >= 3) throw new Error('Bidder index must be 0, 1 or 2');
  if (execute) await assertReleaseReady(config.rpcUrl);
  await requireHealthyServices(config);
  return usingSDK(config, async (state, { network }) => {
    if (state.bidders.some(item => item.fundingIntent && item.fundingIntent.status !== 'confirmed')) throw new Error('An unresolved withdrawal intent exists; reconcile its nullifiers before further funding');
    const bidder = state.bidders[index];
    if (bidder.fundingTransactionHash) throw new Error('Bidder funding already submitted; refusing duplicate withdrawal');
    const plan = makePlan(state, await contractState(config.rpcUrl));
    const item = plan.bidderFunding[index];
    const wallet = SDK.walletForID(state.railgun.id);
    await bounded(SDK.refreshBalances(network.chain, [state.railgun.id]), 180_000, 'Wallet scan not complete within 3 minutes; retry after indexer sync');
    const balance = await SDK.balanceForERC20Token(TXID, wallet, NETWORK_NAME, CONTRACTS.weth, true);
    const amount = { tokenAddress: CONTRACTS.weth, amount: BigInt(item.privateUnshieldDebitWei) };
    if (balance <= amount.amount) throw new Error('No sufficient spendable WETH notes: shield, scan, standby and PPOI must finish before proving');
    const { broadcaster, BroadcasterTransaction, stop } = await discoverBroadcaster(network.chain);
    const provider = new JsonRpcProvider(config.rpcUrl, CHAIN_ID);
    try {
      const feeToken = { tokenAddress: CONTRACTS.weth, feePerUnitGas: BigInt(broadcaster.tokenFee.feePerUnitGas) };
      if (broadcaster.tokenAddress.toLowerCase() !== CONTRACTS.weth.toLowerCase() || feeToken.feePerUnitGas <= 0n || !broadcaster.tokenFee.feesID) throw new Error('Invalid WETH broadcaster quote');
      const gasPrice = BigInt(await rpc(config.rpcUrl, 'eth_gasPrice'));
      const originalGasDetails = { evmGasType: getEVMGasTypeForTransaction(NETWORK_NAME, false), gasEstimate: 0n, gasPrice: gasPrice * 120n / 100n };
      const estimate = await SDK.gasEstimateForUnprovenUnshieldBaseToken(TXID, NETWORK_NAME, bidder.address, state.railgun.id, state.railgun.encryptionKey, amount, originalGasDetails, feeToken, false);
      const gasDetails = { ...originalGasDetails, gasEstimate: estimate.gasEstimate };
      const feeAmount = SDK.calculateBroadcasterFeeERC20Amount(feeToken, gasDetails);
      if (feeAmount.amount > BigInt(plan.broadcasterFeeBudgetPerWithdrawalWei)) throw new Error('Live broadcaster fee exceeds configured per-withdrawal budget');
      const feeRecipient = { ...feeAmount, recipientAddress: broadcaster.railgunAddress };
      if (balance < amount.amount + feeAmount.amount) throw new Error('Insufficient spendable WETH for withdrawal plus broadcaster fee');
      const minimumGasPrice = calculateGasPrice(gasDetails);
      await SDK.generateUnshieldBaseTokenProof(TXID, NETWORK_NAME, bidder.address, state.railgun.id, state.railgun.encryptionKey, amount, feeRecipient, false, minimumGasPrice, () => {});
      const populated = await SDK.populateProvedUnshieldBaseToken(TXID, NETWORK_NAME, bidder.address, state.railgun.id, amount, feeRecipient, false, minimumGasPrice, gasDetails);
      if (populated.transaction.to.toLowerCase() !== CONTRACTS.relayAdapt.toLowerCase()) throw new Error('Unexpected withdrawal transaction target');
      // Stock V2 base-token broadcaster route has requireSuccess=false. Never patch calldata after proving.
      // Full eth_call plus destination balance checks catch failures in this restricted fresh-EOA route.
      await provider.call(populated.transaction);
      const before = await provider.getBalance(bidder.address);
      if (await provider.getCode(bidder.address) !== '0x') throw new Error('Funding destination must be a fresh EOA without deployed code');
      const weth = new Contract(CONTRACTS.weth, ['function balanceOf(address) view returns(uint256)'], provider);
      if (await provider.getBalance(CONTRACTS.relayAdapt) !== 0n || await weth.balanceOf(CONTRACTS.relayAdapt) !== 0n) throw new Error('Public RelayAdapt already holds ETH/WETH; stop to avoid mixing or sweeping unrelated value');
      if (before !== 0n) throw new Error('Fresh bidder already has ETH; refusing a duplicate or correlated top-up');
      const artifact = { createdAt: new Date().toISOString(), bidderIndex: index, expectedNetEthWei: item.netEthWei, broadcasterFeeWei: String(feeAmount.amount), gasDetails, minimumGasPrice, populated, broadcaster, simulated: true, broadcast: false, sdkRequireSuccess: false };
      await writePrivate(path.join(LOCAL, `unshield-${index}-prepared.json`), artifact);
      if (!execute) return { prepared: true, bidderIndex: index, expectedNetEthWei: item.netEthWei, broadcasterFeeWei: String(feeAmount.amount), simulated: true, broadcast: false };
      const submission = await BroadcasterTransaction.create(TXID, populated.transaction.to, populated.transaction.data, broadcaster.railgunAddress, broadcaster.tokenFee.feesID, network.chain, populated.nullifiers ?? [], minimumGasPrice, true, populated.preTransactionPOIsPerTxidLeafPerList);
      await assertReleaseReady(config.rpcUrl); // Proving and synchronization can consume the funding window.
      bidder.fundingIntent = { createdAt: new Date().toISOString(), status: 'prepared-before-broadcast', nullifiers: populated.nullifiers ?? [], calldataHash: keccak256(populated.transaction.data), expectedNetEthWei: item.netEthWei };
      if (!bidder.fundingIntent.nullifiers.length) throw new Error('Withdrawal has no nullifiers to reconcile');
      await writePrivate(path.join(LOCAL, 'wallets.private.json'), state);
      let hash;
      try { hash = await submission.send(); }
      catch {
        bidder.fundingIntent.status = 'broadcast-uncertain';
        await writePrivate(path.join(LOCAL, 'wallets.private.json'), state);
        throw new Error('Broadcaster response uncertain; persisted nullifiers prohibit another funding attempt until reconciled');
      }
      bidder.fundingIntent.status = 'submitted';
      bidder.fundingTransactionHash = hash;
      await writePrivate(path.join(LOCAL, 'wallets.private.json'), state);
      const receipt = await provider.waitForTransaction(hash, 1, 180_000);
      if (!receipt || receipt.status !== 1) throw new Error('Withdrawal failed or receipt unavailable; inspect saved transaction hash before retrying');
      const after = await provider.getBalance(bidder.address, receipt.blockNumber);
      const delivered = after - before;
      const result = { transactionHash: hash, bidderIndex: index, blockNumber: receipt.blockNumber, deliveredWei: String(delivered), expectedNetEthWei: item.netEthWei, netDeliveryVerified: delivered === BigInt(item.netEthWei), adapterEmptyAfter: await provider.getBalance(CONTRACTS.relayAdapt, receipt.blockNumber) === 0n && await weth.balanceOf(CONTRACTS.relayAdapt, { blockTag: receipt.blockNumber }) === 0n, broadcast: true };
      await writePrivate(path.join(LOCAL, `unshield-${index}-receipt.json`), result);
      if (result.netDeliveryVerified && result.adapterEmptyAfter) {
        bidder.fundingIntent.status = 'confirmed';
        await writePrivate(path.join(LOCAL, 'wallets.private.json'), state);
      }
      if (!result.adapterEmptyAfter) throw new Error('Public adapter holds ETH/WETH after funding; stop and inspect the transaction');
      if (!result.netDeliveryVerified) throw new Error('Receipt succeeded but exact net ETH did not arrive; stop and inspect adapter CallError events');
      return result;
    } finally {
      provider.destroy();
      await bounded(stop(), 1000, 'Broadcaster shutdown timeout').catch(() => {});
    }
  });
}
