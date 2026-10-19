#!/usr/bin/env node
import path from 'node:path';
import { CONTRACTS, DEFAULT_RPC, DEFAULT_POI, DEFAULT_GRAPHQL, CHAIN_ID } from './config.mjs';
import { LOCAL, ROOT, json, rpc, initializeSecrets, readPrivate, writePrivate, fundingPlan, withExecutionLock, redactErrorMessage } from './lib.mjs';
import { contractState, preflight } from './preflight.mjs';
const command = process.argv[2];
const rpcUrl = process.env.RAILGUN_SEPOLIA_RPC_URL || DEFAULT_RPC;
const poiUrls = (process.env.RAILGUN_POI_URLS || DEFAULT_POI).split(',').map(value => value.trim()).filter(Boolean);
const graphqlUrl = process.env.RAILGUN_GRAPHQL_URL || DEFAULT_GRAPHQL;
const help = 'Commands: preflight [--skip-broadcasters], wallet-init, sdk-smoke, funding-plan, shield-prepare, shield-send, unshield-prepare <0|1|2>, unshield-send <0|1|2>. Only *-send commands can broadcast; they require a verified release and live service gates.';
try {
  if (command === 'preflight') {
    const result = await preflight({ rpcUrl, poiUrls, graphqlUrl, includeBroadcasters: !process.argv.includes('--skip-broadcasters') });
    console.log(json(result));
    if (!result.contracts.ok || !result.graphql.ok || !result.poi.some(check => check.ok) || !result.broadcasters.result?.ok) process.exitCode = 2;
  } else if (command === 'wallet-init') {
    const { created } = await initializeSecrets();
    // Mnemonics, encryption keys, private bidder keys and 0zk links remain inside mode-0600 ignored state.
    console.log(json({ created, chainId: CHAIN_ID, freshBidders: 3, localState: path.join(LOCAL, 'wallets.private.json'), next: 'sdk-smoke', broadcast: false }));
  } else if (command === 'funding-plan') {
    const state = await readPrivate();
    const onchain = await contractState(rpcUrl);
    const plan = fundingPlan({ bidders: state.bidders, shieldFeeBP: onchain.shieldFeeBP, unshieldFeeBP: onchain.unshieldFeeBP, collateralWei: process.env.RAILGUN_COLLATERAL_WEI, gasBudgetWei: process.env.RAILGUN_GAS_BUDGET_WEI, broadcasterBudgetWei: process.env.RAILGUN_BROADCASTER_BUDGET_WEI });
    await writePrivate(path.join(LOCAL, 'funding-plan.json'), { ...plan, observedAt: new Date().toISOString(), feeBlock: onchain.blockNumber });
    console.log(json({ chainId: CHAIN_ID, bidders: 3, amountStatus: plan.amountStatus, grossShieldEthWei: plan.grossShieldEthWei, localPlan: path.join(LOCAL, 'funding-plan.json'), broadcast: false }));
  } else if (['shield-prepare', 'shield-send', 'unshield-prepare', 'unshield-send'].includes(command)) {
    const { shieldPrepare, unshieldPrepare } = await import('./transactions.mjs');
    const config = { rpcUrl, poiUrls, graphqlUrl };
    const operation = () => command.startsWith('shield-') ? shieldPrepare(config, command.endsWith('-send')) : unshieldPrepare(config, Number(process.argv[3]), command.endsWith('-send'));
    const result = command.endsWith('-send') ? await withExecutionLock(operation) : await operation();
    console.log(json(result));
  } else if (command === 'sdk-smoke') {
    const state = await readPrivate();
    const head = Number(BigInt(await rpc(rpcUrl, 'eth_blockNumber')));
    const { initializeSDK, createOrLoadWallet, loadSDKProvider, SDK, NETWORK_NAME } = await import('./sdk.mjs');
    const context = await initializeSDK({ rpcUrl, poiUrls });
    try {
      const info = await createOrLoadWallet(state, head);
      const provider = await loadSDKProvider(rpcUrl);
      const report = { observedAt: new Date().toISOString(), sdkEngineStarted: true, groth16ProverInstalled: true, walletCreatedOrLoaded: Boolean(info.id), providerLoaded: true, fees: provider.feesSerialized, balanceScanComplete: false, provedSpend: false, broadcast: false, caveat: 'Successful startup is not a complete wallet scan or private spend.' };
      await writePrivate(path.join(LOCAL, 'sdk-smoke.json'), report);
      console.log(json(report));
    } finally { await Promise.race([context.stop(), new Promise(resolve => setTimeout(resolve, 8000))]); }
  } else {
    console.log(help);
    if (command && command !== 'help') process.exitCode = 1;
  }
} catch (error) {
  // SDK errors can contain requests and private witness data. Do not dump exception objects or stacks.
  let state;
  try { state = await readPrivate(); } catch {}
  console.error(json({ command, error: redactErrorMessage(error.message, state),
    broadcast: command?.endsWith('-send') ? 'unknown-check-local-intent-and-receipt' : false }));
  process.exitCode = 1;
}

// The SDK's background pollers can outlive stopRailgunEngine during an in-flight scan.
// Database shutdown is requested above; bound CLI lifetime after the completed operation.
setTimeout(() => process.exit(process.exitCode ?? 0), 1000).unref();
