import { access, chmod, lstat, mkdir, open, readFile, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { Wallet } from 'ethers';
import { DEFAULT_COLLATERAL_WEI, DEFAULT_GAS_BUDGET_WEI } from './config.mjs';

export const ROOT = path.dirname(fileURLToPath(import.meta.url));
export const LOCAL = path.join(ROOT, '.local');
export const SECRET_FILE = path.join(LOCAL, 'wallets.private.json');
export const json = value => JSON.stringify(value, (_key, item) => typeof item === 'bigint' ? item.toString() : item, 2);

export function redactErrorMessage(message, state, environment = process.env) {
  const values = [];
  function collect(value) {
    if (typeof value === 'string' && value.length >= 20) values.push(value);
    else if (Array.isArray(value)) value.forEach(collect);
    else if (value && typeof value === 'object') Object.values(value).forEach(collect);
  }
  collect(state);
  for (const [key, value] of Object.entries(environment)) {
    if (/private.?key|mnemonic|secret|encryption.?key/i.test(key) && value) values.push(value);
  }
  let safe = String(message ?? 'Operation failed');
  for (const value of values.sort((a, b) => b.length - a.length)) safe = safe.replaceAll(value, '[redacted]');
  return safe.slice(0, 2000);
}

export async function privateDirectory(directory = LOCAL) {
  try {
    const info = await lstat(directory);
    if (info.isSymbolicLink() || !info.isDirectory()) throw new Error('Local state path must be a real directory');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    await mkdir(directory, { recursive: true, mode: 0o700 });
  }
  await chmod(directory, 0o700);
}

export async function writePrivate(file, value, exclusive = false) {
  await privateDirectory(path.dirname(file));
  if (!exclusive) {
    try {
      if ((await lstat(file)).isSymbolicLink()) throw new Error('Refusing a symbolic link for local state');
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  if (exclusive) {
    await writeFile(file, json(value) + '\n', { mode: 0o600, flag: 'wx' });
    await chmod(file, 0o600);
    return;
  }
  const temporary = file + '.' + randomBytes(8).toString('hex') + '.tmp';
  try {
    const handle = await open(temporary, 'wx', 0o600);
    try { await handle.writeFile(json(value) + '\n'); await handle.sync(); }
    finally { await handle.close(); }
    await rename(temporary, file);
  } finally { await rm(temporary, { force: true }); }
}

export async function readPrivate(file = SECRET_FILE) {
  const info = await lstat(file);
  if (info.isSymbolicLink() || !info.isFile() || (info.mode & 0o077)) throw new Error('Wallet state must be a regular file with mode 0600');
  return JSON.parse(await readFile(file, 'utf8'));
}

export async function initializeSecrets(file = SECRET_FILE) {
  try { await access(file); return { created: false, state: await readPrivate(file) }; }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  const railgun = Wallet.createRandom();
  const bidders = Array.from({ length: 3 }, (_, index) => {
    const wallet = Wallet.createRandom();
    return { label: `bidder-${index + 1}`, address: wallet.address, privateKey: wallet.privateKey };
  });
  const state = {
    version: 1, chainId: 11155111, createdAt: new Date().toISOString(),
    railgun: { mnemonic: railgun.mnemonic.phrase, encryptionKey: randomBytes(32).toString('hex') },
    shieldPrivateKey: randomBytes(32).toString('hex'), bidders,
  };
  await writePrivate(file, state, true);
  return { created: true, state };
}

export const inclusiveNet = (gross, basisPoints) => {
  gross = BigInt(gross); basisPoints = BigInt(basisPoints);
  if (gross < 0n || basisPoints < 0n || basisPoints >= 10_000n) throw new Error('Invalid fee or amount');
  return gross - gross * basisPoints / 10_000n;
};

// Smallest gross for the contract's inclusive fee rule: base = gross - floor(gross * bp / 10000).
export function grossForNet(net, basisPoints) {
  net = BigInt(net); basisPoints = BigInt(basisPoints);
  if (net < 0n || basisPoints < 0n || basisPoints >= 10_000n) throw new Error('Invalid fee or amount');
  if (!net) return 0n;
  let gross = (net - 1n) * 10_000n / (10_000n - basisPoints) + 1n;
  if (inclusiveNet(gross, basisPoints) !== net) throw new Error('Fee inversion did not produce exact net');
  return gross;
}

export function fundingPlan({ bidders, shieldFeeBP, unshieldFeeBP, collateralWei = DEFAULT_COLLATERAL_WEI, gasBudgetWei = DEFAULT_GAS_BUDGET_WEI, broadcasterBudgetWei = 0n }) {
  collateralWei = BigInt(collateralWei); gasBudgetWei = BigInt(gasBudgetWei); broadcasterBudgetWei = BigInt(broadcasterBudgetWei);
  if (bidders.length !== 3 || new Set(bidders.map(b => b.address.toLowerCase())).size !== 3) throw new Error('Exactly three distinct bidder addresses required');
  if (collateralWei <= 0n || gasBudgetWei <= 0n || broadcasterBudgetWei < 0n) throw new Error('Invalid funding budgets');
  const netPerBidder = collateralWei + gasBudgetWei;
  const privateUnshieldPerBidder = grossForNet(netPerBidder, unshieldFeeBP);
  const privateNeeded = (privateUnshieldPerBidder + broadcasterBudgetWei) * 3n;
  return {
    chainId: 11155111, mode: 'railgun-funded-fresh-eoa', amountStatus: broadcasterBudgetWei ? 'operator-budget-not-live-quote' : 'incomplete-no-broadcaster-fee-quote',
    shieldFeeBP: String(shieldFeeBP), unshieldFeeBP: String(unshieldFeeBP),
    collateralWei: String(collateralWei), gasBudgetWei: String(gasBudgetWei),
    broadcasterFeeBudgetPerWithdrawalWei: String(broadcasterBudgetWei),
    privateWethRequiredWei: String(privateNeeded), grossShieldEthWei: String(grossForNet(privateNeeded, shieldFeeBP)),
    bidderFunding: bidders.map(({ label, address }) => ({ label, address, netEthWei: String(netPerBidder), privateUnshieldDebitWei: String(privateUnshieldPerBidder) })),
    privacy: 'Equal public budgets; funding origins obscured only if private spend uses independent broadcaster. Public destinations, timing and amounts remain visible.',
  };
}

export async function requestJSON(url, body, timeoutMs = 12_000) {
  const response = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs) });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const result = await response.json();
  if (result.error) throw new Error(`JSON-RPC ${result.error.code}: ${result.error.message}`);
  if (result.errors) throw new Error(`GraphQL: ${result.errors.map(item => item.message).join('; ')}`);
  return result;
}
export async function rpc(url, method, params = []) {
  const response = await requestJSON(url, { jsonrpc: '2.0', id: 1, method, params });
  if (!Object.hasOwn(response, 'result')) throw new Error('Missing JSON-RPC result');
  return response.result;
}

export async function withExecutionLock(operation, directory = LOCAL) {
  await privateDirectory(directory);
  const lock = path.join(directory, 'execution.lock');
  let handle;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      handle = await open(lock, 'wx', 0o600);
      break;
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      const existing = await readPrivate(lock);
      if (!Number.isSafeInteger(existing.pid) || existing.pid <= 0) throw new Error('Invalid execution lock; inspect local state before proceeding');
      try { process.kill(existing.pid, 0); throw new Error('Another funding operation owns the local execution lock'); }
      catch (check) {
        if (check.code !== 'ESRCH') throw check;
        // Dead process: transaction intents remain persisted and prohibit duplicate sends.
        await rm(lock);
      }
    }
  }
  if (!handle) throw new Error('Could not acquire execution lock');
  try {
    await handle.writeFile(json({ pid: process.pid, createdAt: new Date().toISOString() }) + '\n');
    await handle.sync();
    return await operation();
  } finally { await handle.close(); await rm(lock, { force: true }); }
}
