import test from 'node:test';
import assert from 'node:assert/strict';
import { assertReleaseReady, unshieldPrepare } from '../transactions.mjs';

test('no release manifest blocks funding before RPC or signer access', async () => {
  await assert.rejects(assertReleaseReady('http://127.0.0.1:1', ''), /PILOT_RELEASE_MANIFEST/);
});

test('invalid bidder slot blocks before service access', async () => {
  await assert.rejects(unshieldPrepare({}, -1), /Bidder index/);
  await assert.rejects(unshieldPrepare({}, 3), /Bidder index/);
});

import { validateFundingWindow, validateShieldSpend, MAX_SHIELD_TOTAL_WEI } from '../funding-guards.mjs';
import { withExecutionLock, redactErrorMessage } from '../lib.mjs';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const window = { state: 0, auctionBiddingEnds: 0, programBiddingEnds: 10_000, timestamp: 1_000, auctionCollateralWei: 1000, plannedCollateralWei: 1000 };
test('funding uses immutable program deadline for Created, checks active deadline, and rejects finalized/short windows', () => {
  assert.equal(validateFundingWindow(window).remainingSeconds, '9000');
  assert.equal(validateFundingWindow({ ...window, state: 1, auctionBiddingEnds: 10_000 }).auctionState, 1);
  assert.equal(validateFundingWindow({ ...window, programBiddingEnds: 8200 }).remainingSeconds, '7200');
  assert.throws(() => validateFundingWindow({ ...window, programBiddingEnds: 8199 }), /at least 2 hours/);
  for (const state of [2, 3]) assert.throws(() => validateFundingWindow({ ...window, state }), /Created or Bidding/);
  assert.throws(() => validateFundingWindow({ ...window, state: 1, auctionBiddingEnds: 10_001 }), /deadlines differ/);
  assert.throws(() => validateFundingWindow({ ...window, plannedCollateralWei: 999 }), /collateral differs/);
});

test('shield cap includes maximum gas and cannot be overridden by budget variables', () => {
  const gasLimit = 1_000_000n, maxFeePerGas = 1_000_000_000n;
  const gas = gasLimit * maxFeePerGas;
  assert.equal(validateShieldSpend({ value: MAX_SHIELD_TOTAL_WEI - gas, gasLimit, maxFeePerGas }).maximumSpendWei, String(MAX_SHIELD_TOTAL_WEI));
  assert.throws(() => validateShieldSpend({ value: MAX_SHIELD_TOTAL_WEI - gas + 1n, gasLimit, maxFeePerGas }), /0.01/);
  assert.throws(() => validateShieldSpend({ value: 1n, gasLimit, maxFeePerGas: 0n }), /must be positive/);
});

test('execution lock excludes concurrent funding and releases on failure', async t => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'railgun-lock-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  await withExecutionLock(async () => {
    await assert.rejects(withExecutionLock(async () => {}, dir), /Another funding operation/);
  }, dir);
  await assert.rejects(withExecutionLock(async () => { throw new Error('operation failed'); }, dir), /operation failed/);
  assert.equal(await withExecutionLock(async () => 'acquired', dir), 'acquired');
});

test('SDK error text suppresses local authority and bidder linkage', () => {
  const mnemonic = 'synthetic mnemonic fixture never a real wallet';
  const address = '0x' + 'ab'.repeat(20);
  const key = 'synthetic signing key fixture';
  const message = `SDK rejected ${mnemonic} at ${address} with ${key}`;
  const safe = redactErrorMessage(message, { railgun: { mnemonic }, bidders: [{ address }] }, { RAILGUN_FUNDER_PRIVATE_KEY: key });
  for (const secret of [mnemonic, address, key]) assert.equal(safe.includes(secret), false);
  assert.match(safe, /SDK rejected/);
});
