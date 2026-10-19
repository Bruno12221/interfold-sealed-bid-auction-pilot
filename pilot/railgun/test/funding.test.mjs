import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, lstat, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fundingPlan, grossForNet, inclusiveNet, initializeSecrets, readPrivate } from '../lib.mjs';
const bidders = [1, 2, 3].map(n => ({ label: `bidder-${n}`, address: `0x${String(n).padStart(40, '0')}` }));

test('fee inversion returns exact net and minimum gross, including rounding boundary', () => {
  for (const fee of [0n, 25n, 5000n]) {
    for (const net of [0n, 1n, 2n, 399n, 400n, 10n ** 18n]) {
      const gross = grossForNet(net, fee);
      assert.equal(inclusiveNet(gross, fee), net);
      if (gross > 0n) assert.ok(inclusiveNet(gross - 1n, fee) < net);
    }
  }
  assert.throws(() => grossForNet(1n, 10_000n));
});

test('three equal net budgets include protocol fees twice and broadcaster separately', () => {
  const plan = fundingPlan({ bidders, shieldFeeBP: 25, unshieldFeeBP: 25, broadcasterBudgetWei: 1000n });
  const net = BigInt(plan.collateralWei) + BigInt(plan.gasBudgetWei);
  assert.ok(plan.bidderFunding.every(b => BigInt(b.netEthWei) === net));
  assert.equal(inclusiveNet(BigInt(plan.grossShieldEthWei), 25), BigInt(plan.privateWethRequiredWei));
  assert.equal(BigInt(plan.privateWethRequiredWei), 3n * (grossForNet(net, 25) + 1000n));
  assert.throws(() => fundingPlan({ bidders: [bidders[0], bidders[0], bidders[2]], shieldFeeBP: 25, unshieldFeeBP: 25 }));
});

test('secrets are generated once, private and never included in public funding plan', async t => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'railgun-wallet-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'wallets.private.json');
  const first = await initializeSecrets(file);
  const second = await initializeSecrets(file);
  assert.equal(first.created, true); assert.equal(second.created, false);
  assert.equal((await lstat(file)).mode & 0o777, 0o600);
  assert.equal((await lstat(dir)).mode & 0o777, 0o700);
  assert.deepEqual(first.state, second.state);
  assert.equal(first.state.bidders.length, 3);
  const plan = fundingPlan({ bidders: first.state.bidders, shieldFeeBP: 25, unshieldFeeBP: 25 });
  assert.ok(!JSON.stringify(plan).includes(first.state.bidders[0].privateKey));
  assert.equal((await readPrivate(file)).railgun.mnemonic, first.state.railgun.mnemonic);
});
