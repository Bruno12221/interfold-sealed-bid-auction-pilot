import assert from 'node:assert/strict';
import { chmod, lstat, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { initializeWallet } from '../wallet.mjs';

test('wallet-init writes a dedicated private mnemonic once and returns only its public identity', async () => {
  const root = await mkdtemp(join(tmpdir(), 'auction-avail-wallet-'));
  const directory = join(root, 'private');
  try {
    const first = await initializeWallet(directory);
    const path = join(directory, 'wallet.private.json');
    const before = await readFile(path, 'utf8');
    const privateWallet = JSON.parse(before);
    assert.equal((await lstat(directory)).mode & 0o777, 0o700);
    assert.equal((await lstat(path)).mode & 0o777, 0o600);
    assert.equal(privateWallet.mnemonic.split(' ').length, 24);
    assert.equal(first.address, privateWallet.address);
    assert.equal(first.keyType, 'sr25519');
    assert.equal(first.reused, false);
    assert.equal(Object.hasOwn(first, 'mnemonic'), false);
    assert.equal(JSON.stringify(first).includes(privateWallet.mnemonic), false);
    assert.equal(first.broadcast, false);
    const second = await initializeWallet(directory);
    assert.equal(second.address, first.address);
    assert.equal(second.reused, true);
    assert.ok((await readFile(path, 'utf8')) === before, 'Wallet initialization replaced private material');
    // Existing permissions are never silently repaired after potential exposure.
    await chmod(path, 0o644);
    await assert.rejects(initializeWallet(directory), /Refusing insecure wallet file/);
    await chmod(path, 0o600);
    await chmod(directory, 0o755);
    await assert.rejects(initializeWallet(directory), /Refusing insecure wallet directory/);
    await chmod(directory, 0o700);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('wallet-init rejects symlinks and partial files instead of replacing private material', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'auction-avail-wallet-'));
  const path = join(directory, 'wallet.private.json'), target = join(directory, 'target');
  try {
    await writeFile(target, 'do not replace', { mode: 0o600 });
    await symlink(target, path);
    await assert.rejects(initializeWallet(directory), /Refusing insecure wallet file/);
    assert.equal(await readFile(target, 'utf8'), 'do not replace');
    await rm(path);
    await writeFile(path, '{', { mode: 0o600 });
    await assert.rejects(initializeWallet(directory), /not valid JSON/);
    assert.equal(await readFile(path, 'utf8'), '{');
  } finally { await rm(directory, { recursive: true, force: true }); }
});
