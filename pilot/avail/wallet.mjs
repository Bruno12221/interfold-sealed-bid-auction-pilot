import { constants } from 'node:fs';
import { lstat, mkdir, open } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { TURING } from './lib.mjs';

const require = createRequire(import.meta.url);
const { Keyring, cryptoWaitReady } = require('avail-js-sdk');
const { mnemonicGenerate, mnemonicValidate } = require('@polkadot/util-crypto');

function requirePrivateFile(info, isDirectory) {
  const mode = isDirectory ? 0o700 : 0o600;
  if ((isDirectory ? !info.isDirectory() : !info.isFile()) || info.isSymbolicLink()
      || (info.mode & 0o777) !== mode || info.uid !== process.getuid()) {
    throw new Error(`Refusing insecure wallet ${isDirectory ? 'directory' : 'file'}: require owner-only ${mode.toString(8)} permissions and current ownership`);
  }
}

function publicRecord(wallet, reused) {
  return { schemaVersion: 1, network: 'avail-turing', genesisHash: TURING.genesisHash,
    keyType: 'sr25519', address: wallet.address, publicKey: wallet.publicKey, reused, broadcast: false };
}

async function loadExisting(path, action) {
  // O_NOFOLLOW closes the check/open symlink race for the wallet itself.
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const info = await handle.stat();
    requirePrivateFile(info, false);
    if (info.size < 1 || info.size > 8192) throw new Error('Invalid private wallet file length');
    let wallet;
    try { wallet = JSON.parse(await handle.readFile('utf8')); }
    catch { throw new Error('Private wallet file is not valid JSON'); }
    if (wallet.schemaVersion !== 1 || wallet.network !== 'avail-turing' || wallet.genesisHash !== TURING.genesisHash
        || wallet.keyType !== 'sr25519' || typeof wallet.mnemonic !== 'string' || !mnemonicValidate(wallet.mnemonic)) {
      throw new Error('Private wallet file is not the dedicated Turing sr25519 wallet');
    }
    let pair;
    try { pair = new Keyring({ type: 'sr25519', ss58Format: 42 }).addFromUri(wallet.mnemonic); }
    catch { throw new Error('Cannot derive the dedicated Turing wallet'); }
    try {
      if (wallet.address !== pair.address || wallet.publicKey !== `0x${Buffer.from(pair.publicKey).toString('hex')}`) {
        throw new Error('Private wallet public identity does not match its mnemonic');
      }
      const record = publicRecord(wallet, true);
      return action ? await action(pair, record) : record;
    } finally { pair.lock(); }
  } finally { await handle.close(); }
}

export async function withWalletSigner(directory, action) {
  requirePrivateFile(await lstat(directory), true);
  await cryptoWaitReady();
  return loadExisting(join(directory, 'wallet.private.json'), action);
}

export async function initializeWallet(directory) {
  if (process.platform === 'win32' || typeof process.getuid !== 'function' || constants.O_NOFOLLOW === undefined) {
    throw new Error('Private wallet creation requires Unix owner-only permissions and O_NOFOLLOW');
  }
  await mkdir(directory, { recursive: true, mode: 0o700 });
  requirePrivateFile(await lstat(directory), true);
  await cryptoWaitReady();
  const path = join(directory, 'wallet.private.json');
  let handle;
  try { handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    const existing = await lstat(path);
    requirePrivateFile(existing, false);
    return loadExisting(path);
  }
  let pair;
  try {
    // mnemonicGenerate uses cryptographic randomness. Do not use this pinned
    // SDK's Account.generate(), which currently uses Math.random().
    const mnemonic = mnemonicGenerate(24);
    pair = new Keyring({ type: 'sr25519', ss58Format: 42 }).addFromUri(mnemonic);
    const wallet = { schemaVersion: 1, network: 'avail-turing', genesisHash: TURING.genesisHash,
      keyType: 'sr25519', createdAt: new Date().toISOString(), address: pair.address,
      publicKey: `0x${Buffer.from(pair.publicKey).toString('hex')}`, mnemonic };
    // Set exact permissions even under a restrictive umask; no group/other
    // access is ever introduced. A crash leaves an unusable file, never replaces
    // an existing key, and a later invocation fails closed on that partial file.
    await handle.chmod(0o600);
    await handle.writeFile(JSON.stringify(wallet, null, 2) + '\n');
    await handle.sync();
    requirePrivateFile(await handle.stat(), false);
    const directoryHandle = await open(directory, constants.O_RDONLY | constants.O_NOFOLLOW);
    try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
    return publicRecord(wallet, false);
  } finally { pair?.lock(); await handle.close(); }
}
