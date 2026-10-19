import { constants } from 'node:fs';
import { lstat, open, readFile, rename, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { keccak256 } from 'ethers';
import { hash32, payloadIdentity, requirePublisherEligibility, retrievePublication, TURING } from './lib.mjs';
import { withWalletSigner } from './wallet.mjs';

export const PUBLICATION_POLICY = Object.freeze({
  publisher: '5FNAKEHhsAXs3N4kJv7A5ddhCHyUMv2U86G8Cmm3xSR3iMcf',
  contentHash: '0x1d167bffa8274622f5bd4df4dea74a7f2c3adea3f68c89e6ce87f49c98cf87f9',
  payloadBytes: 368666,
  appId: 0,
  budgetPlanck: 300_000_000_000_000_000n,
  mortalityBlocks: 4,
});
const INTENT = 'publication-intent.json';
const LOCK = 'publication.lock';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

export async function requirePublicationReadiness(api) {
  const eligibility = await requirePublisherEligibility(api, PUBLICATION_POLICY.publisher);
  if (eligibility.feeAccounting?.publicationSupported !== true) {
    throw new Error(`Turing publication fee/accounting policy is unverified (${eligibility.feeAccounting?.status ?? 'unknown'}); signing is disabled. Funding does not bypass this gate`);
  }
  return eligibility;
}

async function privateDirectory(directory) {
  const info = await lstat(directory);
  if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o777) !== 0o700 || info.uid !== process.getuid()) {
    throw new Error('Publication state directory must be owned by the current user with mode 0700');
  }
}
async function createPrivate(path, data) {
  const handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await handle.chmod(0o600); await handle.writeFile(data); await handle.sync(); }
  finally { await handle.close(); }
}
async function syncDirectory(directory) {
  const handle = await open(directory, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { await handle.sync(); } finally { await handle.close(); }
}
async function readPrivateJson(path) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const info = await handle.stat();
    if (!info.isFile() || (info.mode & 0o777) !== 0o600 || info.uid !== process.getuid() || info.size > 4_194_304) {
      throw new Error('Publication state file must be owned by the current user with mode 0600 and bounded size');
    }
    try { return JSON.parse(await handle.readFile('utf8')); }
    catch { throw new Error('Publication intent is corrupt; refusing any automatic retry'); }
  } finally { await handle.close(); }
}
async function exists(path) {
  try { await lstat(path); return true; }
  catch (error) { if (error.code === 'ENOENT') return false; throw error; }
}
async function updateIntent(directory, intent) {
  const temporary = join(directory, `publication-update-${randomUUID()}.tmp`);
  await createPrivate(temporary, JSON.stringify(intent, null, 2) + '\n');
  await rename(temporary, join(directory, INTENT));
  await syncDirectory(directory);
}
export async function withPublicationLock(directory, action) {
  await privateDirectory(directory);
  let lock;
  try { lock = await open(join(directory, LOCK), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600); }
  catch (error) {
    if (error.code === 'EEXIST') throw new Error('An exclusive publication lock exists; do not remove it until its process and intent have been checked');
    throw error;
  }
  try {
    await lock.chmod(0o600);
    await lock.writeFile(JSON.stringify({ pid: process.pid, createdAt: new Date().toISOString() }) + '\n');
    await lock.sync();
    return await action();
  } finally { await lock.close(); await unlink(join(directory, LOCK)); }
}

export function assertPublicationBudget(feeInput, freeInput, frozenInput, existentialInput) {
  const fee = BigInt(feeInput), free = BigInt(freeInput), frozen = BigInt(frozenInput), existential = BigInt(existentialInput);
  if (fee <= 0n || free < 0n || frozen < 0n || existential < 0n) throw new Error('Invalid fee or account balances');
  const withReserve = (fee * 5n + 3n) / 4n;
  if (withReserve > PUBLICATION_POLICY.budgetPlanck) throw new Error('Live publication fee plus 25% reserve exceeds the local 0.3 AVAIL budget');
  const available = free > frozen ? free - frozen : 0n;
  if (available < withReserve + existential) throw new Error('Dedicated Turing wallet lacks AVAIL for the quoted fee, reserve, and existential balance');
  return { quotePlanck: fee.toString(), quoteWithReservePlanck: withReserve.toString(),
    localBudgetPlanck: PUBLICATION_POLICY.budgetPlanck.toString(), onChainMaxFee: false,
    policy: 'Local budget gate: fresh exact-extrinsic quote plus 25% reserve, 4-block mortality. Avail has no signed max-fee field.' };
}

// Separating this orchestration from SDK signing makes the critical ordering
// testable: durable signed intent first, exactly one submission attempt, and no
// automatic retry after either a response or an ambiguous network failure.
export async function executeOneShot(directory, { prepare, submit, observe }) {
  return withPublicationLock(directory, async () => {
    if (await exists(join(directory, INTENT))) throw new Error('A signed publication intent already exists; use publish-status, never automatic rebroadcast');
    const intent = await prepare();
    intent.stage = 'signed-before-broadcast';
    await createPrivate(join(directory, INTENT), JSON.stringify(intent, null, 2) + '\n');
    await syncDirectory(directory);
    let returnedHash;
    try { returnedHash = await submit(intent.signedExtrinsic); }
    catch {
      intent.stage = 'submission-unknown';
      intent.submissionAttemptedAt = new Date().toISOString();
      await updateIntent(directory, intent);
      throw new Error(`Publication submission is ambiguous; inspect saved intent ${intent.extrinsicHash} with publish-status. No retry was made`);
    }
    if (String(returnedHash).toLowerCase() !== intent.extrinsicHash.toLowerCase()) {
      intent.stage = 'submission-unknown';
      await updateIntent(directory, intent);
      throw new Error('RPC returned a different transaction hash; saved intent must be checked with publish-status');
    }
    intent.stage = 'submitted';
    intent.submittedAt = new Date().toISOString();
    await updateIntent(directory, intent);
    const result = await observe(intent);
    intent.stage = 'finalized';
    intent.result = result;
    await updateIntent(directory, intent);
    return { ...result, intentFile: join(directory, INTENT) };
  });
}

export async function authorizedCiphertext(sourcePath, rawPath) {
  const sourceBytes = await readFile(sourcePath);
  if (sourceBytes.length > 2_097_152) throw new Error('Public encrypted-bid artifact is too large');
  let source;
  try { source = JSON.parse(sourceBytes.toString('utf8')); }
  catch { throw new Error('Public encrypted-bid artifact is invalid JSON'); }
  if (typeof source.ciphertext !== 'string' || !/^0x(?:[0-9a-fA-F]{2})+$/.test(source.ciphertext)) throw new Error('Invalid public ciphertext byte encoding');
  const payload = Buffer.from(source.ciphertext.slice(2), 'hex');
  const identity = payloadIdentity(payload);
  if (identity.contentHash !== PUBLICATION_POLICY.contentHash || source.ciphertextHash !== identity.contentHash
      || identity.bytes !== PUBLICATION_POLICY.payloadBytes || source.slot !== 1) throw new Error('This command is authorized for one exact synthetic Noir-proof ciphertext only');
  try { await createPrivate(rawPath, payload); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    if (!(await readFile(rawPath)).equals(payload)) throw new Error('Saved authorized ciphertext differs from the public encrypted-bid artifact');
  }
  return { payload, identity };
}

async function prepareSignedIntent(api, directory, payload, rawPath) {
  if (api.genesisHash.toHex() !== TURING.genesisHash) throw new Error('Refusing publication outside Avail Turing');
  const eligibility = await requirePublicationReadiness(api);
  return withWalletSigner(directory, async (pair, wallet) => {
    if (wallet.address !== PUBLICATION_POLICY.publisher) throw new Error('Refusing a different publisher wallet');
    const [account, pendingNonce, finalizedHash, bestHeader, methods] = await Promise.all([
      api.query.system.account(wallet.address), api.rpc.system.accountNextIndex(wallet.address),
      api.rpc.chain.getFinalizedHead(), api.rpc.chain.getHeader(), api.rpc.rpc.methods(),
    ]);
    if (!methods.methods.some(method => method.toString() === 'author_submitExtrinsic')) throw new Error('Avail RPC does not expose transaction submission; no signature was made');
    if (account.nonce.toString() !== pendingNonce.toString()) throw new Error('Publisher already has a pending nonce; refusing another publication');
    if (BigInt(account.data.free.toString()) === 0n) throw new Error('Dedicated Turing wallet is not funded yet');
    const finalized = await api.rpc.chain.getHeader(finalizedHash);
    const height = finalized.number.toNumber();
    if (bestHeader.number.toNumber() - height > 1) throw new Error('Turing finality lag is too large for the 4-block mortality policy');
    const tx = api.tx.dataAvailability.submitData(`0x${payload.toString('hex')}`);
    tx.sign(pair, { appId: PUBLICATION_POLICY.appId, nonce: pendingNonce.toString(), tip: 0,
      era: { current: height, period: PUBLICATION_POLICY.mortalityBlocks }, blockHash: finalizedHash,
      genesisHash: api.genesisHash, runtimeVersion: api.runtimeVersion,
      signedExtensions: api.registry.signedExtensions, version: api.extrinsicType });
    if (!tx.isSigned || tx.nonce.toString() !== pendingNonce.toString() || tx.signer.toString() !== wallet.address
        || tx.inner.signature.get('appId').toString() !== '0' || !tx.era.isMortalEra
        || tx.era.asMortalEra.period.toString() !== '4') throw new Error('Signed publication identity, App ID, nonce, or mortality differs from the plan');
    const encoded = tx.toU8a();
    const info = await api.call.transactionPaymentApi.queryInfo(encoded, encoded.length);
    const budget = assertPublicationBudget(info.partialFee.toString(), account.data.free.toString(),
      account.data.frozen?.toString() ?? '0', api.consts.balances.existentialDeposit.toString());
    // Recheck the public state after signing/fee estimation and before saving the
    // intent. No signature reaches the network until all gates pass.
    const [freshAccount, freshNonce, freshHead] = await Promise.all([
      api.query.system.account(wallet.address), api.rpc.system.accountNextIndex(wallet.address), api.rpc.chain.getHeader(),
    ]);
    if (freshNonce.toString() !== pendingNonce.toString() || freshAccount.nonce.toString() !== pendingNonce.toString()
        || freshAccount.data.free.toString() !== account.data.free.toString()
        || (freshAccount.data.frozen?.toString() ?? '0') !== (account.data.frozen?.toString() ?? '0')
        || freshHead.number.toNumber() > height + 1) throw new Error('Publisher state or block changed while preparing the short-lived transaction; no broadcast occurred');
    const freshEligibility = await requirePublicationReadiness(api);
    if (freshEligibility.runtimeCodeStorageHash !== eligibility.runtimeCodeStorageHash
        || freshEligibility.runtimeSpecVersion !== eligibility.runtimeSpecVersion
        || freshEligibility.runtimeTransactionVersion !== eligibility.runtimeTransactionVersion) {
      throw new Error('Turing runtime changed while preparing publication; no intent or broadcast was created');
    }
    return { schemaVersion: 1, createdAt: new Date().toISOString(), network: 'avail-turing', genesisHash: TURING.genesisHash,
      publisherEligibility: freshEligibility,
      publisher: wallet.address, appId: 0, nonce: pendingNonce.toString(),
      payload: payloadIdentity(payload), rawCiphertextFile: rawPath, budget,
      balanceBeforePlanck: account.data.free.toString(), signedAtFinalizedBlock: height,
      mortalityBlocks: PUBLICATION_POLICY.mortalityBlocks, expiresAtBlock: height + PUBLICATION_POLICY.mortalityBlocks,
      extrinsicHash: tx.hash.toHex(), signedExtrinsic: tx.toHex(),
      callHash: keccak256(tx.method.toHex()), transferAmountPlanck: '0',
      caveat: 'Exactly one submitData attempt. A signed intent is never automatically rebroadcast, including after timeout or process restart.' };
  });
}

async function inspectFinalized(api, intent, payload, blockHash, blockNumber, index) {
  const publication = await retrievePublication(api, payload, blockHash, index);
  const events = await api.query.system.events.at(blockHash);
  const fees = events.filter(({ phase, event }) => phase.isApplyExtrinsic && phase.asApplyExtrinsic.toNumber() === index
    && event.section === 'transactionPayment' && event.method === 'TransactionFeePaid');
  if (fees.length !== 1 || fees[0].event.data[0].toString() !== intent.publisher) throw new Error('Cannot authenticate the publication fee event');
  const actualFee = BigInt(fees[0].event.data[1].toString()), tip = BigInt(fees[0].event.data[2].toString());
  const account = await api.query.system.account.at(blockHash, intent.publisher);
  const balanceAfter = BigInt(account.data.free.toString()), debit = BigInt(intent.balanceBeforePlanck) - balanceAfter;
  if (tip !== 0n || actualFee <= 0n || debit !== actualFee) throw new Error('Publication fee does not match the exact dedicated-wallet balance debit');
  const { payload: retrieved, ...coordinates } = publication;
  return { network: 'avail-turing', publisher: intent.publisher, appId: 0, broadcast: true,
    transactionHash: intent.extrinsicHash, blockNumber, blockHash, extrinsicIndex: index,
    payload: { bytes: retrieved.length, contentHash: coordinates.contentHash, sha256: coordinates.sha256 },
    finalized: true, dispatchSuccessVerified: true, exactPublishedBytesVerified: true,
    actualFeePlanck: actualFee.toString(), balanceAfterPlanck: balanceAfter.toString(),
    exactBalanceDebitVerified: true, localBudgetPlanck: PUBLICATION_POLICY.budgetPlanck.toString(),
    localBudgetRespected: actualFee <= PUBLICATION_POLICY.budgetPlanck,
    bridgeProofVerified: false, nextStep: 'Fetch the bridge proof after VectorX has bridged this Avail range; finalization alone is not a Sepolia inclusion receipt.' };
}

export async function observeIntent(api, intent, { waitMs = 480_000 } = {}) {
  if (intent.schemaVersion !== 1 || intent.genesisHash !== TURING.genesisHash || api.genesisHash.toHex() !== TURING.genesisHash
      || intent.publisher !== PUBLICATION_POLICY.publisher || intent.appId !== 0
      || intent.payload?.contentHash !== PUBLICATION_POLICY.contentHash || !Number.isSafeInteger(intent.signedAtFinalizedBlock)
      || intent.signedAtFinalizedBlock < 1 || intent.mortalityBlocks !== 4) throw new Error('Saved intent differs from the one authorized publication');
  const tx = api.tx(intent.signedExtrinsic);
  if (tx.hash.toHex() !== hash32(intent.extrinsicHash, 'intent transaction hash') || !tx.isSigned
      || tx.signer.toString() !== intent.publisher || tx.nonce.toString() !== intent.nonce
      || tx.inner.signature.get('appId').toString() !== '0' || !tx.era.isMortalEra || tx.era.asMortalEra.period.toString() !== '4'
      || tx.method.section !== 'dataAvailability' || tx.method.method !== 'submitData'
      || keccak256(tx.method.args[0].toU8a(true)) !== PUBLICATION_POLICY.contentHash) throw new Error('Saved signed transaction differs from the authorized data publication');
  const payload = Buffer.from(tx.method.args[0].toU8a(true));
  const started = Date.now();
  let nextBlock = intent.signedAtFinalizedBlock;
  do {
    const finalizedHash = await api.rpc.chain.getFinalizedHead();
    const finalized = (await api.rpc.chain.getHeader(finalizedHash)).number.toNumber();
    // A 4-block mortal transaction cannot enter a later block. Bound scans even
    // when a saved intent is inspected days later.
    const lastBlock = Math.min(finalized, intent.signedAtFinalizedBlock + 4);
    while (nextBlock <= lastBlock) {
      const blockHash = (await api.rpc.chain.getBlockHash(nextBlock)).toHex();
      const block = await api.rpc.chain.getBlock(blockHash);
      const index = block.block.extrinsics.findIndex(extrinsic => extrinsic.hash.toHex() === intent.extrinsicHash);
      if (index >= 0) return inspectFinalized(api, intent, payload, blockHash, nextBlock, index);
      nextBlock++;
    }
    if (finalized >= intent.signedAtFinalizedBlock + 4) throw new Error('Saved mortal publication expired without finalized inclusion; do not automatically retry or replace its intent');
    if (Date.now() - started >= waitMs) break;
    await sleep(3000);
  } while (Date.now() - started < waitMs);
  throw new Error('Publication finality is not yet established; use publish-status without rebroadcast');
}

export async function publishAuthorized(api, directory, sourcePath, rawPath) {
  // Check public dispatch eligibility before touching ciphertext state, the
  // execution lock, a signed intent, or the dedicated wallet's private material.
  await requirePublicationReadiness(api);
  const { payload } = await authorizedCiphertext(sourcePath, rawPath);
  return executeOneShot(directory, {
    prepare: () => prepareSignedIntent(api, directory, payload, rawPath),
    submit: async signed => (await api.rpc.author.submitExtrinsic(signed)).toHex(),
    observe: intent => observeIntent(api, intent),
  });
}
export async function publicationStatus(api, directory) {
  return withPublicationLock(directory, async () => {
    const intent = await readPrivateJson(join(directory, INTENT));
    const result = await observeIntent(api, intent, { waitMs: 0 });
    intent.stage = 'finalized'; intent.result = result;
    await updateIntent(directory, intent);
    return { ...result, intentFile: join(directory, INTENT) };
  });
}
