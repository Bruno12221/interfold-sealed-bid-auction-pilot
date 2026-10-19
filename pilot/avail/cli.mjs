import { lstat, mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FetchRequest, JsonRpcProvider } from 'ethers';
import { connectTuring, fetchBridgeProof, hash32, httpUrl, pinnedSepoliaVerifier, publicationPlan,
  publisherEligibility, readPayload, retrievePublication, SEPOLIA, TURING, turingStatus, uint, verifyInclusion } from './lib.mjs';
import { initializeWallet } from './wallet.mjs';
import { publicationStatus, publishAuthorized, PUBLICATION_POLICY } from './publish.mjs';

const usage = 'Usage: node cli.mjs wallet-init | preflight | eligibility [PUBLIC_ADDRESS] | publish | publish-status | plan CIPHERTEXT_BIN --app-id N --publisher PUBLIC_ADDRESS | proof CIPHERTEXT_BIN --block-hash HASH --index N';
const args = process.argv.slice(2), command = args.shift();
const outDir = fileURLToPath(new URL('./.local/', import.meta.url));
async function save(name, value) {
  await mkdir(outDir, { recursive: true, mode: 0o700 });
  const path = resolve(outDir, name);
  await writeFile(path, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
  return path;
}
function flags(values, expected) {
  const result = {};
  while (values.length) {
    const flag = values.shift(), value = values.shift();
    if (!expected.includes(flag) || value === undefined || value.startsWith('--') || Object.hasOwn(result, flag)) throw new Error(usage);
    result[flag] = value;
  }
  if (expected.some(flag => !Object.hasOwn(result, flag))) throw new Error(usage);
  return result;
}

let api, provider;
async function run() {
  if (command === 'wallet-init') {
    if (args.length) throw new Error(usage);
    console.log(JSON.stringify(await initializeWallet(outDir), null, 2));
    // Wallet initialization does not connect to either network.
    return;
  }
  if (!['preflight', 'eligibility', 'plan', 'proof', 'publish', 'publish-status'].includes(command)) throw new Error(usage);
  let payload, options;
  if (['preflight', 'publish', 'publish-status'].includes(command)) { if (args.length) throw new Error(usage); }
  else if (command === 'eligibility') { if (args.length > 1) throw new Error(usage); }
  else {
    const path = args.shift();
    if (!path || path.startsWith('--')) throw new Error(usage);
    options = flags(args, command === 'plan' ? ['--app-id', '--publisher'] : ['--block-hash', '--index']);
    payload = await readPayload(path);
    if (command === 'plan') uint(options['--app-id'], 'appId');
    else { hash32(options['--block-hash'], 'Avail block hash'); uint(options['--index'], 'extrinsic index'); }
  }
  const endpoint = process.env.AVAIL_RPC_URL || TURING.rpc;
  api = await connectTuring(endpoint);
  let report;
  if (command === 'eligibility') {
    report = await publisherEligibility(api, args[0] ?? PUBLICATION_POLICY.publisher);
  } else if (command === 'publish') {
    report = await publishAuthorized(api, outDir,
      fileURLToPath(new URL('../../.pilot/proof-public-bid.json', import.meta.url)),
      fileURLToPath(new URL('../../.pilot/avail-authorized-ciphertext.bin', import.meta.url)));
  } else if (command === 'publish-status') {
    report = await publicationStatus(api, outDir);
  } else if (command === 'preflight') {
    report = { schemaVersion: 1, checkedAt: new Date().toISOString(), readOnly: true, broadcast: false,
      ...await turingStatus(api), rpcOrigin: httpUrl(endpoint, 'Avail RPC').origin,
      publisherEligibility: await publisherEligibility(api, PUBLICATION_POLICY.publisher),
      authorizedPublication: { count: 1, appId: 0, localBudgetAvail: '0.3', command: 'publish' },
      remaining: ['A publisher in the live finalized submitData whitelist and a verified runtime fee/accounting policy are required. Funding alone cannot enable publication.',
        'The current dedicated publisher is checked above. App ID 0 does not bypass the publisher whitelist.'] };
  } else if (command === 'plan') {
    report = await publicationPlan(api, payload, options['--app-id'], options['--publisher']);
    report.rpcOrigin = httpUrl(endpoint, 'Avail RPC').origin;
  } else {
    const publication = await retrievePublication(api, payload, options['--block-hash'], options['--index']);
    const proof = await fetchBridgeProof(process.env.AVAIL_BRIDGE_API_URL || TURING.bridgeApi,
      publication.blockHash, publication.extrinsicIndex, publication.contentHash);
    const request = new FetchRequest(process.env.SEPOLIA_RPC_URL || 'https://ethereum-sepolia.publicnode.com');
    request.timeout = 30_000;
    provider = new JsonRpcProvider(request);
    const { verifier, codeHashes } = await pinnedSepoliaVerifier(provider);
    const receipt = await verifyInclusion(verifier, publication.contentHash, proof, publication.blockNumber);
    if ((await api.rpc.chain.getBlockHash(publication.blockNumber)).toHex() !== publication.blockHash) throw new Error('Publication block changed during verification');
    const { payload: retrieved, ...coordinates } = publication;
    const payloadPath = resolve(outDir, `retrieved-${publication.contentHash.slice(2)}.bin`);
    await mkdir(outDir, { recursive: true, mode: 0o700 });
    await writeFile(payloadPath, retrieved, { mode: 0o600 });
    report = { schemaVersion: 1, checkedAt: new Date().toISOString(), readOnly: true, broadcast: false,
      genesisHash: TURING.genesisHash, publication: coordinates, retrievedPayloadFile: payloadPath,
      availabilityProof: proof.encoded, bridgeApiOrigin: proof.bridgeApiOrigin,
      sepolia: { chainId: SEPOLIA.chainId.toString(), verifier: SEPOLIA.verifier,
        bridge: SEPOLIA.bridge, vectorx: SEPOLIA.vectorx, runtimeCodeHashes: codeHashes, ...receipt } };
  }
  const artifact = await save(['preflight', 'eligibility'].includes(command) ? `${command}.json` : `${command}-${report.payload?.contentHash?.slice(2) ?? report.publication.contentHash.slice(2)}.json`, report);
  // The artifact contains the complete call/proof. Do not dump 360-KiB
  // ciphertext calls or repeated proof calldata into the terminal output.
  const summary = { ...report, artifact };
  if (summary.unsignedCall) summary.unsignedCall = { ...summary.unsignedCall,
    callHex: undefined, callBytes: (summary.unsignedCall.callHex.length - 2) / 2 };
  if (summary.availabilityProof) summary.availabilityProof = { bytes: (summary.availabilityProof.length - 2) / 2 };
  if (summary.sepolia) summary.sepolia = { ...summary.sepolia, validCalldata: undefined, tamperedCalldata: undefined };
  console.log(JSON.stringify(summary, null, 2));
}
try { await run(); }
catch (error) {
  // Do not echo upstream RPC URLs or request objects; URL credentials could be
  // present in environment configuration. No CLI command accepts signing input.
  let broadcast = false;
  if (['publish', 'publish-status'].includes(command)) {
    broadcast = 'unknown-check-saved-publication-intent';
    // A submission cannot begin before this durable intent exists.
    try { await lstat(resolve(outDir, 'publication-intent.json')); }
    catch (stateError) { if (stateError.code === 'ENOENT') broadcast = false; }
  }
  console.error(JSON.stringify({ error: String(error.shortMessage || error.message).replace(/https?:\/\/[^\s)]+/g, '[RPC URL]'), broadcast }));
  process.exitCode = 1;
} finally {
  if (api) await api.disconnect();
  if (provider) provider.destroy();
}
