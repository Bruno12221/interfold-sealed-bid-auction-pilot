import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { Contract, ZeroAddress, keccak256 } from 'ethers';
import { sepoliaProvider, PROTOCOL } from './config.mjs';
import { decodeEnvelope, decodeReveal, secondPrice, validateTranscript } from './lib/auction.mjs';

const [command, ...args] = process.argv.slice(2);
if (!['export', 'settlement'].includes(command)) {
  console.error('Usage: node scripts/auction-session.mjs export CIPHERTEXTS.json PUBLIC_KEY_HEX_FILE\n       node scripts/auction-session.mjs settlement');
  process.exit(1);
}
const deployment = JSON.parse(await readFile('deployments/sepolia.json', 'utf8'));
const provider = await sepoliaProvider();
try {
  const snapshot = await provider.getBlock('latest');
  const block = snapshot.number;
  const at = { blockTag: block };
  const auction = new Contract(deployment.auction.address, [
    'function state() view returns(uint8)', 'function e3Id() view returns(uint256)',
    'function auctionContext() view returns(bytes32)', 'function inputRoot() view returns(bytes32)',
    'function bidCount() view returns(uint256)', 'function bids(uint256) view returns(address bidder,bytes32 ciphertextHash,bytes32 commitment)',
    'function settle(bytes)', 'event BidSubmitted(uint256 indexed index,address indexed bidder,bytes ciphertext,bytes32 commitment,bytes32 inputRoot)',
  ], provider);
  const source = new Contract(deployment.resultSource.address, ['function program() view returns(address)'], provider);
  const programAddress = await source.program(at);
  if (programAddress === ZeroAddress || await auction.state(at) !== 1n) throw new Error('Auction has no bound program or is not in Bidding state');
  // Reuse the exactly pinned E3 tuple from the source interface's compiler output.
  const readArtifact = JSON.parse(await readFile('out/IInterfoldRead.sol/IInterfoldRead.json', 'utf8'));
  const protocol = new Contract(PROTOCOL, readArtifact.abi, provider);
  const e3Id = await auction.e3Id(at);
  const [e3, stage, context, inputRoot, count] = await Promise.all([
    protocol.getE3(e3Id, at), protocol.getE3Stage(e3Id, at), auction.auctionContext(at), auction.inputRoot(at), auction.bidCount(at),
  ]);
  if (e3.e3Program.toLowerCase() !== programAddress.toLowerCase() || e3.paramSet !== 2n) throw new Error('E3 program or secure parameter set differs');
  if (count === 0n || count > 32n) throw new Error('No nonempty canonical bid set to export');
  const program = new Contract(programAddress, [
    'function auctionContext(uint256) view returns(bytes32)', 'function inputRoot(uint256) view returns(bytes32)',
    'function bidCount(uint256) view returns(uint256)', 'function paramsHash() view returns(bytes32)',
    'function computeInputRoot(uint256) view returns(bytes32)',
  ], provider);
  const [programContext, programRoot, programCount, programParamsHash, computeInputRoot] = await Promise.all([
    program.auctionContext(e3Id, at), program.inputRoot(e3Id, at), program.bidCount(e3Id, at),
    program.paramsHash(at), program.computeInputRoot(e3Id, at),
  ]);
  if (programContext !== context || programRoot !== inputRoot || programCount !== count) throw new Error('Program ledger differs from escrow');
  const anchor = { chainId: '11155111', auction: deployment.auction.address.toLowerCase(), e3Id: String(e3Id),
    context, committeePublicKey: e3.committeePublicKey, inputRoot, bidCount: Number(count) };
  await mkdir('.pilot', { recursive: true, mode: 0o700 });
  if (command === 'settlement') {
    if (stage !== 5n) throw new Error(`Threshold decryption has not completed (stage ${stage})`);
    const reveal = decodeReveal(e3.plaintextOutput, count);
    const data = auction.interface.encodeFunctionData('settle', [reveal.settlementCalldataArgument]);
    await provider.call({ from: deployment.deployer, to: deployment.auction.address, data, blockTag: block });
    const report = { checkedAt: new Date().toISOString(), blockNumber: block, ...anchor, ticks: reveal.ticks,
      outcome: secondPrice(reveal.ticks), transaction: { chainId: 11155111, to: deployment.auction.address, value: '0', data },
      simulationPassed: true, broadcast: false };
    await writeFile('.pilot/settlement.json', JSON.stringify(report, null, 2) + '\n');
    console.log(JSON.stringify(report, null, 2));
  } else {
    if (stage !== 3n || BigInt(snapshot.timestamp) < e3.inputWindow[1]) throw new Error('Export computation inputs only after closing, before ciphertext publication, at KeyPublished');
    if (args.length !== 2) throw new Error('Provide ciphertext records and public key hex file');
    const records = JSON.parse(await readFile(args[0], 'utf8'));
    const publicKey = (await readFile(args[1], 'utf8')).trim();
    if (!Array.isArray(records) || records.length !== Number(count)) throw new Error('Ciphertext record count differs');
    const inputs = [];
    const firstBlock = deployment.transactions.find(t => t.label === 'auction').blockNumber;
    const events = [];
    for (let from = firstBlock; from <= block; from += 2000) {
      events.push(...await auction.queryFilter(auction.filters.BidSubmitted(), from, Math.min(from + 1999, block)));
    }
    if (events.length !== Number(count)) throw new Error('Canonical bid events missing or duplicated');
    for (let i = 0; i < events.length; ++i) {
      const event = events[i].args;
      const stored = await auction.bids(i, at);
      if (event.index !== BigInt(i) || event.bidder !== stored.bidder || event.commitment !== stored.commitment
          || keccak256(event.ciphertext) !== stored.ciphertextHash) throw new Error('Bid event differs from escrow');
      decodeEnvelope(event.ciphertext);
      if (!records[i] || records[i].slot !== i) throw new Error('Ciphertext records must be in slot order');
      inputs.push({ slot: i, bidder: event.bidder.toLowerCase(), ciphertext: records[i].ciphertext,
        envelope: event.ciphertext, commitment: event.commitment });
    }
    validateTranscript({ context, expectedInputRoot: inputRoot, expectedCount: Number(count), inputs: inputs.map(x => ({ ...x, index: x.slot })) });
    if ((await provider.getBlock(block)).hash !== snapshot.hash) throw new Error('Chain reorganized while exporting; retry');
    const manifest = { schemaVersion: 1, anchor, publicKey, inputs };
    await writeFile('.pilot/anchor.json', JSON.stringify(anchor, null, 2) + '\n');
    await writeFile('.pilot/manifest.json', JSON.stringify(manifest, null, 2) + '\n');
    await writeFile('.pilot/anchor-provenance.json', JSON.stringify({ capturedAt: new Date().toISOString(),
      blockNumber: block, blockHash: snapshot.hash, protocol: PROTOCOL,
      program: programAddress, paramsHash: programParamsHash, computeInputRoot,
      resultSource: deployment.resultSource.address, ...anchor }, null, 2) + '\n');
    console.log(`Exported ${count} canonical ciphertext inputs at Sepolia block ${block} to .pilot/manifest.json and an independently read .pilot/anchor.json`);
  }
} finally { provider.destroy(); }
