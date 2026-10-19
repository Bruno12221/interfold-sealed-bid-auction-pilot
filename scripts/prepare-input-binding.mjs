import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { createHash } from 'node:crypto';
import { AbiCoder, getBytes, keccak256 } from 'ethers';

const [statementPath, publicBidPath, outputPath] = process.argv.slice(2);
if (!outputPath || process.argv.length !== 5) {
  throw new Error('Usage: node scripts/prepare-input-binding.mjs STATEMENT_JSON PUBLIC_BID_JSON NEW_OUTPUT_DIRECTORY');
}
const statement = JSON.parse(await readFile(statementPath, 'utf8'));
const publicBid = JSON.parse(await readFile(publicBidPath, 'utf8'));
const names = ['chainId', 'program', 'interfold', 'auction', 'context', 'e3Id', 'committeePublicKey',
  'paramsHash', 'slot', 'bidder', 'maxTick', 'ciphertextHash', 'ciphertextCommitment'];
const types = ['uint256', 'address', 'address', 'address', 'bytes32', 'uint256', 'bytes32',
  'bytes32', 'uint256', 'address', 'uint256', 'bytes32', 'bytes32'];
if (Object.keys(statement).length !== names.length || names.some(name => statement[name] === undefined)) {
  throw new Error('Expected the exact thirteen input statement properties');
}
for (const name of ['chainId', 'e3Id', 'slot', 'maxTick']) {
  if (typeof statement[name] !== 'string' || !/^(0|[1-9][0-9]*)$/.test(statement[name])) {
    throw new Error(`${name} must be a canonical decimal string; full uint256 precision is required`);
  }
}
const raw = Buffer.from(getBytes(AbiCoder.defaultAbiCoder().encode(types, names.map(name => statement[name]))));
if (raw.length !== 416) throw new Error('Unexpected input statement encoding');
const ct = Buffer.from(getBytes(publicBid.ciphertext));
if (ct.length > 1_000_000 || !ct.length) throw new Error('Invalid public BFV input size');
if (keccak256(ct) !== statement.ciphertextHash.toLowerCase()
    || publicBid.commitment.toLowerCase() !== statement.ciphertextCommitment.toLowerCase()
    || publicBid.committeePublicKey.toLowerCase() !== statement.committeePublicKey.toLowerCase()
    || BigInt(publicBid.slot) !== BigInt(statement.slot)) throw new Error('Public bid differs from the input statement');
const items = [raw, ct];
const framed = [Buffer.from([2, 0, 0, 0])];
for (const item of items) {
  const size = Buffer.alloc(8); size.writeBigUInt64LE(BigInt(item.length));
  framed.push(size, item);
}
const limbs = [];
for (let i = 0; i < 13; ++i) {
  const value = BigInt('0x' + raw.subarray(i * 32, (i + 1) * 32).toString('hex'));
  limbs.push((value >> 128n).toString(), (value & ((1n << 128n) - 1n)).toString());
}
const out = resolve(outputPath);
await mkdir(out, { mode: 0o700 }); // Deliberately refuse reuse of an older proof bundle.
await writeFile(join(out, 'input.bin'), Buffer.concat(framed));
await writeFile(join(out, 'cli-input.json'), JSON.stringify({ input: items.map(item => '0x01' + item.toString('hex')) }));
await writeFile(join(out, 'statement.bin'), raw);
await writeFile(join(out, 'public-inputs.json'), JSON.stringify(limbs, null, 2) + '\n');
const report = { scope: 'public-byte-binding-bundle-not-a-proof', statementBytes: raw.length,
  statementSha256: createHash('sha256').update(raw).digest('hex'), ciphertextKeccak256: keccak256(ct),
  publicInputs: limbs.length, bindingReceiptGenerated: false, encryptionProofVerified: false };
await writeFile(join(out, 'bundle.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
