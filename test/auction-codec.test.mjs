import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AbiCoder, keccak256, toBeHex } from 'ethers';
import { auctionContext, encodeEnvelope, decodeEnvelope, appendInputRoot, inputLeaf, validateTranscript,
  decodeReveal, secondPrice, encodeRevealForFixture, SCALAR_FIELD } from '../scripts/lib/auction.mjs';

const word = n => toBeHex(n, 32);
const addr = n => toBeHex(n, 20);
const config = { chainId: 11155111, auction: addr(1), seller: addr(2), nft: addr(3), tokenId: '1',
  collateralWei: '1000000000000000', tickWei: '10000000000000', priceLevels: 101, maxBidders: 16,
  e3Id: '7', biddingEnds: '1800000000', settlementDeadline: '1800100000' };
const context = auctionContext(config);
function input(i) {
  const ciphertext = `0x0${i + 1}`;
  return { index: i, bidder: addr(i + 10), ciphertext, commitment: word(i + 1),
    envelope: encodeEnvelope({ ciphertextHash: keccak256(ciphertext), inputProof: '0xaa', availabilityProof: '0xbb' }) };
}
const inputs = [input(0), input(1), input(2)];
let expectedInputRoot = context;
for (const x of inputs) expectedInputRoot = appendInputRoot(expectedInputRoot, x.index, x.bidder, x.envelope, x.commitment);
const transcript = { context, expectedInputRoot, expectedCount: 3, inputs };

test('context changes for each settlement domain field', () => {
  for (const [key, value] of Object.entries({ auction: addr(50), seller: addr(51), nft: addr(52), tokenId: '2',
    collateralWei: '2000000000000000', tickWei: '9000000000000', maxBidders: 15, e3Id: '8',
    biddingEnds: '1800000001', settlementDeadline: '1800100001' })) {
    assert.notEqual(auctionContext({ ...config, [key]: value }), context, key);
  }
  assert.throws(() => auctionContext({ ...config, chainId: 1 }), /Sepolia/);
  assert.throws(() => auctionContext({ ...config, e3Id: 2 ** 54 }), /unsafe/);
  assert.throws(() => auctionContext({ ...config, settlementDeadline: config.biddingEnds }), /deadlines/);
});

test('envelope is canonical and rejects missing or oversized proofs', () => {
  const x = inputs[0];
  assert.equal(encodeEnvelope(decodeEnvelope(x.envelope)), x.envelope);
  assert.throws(() => decodeEnvelope(x.envelope + '00'), /Noncanonical/);
  const data = decodeEnvelope(x.envelope);
  assert.throws(() => encodeEnvelope({ ...data, inputProof: '0x' }), /proof/);
  assert.throws(() => encodeEnvelope({ ...data, availabilityProof: '0x' }), /proof/);
  assert.throws(() => encodeEnvelope({ ...data, inputProof: '0x' + 'aa'.repeat(16384) }), /limit/);
  assert.throws(() => decodeEnvelope(AbiCoder.defaultAbiCoder().encode(['uint8', 'bytes32', 'bytes', 'bytes'],
    [2, data.ciphertextHash, data.inputProof, data.availabilityProof])), /version/);
});

test('ordered complete transcript binds ciphertext, bidder, slot and commitment', () => {
  assert.equal(validateTranscript(transcript).inputRoot, expectedInputRoot);
  assert.equal(validateTranscript(transcript).leaves.length, 3);
  const mutations = [
    { inputs: inputs.slice(0, 2) },
    { inputs: [inputs[1], inputs[0], inputs[2]] },
    { inputs: [inputs[0], { ...inputs[1], bidder: inputs[0].bidder }, inputs[2]] },
    { inputs: [{ ...inputs[0], ciphertext: '0x99' }, inputs[1], inputs[2]] },
    { inputs: [{ ...inputs[0], commitment: word(50) }, inputs[1], inputs[2]] },
    { expectedInputRoot: word(100) }, { expectedCount: 0 },
  ];
  for (const mutation of mutations) assert.throws(() => validateTranscript({ ...transcript, ...mutation }));
  assert.throws(() => appendInputRoot(context, 0, addr(10), inputs[0].envelope, word(SCALAR_FIELD)), /field/);
  assert.notEqual(inputLeaf(context, 0, addr(10), inputs[0].envelope, word(1)),
    inputLeaf(context, 1, addr(10), inputs[0].envelope, word(1)));
});

test('reveal codec uses all 50 little-endian uint64 coefficients', () => {
  assert.deepEqual(decodeReveal(encodeRevealForFixture([31, 77, 42]), 3).ticks, ['31', '77', '42']);
  assert.throws(() => decodeReveal('0x01', 3), /400/);
  assert.throws(() => decodeReveal(encodeRevealForFixture([31, 77, 42, 1]), 3), /Unused/);
  const invalid = new Uint8Array(400); invalid[0] = 101;
  assert.throws(() => decodeReveal(invalid, 1), /range/);
  const bigEndian = new Uint8Array(400); bigEndian[7] = 1;
  assert.throws(() => decodeReveal(bigEndian, 1), /range/);
});

test('second price matches ties, sole positive bidder and abstentions', () => {
  assert.deepEqual(secondPrice([31, 77, 42]), { winnerIndex: 1, highestTicks: '77', priceTicks: '42' });
  assert.deepEqual(secondPrice([77, 77, 42]), { winnerIndex: 0, highestTicks: '77', priceTicks: '77' });
  assert.deepEqual(secondPrice([0, 100, 0]), { winnerIndex: 1, highestTicks: '100', priceTicks: '0' });
  assert.deepEqual(secondPrice([0, 0]), { winnerIndex: null, highestTicks: '0', priceTicks: '0' });
  assert.throws(() => secondPrice([101]), /collateral/);
});
