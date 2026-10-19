import { AbiCoder, ZeroAddress, getAddress, getBytes, hexlify, isHexString, keccak256, toBeHex } from 'ethers';

const abi = AbiCoder.defaultAbiCoder();
export const ENVELOPE_TYPES = ['uint8', 'bytes32', 'bytes', 'bytes'];
export const SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const REVEAL_COEFFICIENTS = 50;

function unsigned(value, bits, label) {
  if (typeof value === 'number' && !Number.isSafeInteger(value)) throw new Error(`${label}: unsafe number`);
  if (typeof value === 'boolean' || value === null || value === undefined) throw new Error(`${label}: integer required`);
  const n = BigInt(value);
  if (n < 0n || n >= (1n << BigInt(bits))) throw new Error(`${label}: outside uint${bits}`);
  return n;
}

function word(value, label, nonzero = true) {
  if (!isHexString(value, 32) || (nonzero && BigInt(value) === 0n)) throw new Error(`${label}: nonzero bytes32 required`);
  return value.toLowerCase();
}

function address(value, label) {
  const normalized = getAddress(value);
  if (normalized === ZeroAddress) throw new Error(`${label}: zero address`);
  return normalized;
}

export function auctionContext(config) {
  const c = config;
  const chainId = unsigned(c.chainId, 256, 'chainId');
  if (chainId !== 11155111n) throw new Error('Only Sepolia chain ID 11155111 is supported');
  const levels = unsigned(c.priceLevels, 16, 'priceLevels');
  const max = unsigned(c.maxBidders, 32, 'maxBidders');
  const collateral = unsigned(c.collateralWei, 256, 'collateralWei');
  const tick = unsigned(c.tickWei, 256, 'tickWei');
  const end = unsigned(c.biddingEnds, 64, 'biddingEnds');
  const deadline = unsigned(c.settlementDeadline, 64, 'settlementDeadline');
  if (levels !== 101n || max === 0n || max > 32n || tick === 0n || collateral < tick * (levels - 1n)) {
    throw new Error('Invalid pilot bid limits or collateral');
  }
  if (end === 0n || deadline <= end) throw new Error('Invalid auction deadlines');
  return keccak256(abi.encode(
    ['uint256', 'address', 'address', 'address', 'uint256', 'uint256', 'uint256', 'uint16', 'uint32', 'uint256', 'uint64', 'uint64'],
    [chainId, address(c.auction, 'auction'), address(c.seller, 'seller'), address(c.nft, 'nft'),
      unsigned(c.tokenId, 256, 'tokenId'), collateral, tick, levels, max,
      unsigned(c.e3Id, 256, 'e3Id'), end, deadline],
  ));
}

export function encodeEnvelope({ ciphertextHash, inputProof, availabilityProof }) {
  word(ciphertextHash, 'ciphertextHash');
  if (!isHexString(inputProof) || getBytes(inputProof).length === 0) throw new Error('Nonempty input proof required');
  if (!isHexString(availabilityProof) || getBytes(availabilityProof).length === 0) throw new Error('Nonempty DA proof required');
  const encoded = abi.encode(ENVELOPE_TYPES, [1, ciphertextHash, inputProof, availabilityProof]);
  if (getBytes(encoded).length > 16384) throw new Error('Envelope exceeds escrow limit');
  return encoded;
}

export function decodeEnvelope(encoded) {
  if (!isHexString(encoded) || getBytes(encoded).length > 16384) throw new Error('Invalid envelope length');
  const [version, ciphertextHash, inputProof, availabilityProof] = abi.decode(ENVELOPE_TYPES, encoded);
  if (version !== 1n) throw new Error('Unsupported envelope version');
  const result = { ciphertextHash, inputProof, availabilityProof };
  if (encodeEnvelope(result).toLowerCase() !== encoded.toLowerCase()) throw new Error('Noncanonical envelope encoding');
  return result;
}

export function appendInputRoot(previousRoot, index, bidder, envelope, commitment) {
  word(previousRoot, 'previousRoot');
  unsigned(index, 32, 'index');
  decodeEnvelope(envelope);
  const scalar = BigInt(word(commitment, 'commitment'));
  if (scalar >= SCALAR_FIELD) throw new Error('Commitment outside BN254 scalar field');
  return keccak256(abi.encode(['bytes32', 'uint256', 'address', 'bytes32', 'bytes32'],
    [previousRoot, index, address(bidder, 'bidder'), keccak256(envelope), commitment]));
}

export function inputLeaf(context, index, bidder, envelope, commitment) {
  word(context, 'context');
  appendInputRoot(context, index, bidder, envelope, commitment);
  return toBeHex(BigInt(keccak256(abi.encode(['bytes32', 'uint256', 'address', 'bytes32', 'bytes32'],
    [context, index, bidder, keccak256(envelope), commitment]))) % SCALAR_FIELD, 32);
}

export function validateTranscript({ context, expectedInputRoot, expectedCount, inputs }) {
  word(context, 'context');
  const count = unsigned(expectedCount, 32, 'expectedCount');
  if (count === 0n || count > 32n || !Array.isArray(inputs) || inputs.length !== Number(count)) {
    throw new Error('Input count must match the nonempty canonical on-chain set');
  }
  const seen = new Set();
  let root = context;
  const leaves = inputs.map((input, i) => {
    if (unsigned(input.index, 32, 'index') !== BigInt(i)) throw new Error('Reordered or missing input');
    const bidder = address(input.bidder, 'bidder');
    if (seen.has(bidder)) throw new Error('Duplicate bidder');
    seen.add(bidder);
    const envelope = decodeEnvelope(input.envelope);
    if (!isHexString(input.ciphertext) || keccak256(input.ciphertext) !== envelope.ciphertextHash.toLowerCase()) {
      throw new Error('Ciphertext bytes do not match the envelope');
    }
    root = appendInputRoot(root, i, bidder, input.envelope, input.commitment);
    return inputLeaf(context, i, bidder, input.envelope, input.commitment);
  });
  if (root !== word(expectedInputRoot, 'expectedInputRoot')) throw new Error('Input root does not match the on-chain anchor');
  return { inputRoot: root, count: inputs.length, leaves };
}

export function decodeReveal(plaintextOutput, count) {
  const n = unsigned(count, 32, 'count');
  if (n === 0n || n > 32n) throw new Error('Expected 1–32 bids');
  const bytes = getBytes(plaintextOutput);
  if (bytes.length !== REVEAL_COEFFICIENTS * 8) throw new Error('Protocol plaintext must be exactly 400 bytes');
  const values = [];
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let i = 0; i < REVEAL_COEFFICIENTS; ++i) {
    const value = view.getBigUint64(i * 8, true);
    if (i < Number(n)) {
      if (value > 100n) throw new Error('Revealed bid exceeds the collateral range');
      values.push(value);
    } else if (value !== 0n) throw new Error('Unused revealed coefficients must be zero');
  }
  return { ticks: values.map(String), settlementCalldataArgument: abi.encode(['uint256[]'], [values]) };
}

export function secondPrice(ticks) {
  if (!Array.isArray(ticks) || ticks.length === 0 || ticks.length > 32) throw new Error('Expected 1–32 bids');
  let highest = 0n, second = 0n, winnerIndex = null;
  ticks.forEach((value, i) => {
    const bid = unsigned(value, 16, 'bid');
    if (bid > 100n) throw new Error('Bid exceeds collateral');
    if (bid > highest) { second = highest; highest = bid; winnerIndex = i; }
    else if (bid > second) second = bid;
  });
  return { winnerIndex, highestTicks: String(highest), priceTicks: String(second) };
}

export function encodeRevealForFixture(ticks) {
  secondPrice(ticks);
  const bytes = new Uint8Array(400);
  const view = new DataView(bytes.buffer);
  ticks.forEach((tick, i) => view.setBigUint64(i * 8, BigInt(tick), true));
  return hexlify(bytes);
}
