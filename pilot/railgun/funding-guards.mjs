export const MIN_FUNDING_WINDOW_SECONDS = 2n * 60n * 60n;
export const MAX_SHIELD_TOTAL_WEI = 10_000_000_000_000_000n; // 0.01 Sepolia ETH, hard cap including maximum gas.

export function validateFundingWindow({ state, auctionBiddingEnds, programBiddingEnds, timestamp, auctionCollateralWei, plannedCollateralWei }) {
  state = BigInt(state); auctionBiddingEnds = BigInt(auctionBiddingEnds); programBiddingEnds = BigInt(programBiddingEnds); timestamp = BigInt(timestamp);
  if (state !== 0n && state !== 1n) throw new Error('Funding requires an auction in Created or Bidding state');
  if (programBiddingEnds < timestamp + MIN_FUNDING_WINDOW_SECONDS) throw new Error('Funding requires at least 2 hours before the program bidding deadline for scan/PPOI');
  if (state === 1n && auctionBiddingEnds !== programBiddingEnds) throw new Error('Escrow/program bidding deadlines differ');
  if (BigInt(auctionCollateralWei) !== BigInt(plannedCollateralWei)) throw new Error('Planned collateral differs from the deployed auction');
  return { auctionState: Number(state), biddingEnds: String(programBiddingEnds), minimumFundingWindowSeconds: String(MIN_FUNDING_WINDOW_SECONDS), remainingSeconds: String(programBiddingEnds - timestamp) };
}

export function validateShieldSpend({ value, gasLimit, maxFeePerGas }) {
  value = BigInt(value); gasLimit = BigInt(gasLimit); maxFeePerGas = BigInt(maxFeePerGas);
  if (value <= 0n || gasLimit <= 0n || maxFeePerGas <= 0n) throw new Error('Shield value, gas limit and maximum fee must be positive');
  const maximumSpendWei = value + gasLimit * maxFeePerGas;
  if (maximumSpendWei > MAX_SHIELD_TOTAL_WEI) throw new Error('Shield plus maximum gas exceeds the hard 0.01 Sepolia ETH pilot cap');
  return { maximumSpendWei: String(maximumSpendWei), hardCapWei: String(MAX_SHIELD_TOTAL_WEI) };
}
