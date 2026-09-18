// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

/// @notice Thrown when a market does not exist.
/// @param marketId The requested market ID.
error MarketDoesNotExist(uint256 marketId);

/// @notice Thrown when a market already exists for a given userkeyHash.
/// @param userkeyHash The duplicate userkeyHash.
error MarketAlreadyExists(bytes32 userkeyHash);

/// @notice Thrown when a pricing contract is not allowlisted.
/// @param pricingContract The disallowed pricing address.
error PricingNotAllowed(address pricingContract);

/// @notice Thrown when position token sell amount is zero.
error ZeroSellAmount();

/// @notice Thrown when payment is below the minimum threshold.
/// @param provided The amount that was provided.
/// @param minimum The minimum allowed (MIN_BUY).
error AmountBelowMinimum(uint256 provided, uint256 minimum);

/// @notice Thrown when slippage protection triggers.
/// @param actual The actual amount (tokens or credits).
/// @param minimum The minimum the caller required.
error SlippageExceeded(uint256 actual, uint256 minimum);

/// @notice Thrown when the seller has insufficient position tokens.
/// @param have The seller's balance.
/// @param need The amount they tried to sell.
error InsufficientPositionTokens(uint256 have, uint256 need);

/// @notice Thrown when a market is fully paused.
/// @param marketId The paused market.
error MarketPaused(uint256 marketId);

/// @notice Thrown when a market is in sell-only mode and a buy is attempted.
/// @param marketId The sell-only market.
error MarketSellOnly(uint256 marketId);

/// @notice Thrown when a fee exceeds the allowed maximum.
/// @param bps The provided basis points.
/// @param max The maximum allowed.
error FeeBpsTooHigh(uint256 bps, uint256 max);

/// @notice Thrown when initial supply per side is zero.
error ZeroInitialSupply();

/// @notice Thrown at initialize when the token does not expose ERC20Burnable.burn.
/// @param token The ERC-20 token that failed the burn(0) probe.
error TokenNotBurnable(address token);

/// @notice Thrown when a buy yields zero tokens from the bonding curve.
/// @param curveAmount The amount sent to the bonding curve (after protocol fee).
error ZeroTokensMinted(uint256 curveAmount);

/// @notice Thrown when a sell's net credits out would round to zero.
/// @dev Prevents burning position tokens for no payout when max fees + dust curveRevenue collapse the payout.
///      Callers can set `minCreditsOut > 0` for the same guarantee; this is a contract-level floor.
error ZeroPayout();

/// @notice Thrown when openPositionWithPermit's permit did not produce sufficient
///         allowance and the caller has no pre-existing allowance to fall back on.
///         Surfaces the real reason instead of the opaque ERC20InsufficientAllowance
///         that follows from a swallowed permit.
/// @param owner The would-be permit owner.
/// @param required The allowance required to complete the trade.
error InsufficientPermitAllowance(address owner, uint256 required);
