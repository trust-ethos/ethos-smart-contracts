// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

/// @notice Thrown when a sell is attempted with insufficient supply.
/// @param supply The current supply.
/// @param amount The amount attempted to sell.
error InsufficientSupplyToSell(uint256 supply, uint256 amount);

/// @notice Thrown when an LMSR strategy is constructed with a zero or out-of-range base
///         liquidity parameter (`b0`).
error InvalidBaseLiquidityParameter();

/// @notice Thrown when an LMSR strategy is constructed with an out-of-range adaptive
///         scaling parameter (`alpha`).
/// @dev Low `alpha` can exceed PRBMath's safe `exp` domain; high `alpha` can
///      overflow `b0 + alpha·sum/WAD` over the capped quote domain.
error InvalidAlphaParameter();

/// @notice Thrown when |trustSupply - distrustSupply| / b exceeds the safe domain
///         where exp/ln math is well-defined under PRBMath SD59x18.
/// @param absDiff The absolute supply difference (WAD-scaled).
/// @param b The current liquidity parameter (WAD-scaled).
error SuppliesExceedSafeLimit(uint256 absDiff, uint256 b);

/// @notice Thrown when Adaptive LMSR supplies exceed the proven arithmetic domain.
/// @param trustSupply Trust-side supply passed to the pricing strategy.
/// @param distrustSupply Distrust-side supply passed to the pricing strategy.
/// @param maxSupplySum Maximum supported trust+distrust supply sum.
error SuppliesExceedArithmeticLimit(uint256 trustSupply, uint256 distrustSupply, uint256 maxSupplySum);

/// @notice Thrown when getTokensForBudget cannot find an upper bound for the binary
///         search before hitting the strategy's per-trade token cap. Indicates the
///         caller is attempting to spend more than the strategy supports in a single trade.
/// @param budget The budget that could not be bracketed.
error BudgetUpperBoundNotFound(uint256 budget);
