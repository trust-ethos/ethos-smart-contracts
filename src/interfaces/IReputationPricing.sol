// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

/**
 * @title IReputationPricing
 * @author Ethos Network
 * @notice Interface for pricing strategies used by Ethos reputation markets.
 * @dev Implementations define a cost surface over both sides of a market and derive
 *      spot prices, buy/sell costs, a trust signal, and a budget→tokens inverse from it.
 *
 *      Argument order convention: every priced function receives `trustSupply` first
 *      and `distrustSupply` second, regardless of which side the caller is operating on.
 *      `isPositive` selects the side. Joint cost functions (e.g. LMSR) need both supplies;
 *      independent-per-side curves (e.g. linear bonding curves) ignore the opposing one.
 *      Callers MUST NOT mirror "self-side first" patterns — that would silently invert
 *      the cost surface for the distrust side under joint strategies.
 *
 *      All supplies and amounts are WAD-scaled (1e18 = 1 token).
 * @custom:security-contact security@ethos.network
 */
interface IReputationPricing {
  /// @notice Human-readable name of the pricing strategy (e.g. "AdaptiveLMSR").
  /// @return The strategy name.
  function name() external pure returns (string memory);

  /// @notice Spot price for the `isPositive` side at state `(trustSupply, distrustSupply)`.
  /// @param trustSupply Trust-side token supply (WAD-scaled, 18 decimals).
  /// @param distrustSupply Distrust-side token supply (WAD-scaled, 18 decimals).
  /// @param isPositive True for the trust side, false for the distrust side.
  /// @return Spot price in the market's base currency (WAD-scaled).
  function getPrice(uint256 trustSupply, uint256 distrustSupply, bool isPositive) external view returns (uint256);

  /// @notice Cost to buy or sell `amount` tokens on the `isPositive` side at state
  ///         `(trustSupply, distrustSupply)`.
  /// @param trustSupply Trust-side token supply (WAD-scaled, 18 decimals).
  /// @param distrustSupply Distrust-side token supply (WAD-scaled, 18 decimals).
  /// @param isPositive True for the trust side, false for the distrust side.
  /// @param isBuy True for a buy, false for a sell.
  /// @param amount Number of tokens to buy or sell (WAD-scaled).
  /// @return Total cost in the market's base currency (WAD-scaled).
  function getCost(uint256 trustSupply, uint256 distrustSupply, bool isPositive, bool isBuy, uint256 amount)
    external
    view
    returns (uint256);

  /// @notice Trust signal derived from opposing supplies, returned as a WAD fraction.
  /// @dev Returns 5e17 (50 %) when both supplies are zero. Declared `view` rather than
  ///      `pure` so joint-cost strategies can read immutable parameters; pure
  ///      implementations remain valid because `pure` satisfies the `view` contract.
  /// @param trustSupply Trust-side token supply (WAD-scaled, 18 decimals).
  /// @param distrustSupply Distrust-side token supply (WAD-scaled, 18 decimals).
  /// @return Signal in [0, 1e18] where 1e18 = 100 % trust.
  function getSignal(uint256 trustSupply, uint256 distrustSupply) external view returns (uint256);

  /// @notice Maximum whole tokens purchasable with `budget` from state
  ///         `(trustSupply, distrustSupply)` for the `isPositive` side. Rounds down.
  /// @param trustSupply Trust-side token supply (WAD-scaled, 18 decimals).
  /// @param distrustSupply Distrust-side token supply (WAD-scaled, 18 decimals).
  /// @param isPositive True for the trust side, false for the distrust side.
  /// @param budget Amount of base currency available (WAD-scaled).
  /// @return Number of tokens that can be bought (WAD-scaled).
  function getTokensForBudget(uint256 trustSupply, uint256 distrustSupply, bool isPositive, uint256 budget)
    external
    view
    returns (uint256);
}
