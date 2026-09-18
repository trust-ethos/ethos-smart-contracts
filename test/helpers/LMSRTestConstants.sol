// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

/// @title LMSRTestConstants
/// @notice Centralised constants for AdaptiveLMSR test suites. Mirrors the production deploy
///         defaults so unit and integration tests share the same `b0` and `alpha` values.
library LMSRTestConstants {
  /// @dev Production-default base liquidity (100 WAD-scaled tokens).
  uint256 internal constant B0 = 100e18;

  /// @dev Production-default adaptive scaling coefficient (0.1 WAD-scaled).
  uint256 internal constant ALPHA = 0.1e18;
}
