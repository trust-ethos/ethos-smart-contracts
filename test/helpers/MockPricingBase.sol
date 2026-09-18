// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {IReputationPricing} from "../../src/interfaces/IReputationPricing.sol";
import {HALF_WAD} from "../../src/utils/MathConstants.sol";

/// @title MockPricingBase
/// @notice Abstract scaffold for `IReputationPricing` mocks used by EthosMarket tests.
/// @dev Concrete mocks override only the hook(s) they need. Defaults are sensible
///      for a "healthy linear" curve so that tests focused on a single behaviour
///      (e.g. `getPrice` reverts) don't have to re-implement every method.
abstract contract MockPricingBase is IReputationPricing {
  /// @inheritdoc IReputationPricing
  function getPrice(uint256, uint256, bool) external view virtual override returns (uint256) {
    return HALF_WAD;
  }

  /// @inheritdoc IReputationPricing
  function getCost(uint256, uint256, bool, bool, uint256 amount) external view virtual override returns (uint256) {
    return amount;
  }

  /// @inheritdoc IReputationPricing
  function getSignal(uint256, uint256) external view virtual override returns (uint256) {
    return HALF_WAD;
  }

  /// @inheritdoc IReputationPricing
  function getTokensForBudget(uint256, uint256, bool, uint256 budget) external view virtual override returns (uint256) {
    return budget;
  }
}
