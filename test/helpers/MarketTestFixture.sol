// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {AdaptiveLMSRPricing} from "../../src/AdaptiveLMSRPricing.sol";
import {LMSRTestConstants} from "./LMSRTestConstants.sol";
import {MarketStackFixture} from "./MarketStackFixture.sol";

/// @title MarketTestFixture
/// @notice Shared setup and helpers for EthosMarket test suites that use the
///         AdaptiveLMSRPricing strategy. Inherit and call `_deployMarketStack()` in setUp().
abstract contract MarketTestFixture is MarketStackFixture {
  // --- Contracts ---

  AdaptiveLMSRPricing public pricing;

  // --- Setup helpers ---

  /// @dev Deploys Whuffie, Market, Pricing, wires InteractionControl, allowlists pricing.
  function _deployMarketStack(uint256 initialSupply) internal {
    _deployStack(initialSupply);
    pricing = new AdaptiveLMSRPricing(LMSRTestConstants.B0, LMSRTestConstants.ALPHA);
    _setPricingAllowed(address(pricing), true);
  }

  // --- Trading helpers ---

  function _createMarketAdmin(string memory userkey, string memory subjectName, uint256 initialBacking)
    internal
    returns (uint256 marketId)
  {
    vm.prank(_admin);
    market.createMarketAdmin(userkey, subjectName, initialBacking, address(pricing));
    marketId = market.marketCount();
  }

  // --- Signature helpers ---

  function _signCreateMarket(
    address caller,
    string memory userkey_,
    string memory subjectName_,
    uint256 initialBacking_,
    address pricingContract_,
    uint256 deadline,
    uint256 randValue
  ) internal view returns (bytes memory) {
    return _signHash(
      keccak256(
        abi.encode(
          address(market),
          block.chainid,
          caller,
          userkey_,
          subjectName_,
          initialBacking_,
          pricingContract_,
          deadline,
          randValue
        )
      )
    );
  }

  function _createMarketWithSig(
    address caller,
    string memory userkey_,
    string memory subjectName_,
    uint256 initialBacking_,
    uint256 randValue
  ) internal returns (uint256 marketId) {
    uint256 deadline = block.timestamp + 1 hours;
    bytes memory sig =
      _signCreateMarket(caller, userkey_, subjectName_, initialBacking_, address(pricing), deadline, randValue);

    vm.prank(caller);
    whuffie.approve(address(market), initialBacking_);
    vm.prank(caller);
    market.createMarket(userkey_, subjectName_, initialBacking_, address(pricing), deadline, randValue, sig);
    marketId = market.marketCount();
  }

  // --- Assertions ---

  function _assertMarketBacked(uint256 marketId) internal view {
    _assertSolvent(marketId);
  }
}
