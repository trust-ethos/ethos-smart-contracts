// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {EthosMarket} from "../../src/EthosMarket.sol";
import {EthosWhuffie} from "../../src/EthosWhuffie.sol";
import {PositionToken} from "../../src/PositionToken.sol";
import {ETHOS_MARKET} from "../../src/utils/Constants.sol";
import {InteractionControlFixture} from "./InteractionControlFixture.sol";
import {V2TestFixture} from "./V2TestFixture.sol";

/// @title MarketStackFixture
/// @notice Pricing-agnostic shared setup for EthosMarket test suites. Deploys Whuffie
///         and EthosMarket, wires InteractionControl, and exposes shared test actors
///         and helpers. Concrete fixtures deploy their own pricing contract on top.
/// @dev Inherit this and call `_deployStack(initialSupply)` in setUp(). After that,
///      deploy your pricing contract and call `_setPricingAllowed(pricing, true)`.
abstract contract MarketStackFixture is V2TestFixture, InteractionControlFixture {
  // --- Contracts ---

  EthosWhuffie public whuffie;
  EthosMarket public market;

  // --- Test actors ---

  address public alice = address(0xA11CE1);
  address public bob = address(0xB0B);
  address public carol = address(0xCA201);
  address public feeRecipient = address(0xFEE5);

  // --- Market snapshot ---

  /// @dev Mirrors EthosMarket.MarketState field order for auto-generated getter decoding.
  struct MarketSnapshot {
    bytes32 userkeyHash;
    address trustToken;
    bool exists;
    EthosMarket.PauseState pauseState;
    address distrustToken;
    address pricingContract;
    uint256 trustSupply;
    uint256 distrustSupply;
    uint256 poolBacking;
    uint256 totalVolume;
  }

  // --- Setup ---

  /// @dev Deploys Whuffie + EthosMarket and wires InteractionControl. Pricing is NOT
  ///      configured here — concrete fixtures deploy their own strategy and allowlist
  ///      it afterwards.
  function _deployStack(uint256 initialSupply) internal {
    _deployInfra();

    whuffie = EthosWhuffie(_deployProxy(address(new EthosWhuffie())));
    whuffie.initialize(_owner, address(_cam), _WHUFFIE_TOKEN_CAP);
    vm.prank(_owner);
    whuffie.unlockTransfers();

    market = EthosMarket(_deployProxy(address(new EthosMarket())));
    market.initialize(_defaultInitParams(), address(whuffie), initialSupply);

    _setupInteractionControl(_cam);
    _registerControlledContract(ETHOS_MARKET, address(market));
  }

  /// @dev Allowlists a pricing contract on the market.
  function _setPricingAllowed(address pricing, bool allowed) internal {
    vm.prank(_owner);
    market.setPricingAllowed(pricing, allowed);
  }

  /// @dev Funds each address with `amount` WHUF via owner mint.
  function _fundActors(address[] memory actors, uint256 amount) internal {
    vm.startPrank(_owner);
    for (uint256 i = 0; i < actors.length; i++) {
      whuffie.mint(actors[i], amount);
    }
    vm.stopPrank();
  }

  // --- Market read helpers ---

  function _snapshot(uint256 marketId) internal view returns (MarketSnapshot memory s) {
    (s.userkeyHash, s.trustToken, s.exists, s.pauseState, s.distrustToken, s.pricingContract,,,,) =
      market.markets(marketId);
    (,,,,,, s.trustSupply, s.distrustSupply, s.poolBacking, s.totalVolume) = market.markets(marketId);
  }

  // --- Trading helpers ---

  function _trustToken(uint256 marketId) internal view returns (address) {
    return _snapshot(marketId).trustToken;
  }

  function _distrustToken(uint256 marketId) internal view returns (address) {
    return _snapshot(marketId).distrustToken;
  }

  function _approveAndBuy(address buyer, uint256 marketId, bool isPositive, uint256 amount)
    internal
    returns (uint256 tokensMinted)
  {
    vm.prank(buyer);
    whuffie.approve(address(market), amount);

    address tokenAddr = isPositive ? _trustToken(marketId) : _distrustToken(marketId);
    uint256 balBefore = PositionToken(tokenAddr).balanceOf(buyer);

    vm.prank(buyer);
    market.openPosition(marketId, isPositive, amount, 0);

    tokensMinted = PositionToken(tokenAddr).balanceOf(buyer) - balBefore;
  }

  // --- Assertions ---

  function _assertSolvent(uint256 marketId) internal view {
    MarketSnapshot memory s = _snapshot(marketId);
    assertGe(whuffie.balanceOf(address(market)), s.poolBacking, "solvency violated");
  }

  /// @dev Verifies that the contract balance covers the sum of ALL markets' obligations.
  function _assertGloballySolvent() internal view {
    uint256 totalRequired;
    uint256 count = market.marketCount();
    for (uint256 i = 1; i <= count; i++) {
      MarketSnapshot memory s = _snapshot(i);
      if (!s.exists) continue;
      totalRequired += s.poolBacking;
    }
    assertGe(whuffie.balanceOf(address(market)), totalRequired, "global solvency violated");
  }
}
