// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {Test} from "forge-std/Test.sol";
import {EthosMarket} from "../../src/EthosMarket.sol";
import {EthosWhuffie} from "../../src/EthosWhuffie.sol";
import {PositionToken} from "../../src/PositionToken.sol";
import {IReputationPricing} from "../../src/interfaces/IReputationPricing.sol";

/// @title BaseMarketHandler
/// @notice Abstract handler scaffold for EthosMarket invariant tests. Wraps every action in
///         try/catch so legitimate revert paths don't abort the invariant run; concrete
///         handlers extend this and may add additional actions (e.g. transfers, fee admin).
/// @dev Subclasses pick the trade size cap by overriding `_maxTradeAmount()`. The base
///      ships with `createMarketAction`, `buyAction`, biased-`sellAction`, and
///      `imbalanceBuildAction` — the four selectors common to every invariant suite.
abstract contract BaseMarketHandler is Test {
  EthosMarket public immutable market;
  EthosWhuffie public immutable whuffie;
  IReputationPricing public immutable pricing;
  address public immutable owner;
  address public immutable admin;

  address[] public actors;
  uint256 public constant INITIAL_BACKING = 100e18;

  uint256 public createCalls;
  uint256 public buyCalls;
  uint256 public sellCalls;
  uint256 public imbalanceCalls;

  uint256 public createReverts;
  uint256 public buyReverts;
  uint256 public sellReverts;
  uint256 public imbalanceReverts;

  uint256 private _userkeySalt;

  constructor(
    EthosMarket market_,
    EthosWhuffie whuffie_,
    IReputationPricing pricing_,
    address owner_,
    address admin_,
    address[] memory actors_
  ) {
    market = market_;
    whuffie = whuffie_;
    pricing = pricing_;
    owner = owner_;
    admin = admin_;
    actors = actors_;
  }

  /// @dev Subclass-supplied per-trade cap. Larger caps stress the cost surface tail;
  ///      smaller caps keep numerically thin markets stable under fuzzed sequences.
  function _maxTradeAmount() internal view virtual returns (uint256);

  function _pickActor(uint256 seed) internal view returns (address) {
    return actors[seed % actors.length];
  }

  function _pickMarket(uint256 seed) internal view returns (uint256) {
    uint256 count = market.marketCount();
    if (count == 0) return 0;
    return (seed % count) + 1;
  }

  function createMarketAction(uint256 backingSeed) external {
    uint256 backing = bound(backingSeed, market.MIN_BUY(), INITIAL_BACKING);
    string memory userkey = string(abi.encodePacked("inv-", vm.toString(_userkeySalt++)));
    vm.prank(admin);
    try market.createMarketAdmin(userkey, "subject", backing, address(pricing)) {
      createCalls++;
    } catch {
      createReverts++;
    }
  }

  function buyAction(uint256 actorSeed, uint256 marketSeed, bool isPositive, uint256 amount) external {
    uint256 id = _pickMarket(marketSeed);
    if (id == 0) return;
    address actor = _pickActor(actorSeed);
    amount = bound(amount, market.MIN_BUY(), _maxTradeAmount());
    vm.prank(actor);
    try market.openPosition(id, isPositive, amount, 0) {
      buyCalls++;
    } catch {
      buyReverts++;
    }
  }

  /// @dev Biased-sell: full-balance sells fire ~25 % of the time to drain a side.
  function sellAction(uint256 actorSeed, uint256 marketSeed, bool isPositive, uint256 amountSeed) external {
    uint256 id = _pickMarket(marketSeed);
    if (id == 0) return;
    address actor = _pickActor(actorSeed);
    (, address trustToken,,, address distrustToken,,,,,) = market.markets(id);
    address tokenAddr = isPositive ? trustToken : distrustToken;
    uint256 bal = PositionToken(tokenAddr).balanceOf(actor);
    if (bal == 0) return;
    uint256 amount = (amountSeed % 4 == 0) ? bal : bound(amountSeed, 1, bal);
    vm.prank(actor);
    try market.closePosition(id, isPositive, amount, 0) {
      sellCalls++;
    } catch {
      sellReverts++;
    }
  }

  /// @dev Pushes the trust side hard with a large buy so the cost surface enters its
  ///      asymmetric tail. Always trust-side and biased toward the upper half of the
  ///      trade range — the `isPositive` parameter is ignored to keep the imbalance
  ///      direction consistent across fuzz seeds.
  function imbalanceBuildAction(uint256 actorSeed, uint256 marketSeed, bool, uint256 amountSeed) external {
    uint256 id = _pickMarket(marketSeed);
    if (id == 0) return;
    address actor = _pickActor(actorSeed);
    uint256 maxAmount = _maxTradeAmount();
    uint256 minAmount = maxAmount / 2 < market.MIN_BUY() ? market.MIN_BUY() : maxAmount / 2;
    uint256 amount = bound(amountSeed, minAmount, maxAmount);
    vm.prank(actor);
    try market.openPosition(id, true, amount, 0) {
      imbalanceCalls++;
    } catch {
      imbalanceReverts++;
    }
  }
}
