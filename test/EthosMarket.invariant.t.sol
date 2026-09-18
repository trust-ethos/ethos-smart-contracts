// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {StdInvariant} from "forge-std/StdInvariant.sol";
import {EthosMarket} from "../src/EthosMarket.sol";
import {EthosWhuffie} from "../src/EthosWhuffie.sol";
import {PositionToken} from "../src/PositionToken.sol";
import {IReputationPricing} from "../src/interfaces/IReputationPricing.sol";
import {BaseMarketHandler} from "./helpers/BaseMarketHandler.sol";
import {MarketTestFixture} from "./helpers/MarketTestFixture.sol";

/// @dev Bounded handler that translates random fuzzer inputs into legal calls
///      against the EthosMarket/Whuffie stack. Extends `BaseMarketHandler` for the
///      core action set (create / buy / biased-sell / imbalance-build) and adds
///      transfer + per-action fee/pause admin actions on top.
contract MarketHandler is BaseMarketHandler {
  uint256 public constant MAX_TRADE = 1_000e18;

  uint256 public transferCalls;
  uint256 public feeCalls;
  uint256 public pauseCalls;

  constructor(
    EthosMarket market_,
    EthosWhuffie whuffie_,
    address pricing_,
    address owner_,
    address admin_,
    address[] memory actors_
  ) BaseMarketHandler(market_, whuffie_, IReputationPricing(pricing_), owner_, admin_, actors_) {}

  function _maxTradeAmount() internal pure override returns (uint256) {
    return MAX_TRADE;
  }

  function transferAction(uint256 fromSeed, uint256 toSeed, uint256 marketSeed, bool isPositive, uint256 amountSeed)
    external
  {
    uint256 id = _pickMarket(marketSeed);
    if (id == 0) return;
    address from = _pickActor(fromSeed);
    address to = _pickActor(toSeed);
    if (from == to) return;

    (, address trustToken,,, address distrustToken,,,,,) = market.markets(id);
    address tokenAddr = isPositive ? trustToken : distrustToken;
    uint256 bal = PositionToken(tokenAddr).balanceOf(from);
    if (bal == 0) return;

    uint256 amount = bound(amountSeed, 1, bal);
    vm.prank(from);
    try PositionToken(tokenAddr).transfer(to, amount) returns (bool) {
      transferCalls++;
    } catch {}
  }

  function setExitFeeAction(uint256 bpsSeed) external {
    uint256 bps = bound(bpsSeed, 0, market.MAX_PROTOCOL_FEE_BPS());
    vm.prank(owner);
    try market.setExitFeeBasisPoints(bps) {
      feeCalls++;
    } catch {}
  }

  function setEntryFeeAction(uint256 bpsSeed) external {
    uint256 bps = bound(bpsSeed, 0, market.MAX_PROTOCOL_FEE_BPS());
    vm.prank(owner);
    try market.setEntryFeeBasisPoints(bps) {
      feeCalls++;
    } catch {}
  }

  function setPauseStateAction(uint256 marketSeed, uint256 stateSeed) external {
    uint256 id = _pickMarket(marketSeed);
    if (id == 0) return;
    EthosMarket.PauseState state = EthosMarket.PauseState(stateSeed % 3);
    vm.prank(admin);
    try market.setMarketPauseState(id, state) {
      pauseCalls++;
    } catch {}
  }
}

/// @notice Solvency invariant suite for EthosMarket. Defense for audit
///         finding M-1: the contract balance always covers the
///         sum of every market's obligations across any reachable sequence
///         of trades.
contract EthosMarketInvariantTest is StdInvariant, MarketTestFixture {
  uint256 public constant INITIAL_SUPPLY = 100e18;
  uint256 public constant ACTOR_BALANCE = 10_000_000e18;

  MarketHandler internal handler;

  function setUp() public {
    _deployMarketStack(INITIAL_SUPPLY);

    address[] memory actors = new address[](4);
    actors[0] = alice;
    actors[1] = bob;
    actors[2] = carol;
    // _admin joins the actor pool so both the setUp seeds and handler-initiated
    // createMarketAdmin calls share the same funded+approved address.
    actors[3] = _admin;
    _fundActors(actors, ACTOR_BALANCE);

    // Blanket approval — the handler drains balances across many calls.
    for (uint256 i = 0; i < actors.length; i++) {
      vm.prank(actors[i]);
      whuffie.approve(address(market), type(uint256).max);
    }

    // Seed two markets so cross-market actions fire immediately.
    _createMarketAdmin("address:0xSeedAlice", "SeedAlice", 100e18);
    _createMarketAdmin("address:0xSeedBob", "SeedBob", 100e18);

    // Only the first three actors trade in the handler — _admin is solely for
    // market creation, which transfers from msg.sender, not from trading actors.
    address[] memory traders = new address[](3);
    traders[0] = alice;
    traders[1] = bob;
    traders[2] = carol;
    handler = new MarketHandler(market, whuffie, address(pricing), _owner, _admin, traders);

    bytes4[] memory selectors = new bytes4[](8);
    selectors[0] = handler.createMarketAction.selector;
    selectors[1] = handler.buyAction.selector;
    selectors[2] = handler.sellAction.selector;
    selectors[3] = handler.transferAction.selector;
    selectors[4] = handler.setExitFeeAction.selector;
    selectors[5] = handler.setEntryFeeAction.selector;
    selectors[6] = handler.setPauseStateAction.selector;
    selectors[7] = handler.imbalanceBuildAction.selector;

    targetContract(address(handler));
    targetSelector(StdInvariant.FuzzSelector({addr: address(handler), selectors: selectors}));
  }

  /// @dev THE invariant. The market contract must always hold at least as much
  ///      Whuffie as it owes across every market: pool backing.
  function invariant_solvency_balanceCoversAllObligations() public view {
    uint256 balance = whuffie.balanceOf(address(market));
    uint256 totalRequired;
    uint256 count = market.marketCount();
    for (uint256 i = 1; i <= count; i++) {
      MarketSnapshot memory s = _snapshot(i);
      if (!s.exists) continue;
      totalRequired += s.poolBacking;
    }
    assertGe(balance, totalRequired, "market solvency violated");
  }

  /// @dev Market IDs are append-only: `marketCount` never decreases.
  uint256 internal _lastSeenMarketCount;

  function invariant_marketCountMonotonic() public {
    uint256 current = market.marketCount();
    assertGe(current, _lastSeenMarketCount, "marketCount must be monotonically increasing");
    _lastSeenMarketCount = current;
  }
}
