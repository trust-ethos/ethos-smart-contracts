// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {StdInvariant} from "forge-std/StdInvariant.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {AdaptiveLMSRPricing} from "../src/AdaptiveLMSRPricing.sol";
import {EthosMarket} from "../src/EthosMarket.sol";
import {EthosWhuffie} from "../src/EthosWhuffie.sol";
import {IReputationPricing} from "../src/interfaces/IReputationPricing.sol";
import {PositionToken} from "../src/PositionToken.sol";
import {BPS_DENOMINATOR} from "../src/utils/MathConstants.sol";
import {BaseMarketHandler} from "./helpers/BaseMarketHandler.sol";
import {LMSRTestConstants} from "./helpers/LMSRTestConstants.sol";
import {MarketStackFixture} from "./helpers/MarketStackFixture.sol";

/// @notice Adaptive LMSR variant of the EthosMarket invariant suite. Mirrors
///         EthosMarket.invariant.t.sol's solvency invariant against the joint-cost
///         strategy. Trade sizes are bounded by `MAX_TRADE` and stay well below
///         `MAX_TOKENS_PER_TRADE` (1e33) — large enough to push the cost surface
///         tail under fuzzed sequences without crossing the doubling-search cap.
contract LMSRMarketHandler is BaseMarketHandler {
  /// @dev Sized to stress the cost surface tail under fuzzed sequences while staying
  ///      well below `MAX_TOKENS_PER_TRADE = 1e33`. ~1e26 = 1e8 WAD-scaled tokens —
  ///      orders of magnitude beyond any realistic trade.
  uint256 public constant MAX_TRADE = 1e26;
  uint256 private constant PAUSE_STATE_COUNT = uint256(type(EthosMarket.PauseState).max) + 1;

  uint256 public transferCalls;
  uint256 public transferReverts;
  uint256 public feeCalls;
  uint256 public feeReverts;
  uint256 public pauseCalls;
  uint256 public pauseReverts;

  constructor(
    EthosMarket market_,
    EthosWhuffie whuffie_,
    AdaptiveLMSRPricing pricing_,
    address owner_,
    address admin_,
    address[] memory actors_
  ) BaseMarketHandler(market_, whuffie_, IReputationPricing(address(pricing_)), owner_, admin_, actors_) {}

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
    } catch {
      transferReverts++;
    }
  }

  function setExitFeeAction(uint256 bpsSeed) external {
    uint256 bps = bound(bpsSeed, 0, market.MAX_PROTOCOL_FEE_BPS());
    vm.prank(owner);
    try market.setExitFeeBasisPoints(bps) {
      feeCalls++;
    } catch {
      feeReverts++;
    }
  }

  function setEntryFeeAction(uint256 bpsSeed) external {
    uint256 bps = bound(bpsSeed, 0, market.MAX_PROTOCOL_FEE_BPS());
    vm.prank(owner);
    try market.setEntryFeeBasisPoints(bps) {
      feeCalls++;
    } catch {
      feeReverts++;
    }
  }

  function setPauseStateAction(uint256 marketSeed, uint256 stateSeed) external {
    uint256 id = _pickMarket(marketSeed);
    if (id == 0) return;
    EthosMarket.PauseState state = EthosMarket.PauseState(stateSeed % PAUSE_STATE_COUNT);
    vm.prank(admin);
    try market.setMarketPauseState(id, state) {
      pauseCalls++;
    } catch {
      pauseReverts++;
    }
  }
}

contract LMSRMarketSurplusHandler is LMSRMarketHandler {
  uint256 public directWhuffieTransferCalls;
  uint256 public directWhuffieTransferReverts;
  uint256 public directWhuffieTransferred;

  constructor(
    EthosMarket market_,
    EthosWhuffie whuffie_,
    AdaptiveLMSRPricing pricing_,
    address owner_,
    address admin_,
    address[] memory actors_
  ) LMSRMarketHandler(market_, whuffie_, pricing_, owner_, admin_, actors_) {}

  function directWhuffieTransferAction(uint256 actorSeed, uint256 amountSeed) external {
    address actor = _pickActor(actorSeed);
    uint256 balance = whuffie.balanceOf(actor);
    if (balance == 0) return;

    uint256 amount = bound(amountSeed, 1, balance);
    vm.prank(actor);
    try whuffie.transfer(address(market), amount) returns (bool ok) {
      if (!ok) return;
      directWhuffieTransferCalls++;
      directWhuffieTransferred += amount;
    } catch {
      directWhuffieTransferReverts++;
    }
  }
}

contract EthosMarketAdaptiveLMSRInvariantTest is StdInvariant, MarketStackFixture {
  uint256 public constant B0 = LMSRTestConstants.B0;
  uint256 public constant ALPHA = LMSRTestConstants.ALPHA;
  uint256 public constant INITIAL_SUPPLY = 100e18;
  // Scaled to cover several worst-case `MAX_TRADE` buys per actor without drying out.
  uint256 public constant ACTOR_BALANCE = 1e30;

  struct LiquidationCursor {
    uint256 trustSupply;
    uint256 distrustSupply;
    uint256 exitFeeBps;
  }

  AdaptiveLMSRPricing internal pricing;

  LMSRMarketHandler internal handler;
  address[] internal traderActors;
  uint256 internal initialTraderWhuffie;

  function setUp() public {
    _deployStack(INITIAL_SUPPLY);

    pricing = new AdaptiveLMSRPricing(B0, ALPHA);
    _setPricingAllowed(address(pricing), true);

    address[] memory actors = new address[](4);
    actors[0] = alice;
    actors[1] = bob;
    actors[2] = carol;
    actors[3] = _admin;

    for (uint256 i; i < actors.length; i++) {
      vm.prank(_owner);
      whuffie.mint(actors[i], ACTOR_BALANCE);
      vm.prank(actors[i]);
      whuffie.approve(address(market), type(uint256).max);
    }

    // Seed two markets so cross-market actions fire immediately.
    vm.prank(_admin);
    market.createMarketAdmin("address:0xLmsrSeedAlice", "lmsr-seed-alice", 100e18, address(pricing));
    vm.prank(_admin);
    market.createMarketAdmin("address:0xLmsrSeedBob", "lmsr-seed-bob", 100e18, address(pricing));

    address[] memory traders = new address[](3);
    traders[0] = alice;
    traders[1] = bob;
    traders[2] = carol;
    traderActors = traders;
    initialTraderWhuffie = _sumTraderWhuffieBalances();
    handler = new LMSRMarketHandler(market, whuffie, pricing, _owner, _admin, traders);

    bytes4[] memory selectors = new bytes4[](8);
    selectors[0] = handler.createMarketAction.selector;
    selectors[1] = handler.buyAction.selector;
    selectors[2] = handler.sellAction.selector;
    selectors[3] = handler.imbalanceBuildAction.selector;
    selectors[4] = handler.transferAction.selector;
    selectors[5] = handler.setExitFeeAction.selector;
    selectors[6] = handler.setEntryFeeAction.selector;
    selectors[7] = handler.setPauseStateAction.selector;

    targetContract(address(handler));
    targetSelector(StdInvariant.FuzzSelector({addr: address(handler), selectors: selectors}));
  }

  /// @dev Solvency invariant under AdaptiveLMSR. The contract's whuffie balance
  ///      must always cover the sum of every market's pool backing.
  function invariant_solvency_balanceCoversAllObligations_lmsr() public view {
    _assertGloballySolvent();
  }

  /// @dev This handler excludes direct Whuffie transfers, so balance must equal backing.
  function invariant_marketBalanceEqualsPoolBacking_lmsr() public view {
    uint256 totalBacking;
    uint256 count = market.marketCount();
    for (uint256 i = 1; i <= count; ++i) {
      MarketSnapshot memory s = _snapshot(i);
      if (!s.exists) continue;
      totalBacking += s.poolBacking;
    }

    assertEq(whuffie.balanceOf(address(market)), totalBacking, "market balance/accounting drift");
  }

  function invariant_positionTokenSupplyMatchesMarketAccounting_lmsr() public view {
    uint256 count = market.marketCount();
    for (uint256 i = 1; i <= count; ++i) {
      MarketSnapshot memory s = _snapshot(i);
      if (!s.exists) continue;

      assertEq(PositionToken(s.trustToken).totalSupply(), s.trustSupply, "trust supply accounting mismatch");
      assertEq(PositionToken(s.distrustToken).totalSupply(), s.distrustSupply, "distrust supply accounting mismatch");
    }
  }

  uint256 internal _lastSeenMarketCount;
  mapping(uint256 marketId => uint256 totalVolume) internal _lastSeenTotalVolume;

  function invariant_marketCountMonotonic_lmsr() public {
    uint256 current = market.marketCount();
    assertGe(current, _lastSeenMarketCount, "marketCount must be monotonically increasing");
    _lastSeenMarketCount = current;
  }

  function invariant_totalVolumeMonotonicAndCoversBacking_lmsr() public {
    uint256 count = market.marketCount();
    for (uint256 i = 1; i <= count; ++i) {
      MarketSnapshot memory s = _snapshot(i);
      if (!s.exists) continue;

      assertGe(s.totalVolume, _lastSeenTotalVolume[i], "totalVolume must be monotonically increasing");
      assertGe(s.totalVolume, s.poolBacking, "totalVolume must cover current backing");
      _lastSeenTotalVolume[i] = s.totalVolume;
    }
  }

  function invariant_traderLiquidationValueCannotExceedStartingWhuffie_lmsr() public view {
    uint256 currentWhuffie = _sumTraderWhuffieBalances();
    (uint256 liquidationValue, uint256 strandedDust) = _deterministicTraderLiquidationValue();
    uint256 executableWealth = currentWhuffie + liquidationValue;
    if (executableWealth <= initialTraderWhuffie) return;

    uint256 excess = executableWealth - initialTraderWhuffie;
    assertLe(excess, _strandedDustAllowance(strandedDust), "open inventory wealth exceeds stranded dust bound");
  }

  function _sumTraderWhuffieBalances() internal view returns (uint256 total) {
    for (uint256 i; i < traderActors.length; ++i) {
      total += whuffie.balanceOf(traderActors[i]);
    }
  }

  function _deterministicTraderLiquidationValue() internal view returns (uint256 total, uint256 strandedDust) {
    uint256 count = market.marketCount();
    LiquidationCursor memory cursor;
    cursor.exitFeeBps = market.exitFeeBps();

    for (uint256 marketId = 1; marketId <= count; ++marketId) {
      MarketSnapshot memory s = _snapshot(marketId);
      if (!s.exists || s.pauseState == EthosMarket.PauseState.PAUSED) continue;

      cursor.trustSupply = s.trustSupply;
      cursor.distrustSupply = s.distrustSupply;

      uint256 actorCount = traderActors.length;
      uint256[] memory trustBalances = new uint256[](actorCount);
      uint256[] memory distrustBalances = new uint256[](actorCount);
      for (uint256 actorIndex; actorIndex < actorCount; ++actorIndex) {
        address actor = traderActors[actorIndex];
        trustBalances[actorIndex] = PositionToken(s.trustToken).balanceOf(actor);
        distrustBalances[actorIndex] = PositionToken(s.distrustToken).balanceOf(actor);
      }

      bool progressed = true;
      while (progressed) {
        progressed = false;
        for (uint256 actorIndex; actorIndex < actorCount; ++actorIndex) {
          uint256 trustBalance = trustBalances[actorIndex];
          if (trustBalance > 0) {
            uint256 trustPayout = _netExecutableSellValue(cursor, true, trustBalance);
            if (trustPayout > 0) {
              total += trustPayout;
              cursor.trustSupply -= trustBalance;
              trustBalances[actorIndex] = 0;
              progressed = true;
            }
          }

          uint256 distrustBalance = distrustBalances[actorIndex];
          if (distrustBalance > 0) {
            uint256 distrustPayout = _netExecutableSellValue(cursor, false, distrustBalance);
            if (distrustPayout > 0) {
              total += distrustPayout;
              cursor.distrustSupply -= distrustBalance;
              distrustBalances[actorIndex] = 0;
              progressed = true;
            }
          }
        }
      }

      for (uint256 actorIndex; actorIndex < actorCount; ++actorIndex) {
        strandedDust += trustBalances[actorIndex] + distrustBalances[actorIndex];
      }
    }
  }

  function _strandedDustAllowance(uint256 strandedDust) internal pure returns (uint256) {
    // Bound wealth by dust collateral, not the saturated-tail mark price.
    return strandedDust * 2;
  }

  function _netExecutableSellValue(LiquidationCursor memory cursor, bool isPositive, uint256 amount)
    internal
    view
    returns (uint256)
  {
    uint256 curveRevenue = pricing.getCost(cursor.trustSupply, cursor.distrustSupply, isPositive, false, amount);
    uint256 exitFee = Math.mulDiv(curveRevenue, cursor.exitFeeBps, BPS_DENOMINATOR, Math.Rounding.Ceil);
    return curveRevenue - exitFee;
  }
}

contract EthosMarketAdaptiveLMSRSurplusInvariantTest is StdInvariant, MarketStackFixture {
  uint256 public constant B0 = LMSRTestConstants.B0;
  uint256 public constant ALPHA = LMSRTestConstants.ALPHA;
  uint256 public constant INITIAL_SUPPLY = 100e18;
  uint256 public constant ACTOR_BALANCE = 1e30;

  AdaptiveLMSRPricing internal pricing;
  LMSRMarketSurplusHandler internal handler;

  function setUp() public {
    _deployStack(INITIAL_SUPPLY);

    pricing = new AdaptiveLMSRPricing(B0, ALPHA);
    _setPricingAllowed(address(pricing), true);

    address[] memory actors = new address[](4);
    actors[0] = alice;
    actors[1] = bob;
    actors[2] = carol;
    actors[3] = _admin;

    for (uint256 i; i < actors.length; i++) {
      vm.prank(_owner);
      whuffie.mint(actors[i], ACTOR_BALANCE);
      vm.prank(actors[i]);
      whuffie.approve(address(market), type(uint256).max);
    }

    vm.prank(_admin);
    market.createMarketAdmin("address:0xLmsrSurplusSeedAlice", "lmsr-surplus-seed-alice", 100e18, address(pricing));
    vm.prank(_admin);
    market.createMarketAdmin("address:0xLmsrSurplusSeedBob", "lmsr-surplus-seed-bob", 100e18, address(pricing));

    address[] memory traders = new address[](3);
    traders[0] = alice;
    traders[1] = bob;
    traders[2] = carol;
    handler = new LMSRMarketSurplusHandler(market, whuffie, pricing, _owner, _admin, traders);

    bytes4[] memory selectors = new bytes4[](9);
    selectors[0] = handler.createMarketAction.selector;
    selectors[1] = handler.buyAction.selector;
    selectors[2] = handler.sellAction.selector;
    selectors[3] = handler.imbalanceBuildAction.selector;
    selectors[4] = handler.transferAction.selector;
    selectors[5] = handler.setExitFeeAction.selector;
    selectors[6] = handler.setEntryFeeAction.selector;
    selectors[7] = handler.setPauseStateAction.selector;
    selectors[8] = handler.directWhuffieTransferAction.selector;

    targetContract(address(handler));
    targetSelector(StdInvariant.FuzzSelector({addr: address(handler), selectors: selectors}));
  }

  function invariant_surplusBalanceEqualsDirectTransfers_lmsr() public view {
    uint256 totalBacking;
    uint256 count = market.marketCount();
    for (uint256 i = 1; i <= count; ++i) {
      MarketSnapshot memory s = _snapshot(i);
      if (!s.exists) continue;
      totalBacking += s.poolBacking;
    }

    uint256 balance = whuffie.balanceOf(address(market));
    assertGe(balance, totalBacking, "market balance must cover backing plus surplus");
    assertEq(balance - totalBacking, handler.directWhuffieTransferred(), "surplus should equal direct transfers");
  }

  function invariant_positionTokenSupplyMatchesMarketAccounting_withSurplus_lmsr() public view {
    uint256 count = market.marketCount();
    for (uint256 i = 1; i <= count; ++i) {
      MarketSnapshot memory s = _snapshot(i);
      if (!s.exists) continue;

      assertEq(PositionToken(s.trustToken).totalSupply(), s.trustSupply, "trust supply accounting mismatch");
      assertEq(PositionToken(s.distrustToken).totalSupply(), s.distrustSupply, "distrust supply accounting mismatch");
    }
  }
}
