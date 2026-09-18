// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {Test} from "forge-std/Test.sol";
import {AdaptiveLMSRPricing} from "../src/AdaptiveLMSRPricing.sol";
import {
  BudgetUpperBoundNotFound,
  InsufficientSupplyToSell,
  InvalidAlphaParameter,
  InvalidBaseLiquidityParameter,
  SuppliesExceedArithmeticLimit,
  SuppliesExceedSafeLimit
} from "../src/errors/PricingErrors.sol";
import {HALF_WAD, WAD} from "../src/utils/MathConstants.sol";
import {LMSRTestConstants} from "./helpers/LMSRTestConstants.sol";

contract AdaptiveLMSRPricingTest is Test {
  uint256 constant B0 = LMSRTestConstants.B0;
  uint256 constant ALPHA = LMSRTestConstants.ALPHA;

  AdaptiveLMSRPricing pricing;

  function setUp() public {
    pricing = new AdaptiveLMSRPricing(B0, ALPHA);
  }

  // --- Constructor ---

  function test_constructor_reverts_on_zero_b0() public {
    vm.expectRevert(InvalidBaseLiquidityParameter.selector);
    new AdaptiveLMSRPricing(0, ALPHA);
  }

  /// @notice b0 above MAX_B0 reverts. Guards against deploy-time misconfiguration.
  function test_constructor_reverts_on_b0_above_max() public {
    uint256 maxB0 = pricing.MAX_B0();
    vm.expectRevert(InvalidBaseLiquidityParameter.selector);
    new AdaptiveLMSRPricing(maxB0 + 1, ALPHA);
  }

  function test_constructor_reverts_on_zero_alpha() public {
    vm.expectRevert(InvalidAlphaParameter.selector);
    new AdaptiveLMSRPricing(B0, 0);
  }

  function test_constructor_reverts_on_alpha_below_floor() public {
    uint256 alphaBelowFloor = pricing.MIN_ALPHA() - 1;
    vm.expectRevert(InvalidAlphaParameter.selector);
    new AdaptiveLMSRPricing(B0, alphaBelowFloor);
  }

  function test_constructor_reverts_on_truncated_alpha_floor() public {
    vm.expectRevert(InvalidAlphaParameter.selector);
    new AdaptiveLMSRPricing(B0, WAD / 41);
  }

  function test_constructor_reverts_on_alpha_above_max() public {
    uint256 alphaAboveMax = pricing.MAX_ALPHA() + 1;
    vm.expectRevert(InvalidAlphaParameter.selector);
    new AdaptiveLMSRPricing(B0, alphaAboveMax);
  }

  function test_constructor_accepts_alpha_at_max() public {
    uint256 maxAlpha = pricing.MAX_ALPHA();
    AdaptiveLMSRPricing p = new AdaptiveLMSRPricing(B0, maxAlpha);
    assertEq(p.alpha(), maxAlpha);
  }

  function test_maxAlpha_keepsBArithmeticSafeForCappedBuyAtCappedSupplies() public {
    AdaptiveLMSRPricing p = new AdaptiveLMSRPricing(pricing.MAX_B0(), pricing.MAX_ALPHA());
    uint256 cap = p.MAX_TOKENS_PER_TRADE();

    uint256 cost = p.getCost(cap, cap, true, true, cap);

    assertGt(cost, 0);
  }

  function test_getPrice_revertsWithArithmeticLimit_aboveSafeSupplySum() public {
    uint256 maxSupply = pricing.MAX_SAFE_SUPPLY_SUM();

    vm.expectRevert(abi.encodeWithSelector(SuppliesExceedArithmeticLimit.selector, maxSupply + 1, 0, maxSupply));
    pricing.getPrice(maxSupply + 1, 0, true);
  }

  function test_getPrice_revertsWithArithmeticLimit_onSupplySumOverflow() public {
    uint256 maxSupply = pricing.MAX_SAFE_SUPPLY_SUM();

    vm.expectRevert(abi.encodeWithSelector(SuppliesExceedArithmeticLimit.selector, type(uint256).max, 1, maxSupply));
    pricing.getPrice(type(uint256).max, 1, true);
  }

  function test_getCost_allowsSellAtSafeSupplySumButBlocksBuyBeyondSafeSupplySum() public {
    uint256 maxSupply = pricing.MAX_SAFE_SUPPLY_SUM();

    uint256 sellRevenue = pricing.getCost(maxSupply, 0, true, false, WAD);
    assertGt(sellRevenue, 0);

    vm.expectRevert(abi.encodeWithSelector(SuppliesExceedArithmeticLimit.selector, maxSupply + WAD, 0, maxSupply));
    pricing.getCost(maxSupply, 0, true, true, WAD);
  }

  function test_constructor_accepts_alpha_at_ceil_floor() public {
    uint256 alphaFloor = pricing.MIN_ALPHA();
    AdaptiveLMSRPricing p = new AdaptiveLMSRPricing(B0, alphaFloor);
    assertEq(p.alpha(), alphaFloor);
  }

  function test_constructor_sets_immutables() public view {
    assertEq(pricing.b0(), B0);
    assertEq(pricing.alpha(), ALPHA);
  }

  // --- Reference vectors ---

  /// @notice Independent Decimal oracle vectors for production parameters.
  function test_referenceVectors_independentDecimalOracle() public view {
    uint256 tolerance = 1e9;

    assertApproxEqAbs(
      pricing.getPrice(250 * WAD, 100 * WAD, true), 752_336_198_860_928_375, tolerance, "trust-dominant trust price"
    );
    assertApproxEqAbs(pricing.getPrice(0, 100 * WAD, true), 287_185_901_382_502_632, tolerance, "depleted trust price");
    assertApproxEqAbs(pricing.getPrice(100 * WAD, 0, true), 712_814_098_617_497_368, tolerance, "dominant trust price");

    assertApproxEqAbs(
      pricing.getCost(100 * WAD, 100 * WAD, true, true, 10 * WAD),
      5_796_423_579_380_039_672,
      tolerance,
      "neutral trust buy cost"
    );
    assertApproxEqAbs(
      pricing.getCost(250 * WAD, 100 * WAD, true, true, 10 * WAD),
      8_136_644_073_040_427_297,
      tolerance,
      "dominant trust buy cost"
    );
    assertApproxEqAbs(
      pricing.getCost(250 * WAD, 100 * WAD, false, true, 10 * WAD),
      3_122_119_112_188_993_294,
      tolerance,
      "depleted distrust buy cost"
    );
    assertApproxEqAbs(
      pricing.getCost(260 * WAD, 100 * WAD, true, false, 10 * WAD),
      8_136_644_073_040_427_297,
      tolerance,
      "dominant trust sell revenue"
    );
    assertApproxEqAbs(
      pricing.getCost(250 * WAD, 110 * WAD, false, false, 10 * WAD),
      3_122_119_112_188_993_294,
      tolerance,
      "depleted distrust sell revenue"
    );
  }

  // --- name() ---

  function test_name() public view {
    assertEq(pricing.name(), "AdaptiveLMSR");
  }

  // --- getPrice: spot price symmetry ---

  /// @notice trustPrice + distrustPrice ≈ 1e18 across a range of supplies.
  function test_getPrice_sums_to_one() public view {
    _assertPriceSum(0, 0);
    _assertPriceSum(WAD, WAD);
    _assertPriceSum(100 * WAD, 50 * WAD);
    _assertPriceSum(1000 * WAD, 1 * WAD);
    _assertPriceSum(0, 1000 * WAD);
  }

  function _assertPriceSum(uint256 trust, uint256 distrust) internal view {
    uint256 trustPrice = pricing.getPrice(trust, distrust, true);
    uint256 distrustPrice = pricing.getPrice(trust, distrust, false);
    // Allow ±1 wei from PRBMath rounding.
    assertApproxEqAbs(trustPrice + distrustPrice, WAD, 1);
  }

  /// @notice Side-swap symmetry: getPrice(a, b, true) == getPrice(b, a, false) (within rounding).
  function test_getPrice_side_swap_symmetry() public view {
    uint256 a = 250 * WAD;
    uint256 b = 100 * WAD;
    uint256 trustPriceAtA = pricing.getPrice(a, b, true);
    uint256 distrustPriceAtSwapped = pricing.getPrice(b, a, false);
    assertApproxEqAbs(trustPriceAtA, distrustPriceAtSwapped, 1);
  }

  /// @notice Neutral state (qt = qd): both sides return HALF_WAD.
  function test_getPrice_neutral_returnsHalf() public view {
    assertApproxEqAbs(pricing.getPrice(0, 0, true), HALF_WAD, 1);
    assertApproxEqAbs(pricing.getPrice(100 * WAD, 100 * WAD, true), HALF_WAD, 1);
  }

  /// @notice Asymmetric state: trust > distrust pulls the trust-side price above HALF_WAD
  ///         and the distrust-side price below it. Pins that the side branches diverge.
  function test_getPrice_asymmetric_branches_diverge() public view {
    uint256 trust = 100 * WAD;
    uint256 distrust = 50 * WAD;
    uint256 trustPrice = pricing.getPrice(trust, distrust, true);
    uint256 distrustPrice = pricing.getPrice(trust, distrust, false);
    assertGt(trustPrice, HALF_WAD, "trust-side price should exceed 0.5 when trust > distrust");
    assertLt(distrustPrice, HALF_WAD, "distrust-side price should fall below 0.5 when trust > distrust");
    assertApproxEqAbs(trustPrice + distrustPrice, WAD, 1, "sides sum to 1");
  }

  // --- getCost: zero-amount short-circuit ---

  function test_getCost_zero_amount_returns_zero_exact() public view {
    // Zero amount must return EXACTLY 0 — asymmetric Ceil/Floor would otherwise
    // leak ≥1 wei spuriously.
    assertEq(pricing.getCost(100 * WAD, 50 * WAD, true, true, 0), 0, "buy zero amount");
    assertEq(pricing.getCost(100 * WAD, 50 * WAD, true, false, 0), 0, "sell zero amount");
    assertEq(pricing.getCost(100 * WAD, 50 * WAD, false, true, 0), 0, "buy zero amount distrust");
    assertEq(pricing.getCost(100 * WAD, 50 * WAD, false, false, 0), 0, "sell zero amount distrust");
  }

  // --- getCost: insufficient supply on sell ---

  /// @notice Selling more than the trust-side supply reverts InsufficientSupplyToSell.
  function test_getCost_sell_reverts_insufficient_trust_supply() public {
    uint256 trust = 5 * WAD;
    uint256 distrust = 100 * WAD;
    uint256 amount = trust + 1;
    vm.expectRevert(abi.encodeWithSelector(InsufficientSupplyToSell.selector, trust, amount));
    pricing.getCost(trust, distrust, true, false, amount);
  }

  /// @notice Selling more than the distrust-side supply reverts InsufficientSupplyToSell.
  function test_getCost_sell_reverts_insufficient_distrust_supply() public {
    uint256 trust = 100 * WAD;
    uint256 distrust = 5 * WAD;
    uint256 amount = distrust + 1;
    vm.expectRevert(abi.encodeWithSelector(InsufficientSupplyToSell.selector, distrust, amount));
    pricing.getCost(trust, distrust, false, false, amount);
  }

  // --- getCost: monotonicity ---

  function test_getCost_buy_monotonic() public view {
    uint256 trust = 100 * WAD;
    uint256 distrust = 100 * WAD;
    uint256 small = pricing.getCost(trust, distrust, true, true, WAD);
    uint256 medium = pricing.getCost(trust, distrust, true, true, 5 * WAD);
    uint256 large = pricing.getCost(trust, distrust, true, true, 20 * WAD);
    assertGt(medium, small, "5 tokens cost more than 1");
    assertGt(large, medium, "20 tokens cost more than 5");
  }

  function test_getCost_sell_monotonic() public view {
    uint256 trust = 200 * WAD;
    uint256 distrust = 100 * WAD;
    uint256 small = pricing.getCost(trust, distrust, true, false, WAD);
    uint256 medium = pricing.getCost(trust, distrust, true, false, 5 * WAD);
    uint256 large = pricing.getCost(trust, distrust, true, false, 20 * WAD);
    assertGt(medium, small, "5 tokens revenue more than 1");
    assertGt(large, medium, "20 tokens revenue more than 5");
  }

  // --- getCost: path independence (LMSR's defining property, direction-bounded) ---

  /// @notice Sum of n sequential 1-token buys ≥ a single n-token buy (Ceil rounding makes
  ///         the sum at least as large). Bound the divergence to ≤ n wei to catch rounding
  ///         direction bugs.
  function test_getCost_path_independence_bounded() public view {
    uint256 trust = 100 * WAD;
    uint256 distrust = 100 * WAD;
    uint256 n = 10;

    uint256 singleCost = pricing.getCost(trust, distrust, true, true, n * WAD);

    uint256 sequentialCost;
    uint256 currentTrust = trust;
    for (uint256 i; i < n; i++) {
      sequentialCost += pricing.getCost(currentTrust, distrust, true, true, WAD);
      currentTrust += WAD;
    }

    assertGe(sequentialCost, singleCost, "sequential >= single (Ceil rounding)");
    assertLe(sequentialCost - singleCost, n, "divergence bound: <= n wei from per-step Ceil");
  }

  // --- Round-trip bound: buy then immediate sell ---

  function test_getCost_round_trip_no_arbitrage() public view {
    uint256 trust = 100 * WAD;
    uint256 distrust = 100 * WAD;
    uint256 amount = 5 * WAD;

    uint256 buyCost = pricing.getCost(trust, distrust, true, true, amount);
    // After the buy: trust = trust + amount.
    uint256 sellRevenue = pricing.getCost(trust + amount, distrust, true, false, amount);

    assertLe(sellRevenue, buyCost, "round-trip: sell revenue <= buy cost (no path arbitrage)");
  }

  // --- getTokensForBudget: consistency ---

  /// @notice Returned `n` satisfies getCost(n) ≤ budget < getCost(n+1).
  function test_getTokensForBudget_consistency() public view {
    uint256 trust = 100 * WAD;
    uint256 distrust = 100 * WAD;
    // Budget that buys around 5 tokens.
    uint256 budget = pricing.getCost(trust, distrust, true, true, 5 * WAD);

    uint256 n = pricing.getTokensForBudget(trust, distrust, true, budget);
    if (n > 0) {
      assertLe(pricing.getCost(trust, distrust, true, true, n), budget, "getCost(n) <= budget");
    }
    // n must be far below MAX_TOKENS_PER_TRADE for the +1 check to be meaningful.
    assertLt(n + 1, pricing.MAX_TOKENS_PER_TRADE(), "n+1 within strategy domain");
    assertGt(pricing.getCost(trust, distrust, true, true, n + 1), budget, "getCost(n+1) > budget");
  }

  function test_getTokensForBudget_zero_budget() public view {
    assertEq(pricing.getTokensForBudget(100 * WAD, 100 * WAD, true, 0), 0);
  }

  function test_getTokensForBudget_justBelowCapCost_returnsBelowTradeCap() public view {
    uint256 trust = WAD;
    uint256 distrust = WAD;
    uint256 cap = pricing.MAX_TOKENS_PER_TRADE();
    uint256 capCost = pricing.getCost(trust, distrust, true, true, cap);

    uint256 n = pricing.getTokensForBudget(trust, distrust, true, capCost - 1);

    assertLt(n, cap, "budget just below cap cost cannot buy the capped amount");
    assertLe(pricing.getCost(trust, distrust, true, true, n), capCost - 1);
    assertGt(pricing.getCost(trust, distrust, true, true, n + 1), capCost - 1);
  }

  /// @notice Tiny budget: getCost(WAD) > budget on first iteration → binary search refines [0, WAD]
  ///         and returns 0 (or a small partial-token count if amounts < WAD are buyable).
  function test_getTokensForBudget_tiny_budget_returns_zero_or_partial() public view {
    uint256 trust = 100 * WAD;
    uint256 distrust = 100 * WAD;
    uint256 tinyBudget = 1; // 1 wei

    uint256 n = pricing.getTokensForBudget(trust, distrust, true, tinyBudget);
    if (n > 0) {
      assertLe(pricing.getCost(trust, distrust, true, true, n), tinyBudget);
    }
  }

  /// @notice Saturated-domain budget revert: builds state where the doubling search hits
  ///         the static cap before crossing budget, expecting BudgetUpperBoundNotFound
  ///         (NOT a PRBMath overflow). Confirms the fail-closed behaviour.
  function test_getTokensForBudget_reverts_when_cap_reached() public {
    uint256 trust = WAD;
    uint256 distrust = WAD;
    // A "huge" budget — much larger than the cost of buying MAX_TOKENS_PER_TRADE
    // even at imbalanced state. The doubling search will hit the cap, see that
    // getCost(cap) <= budget, and revert.
    uint256 hugeBudget = type(uint128).max;
    vm.expectRevert(abi.encodeWithSelector(BudgetUpperBoundNotFound.selector, hugeBudget));
    pricing.getTokensForBudget(trust, distrust, true, hugeBudget);
  }

  // --- Safe-domain boundary ---

  function test_safeDomain_revert_unreachable_at_min_alpha() public {
    AdaptiveLMSRPricing thinAlpha = new AdaptiveLMSRPricing(1, pricing.MIN_ALPHA());

    uint256 trust = thinAlpha.MAX_TOKENS_PER_TRADE() / 2;
    uint256 distrust = 0;

    uint256 trustPrice = thinAlpha.getPrice(trust, distrust, true);
    assertGt(trustPrice, 0);
    assertLt(trustPrice, WAD);

    uint256 buyCost = thinAlpha.getCost(trust, distrust, true, true, WAD);
    assertGt(buyCost, 0);
  }

  // --- getSignal ---

  /// @notice getSignal(0, 0) = HALF_WAD per IReputationPricing contract.
  function test_getSignal_zero_zero_is_half() public view {
    assertEq(pricing.getSignal(0, 0), HALF_WAD);
  }

  function test_getSignal_equal_is_half() public view {
    assertApproxEqAbs(pricing.getSignal(100 * WAD, 100 * WAD), HALF_WAD, 1);
  }

  function test_getSignal_trust_dominant() public view {
    uint256 signal = pricing.getSignal(200 * WAD, 100 * WAD);
    assertGt(signal, HALF_WAD);
    assertLt(signal, WAD);
  }

  function test_getSignal_distrust_dominant() public view {
    uint256 signal = pricing.getSignal(100 * WAD, 200 * WAD);
    assertLt(signal, HALF_WAD);
    assertGt(signal, 0);
  }

  // --- Cost asymmetry: Ceil for buys, Floor for sells ---

  /// @notice On the same state, an immediate buy-sell round trip costs the seller
  ///         strictly more than 0 (exit fee aside), bounded above by ~few wei from rounding.
  function test_getCost_buy_minus_sell_within_few_wei() public view {
    uint256 trust = 100 * WAD;
    uint256 distrust = 100 * WAD;
    uint256 amount = 1 * WAD;

    uint256 buyCost = pricing.getCost(trust, distrust, true, true, amount);
    uint256 sellRevenue = pricing.getCost(trust + amount, distrust, true, false, amount);
    assertGt(buyCost, sellRevenue, "buy > sell revenue (Ceil/Floor asymmetry leaks at least 1 wei)");
    // Net rounding leak should be very small relative to the cost itself.
    assertLe(buyCost - sellRevenue, 4, "rounding leak <= 4 wei per round trip");
  }

  /// @notice Fuzzed buy-then-sell: the round-trip leak from Ceil/Floor asymmetry stays bounded
  ///         by a few wei across the (qt, qd, amount) state space. Catches rounding-direction
  ///         regressions that the single-state assertion above might miss.
  function testFuzz_getCost_buy_minus_sell_bounded(uint256 trustSeed, uint256 distrustSeed, uint256 amountSeed)
    public
    view
  {
    uint256 trust = bound(trustSeed, 0, 1e21);
    uint256 distrust = bound(distrustSeed, 0, 1e21);
    uint256 amount = bound(amountSeed, 1, 100 * WAD);

    uint256 buyCost = pricing.getCost(trust, distrust, true, true, amount);
    uint256 sellRevenue = pricing.getCost(trust + amount, distrust, true, false, amount);

    assertGe(buyCost, sellRevenue, "round trip: buy >= sell revenue");
    // Bound is generous because the larger of (qt, qd, amount) drives the b·ln(...) magnitude
    // and Ceil/Floor each leak at most one ULP per call; allow a couple ULPs for safety.
    assertLe(buyCost - sellRevenue, 8, "rounding leak per round trip stays small");
  }

  function testFuzz_getCost_crossSideClosedPath_noArbitrage_wadScale(
    uint256 trustSeed,
    uint256 distrustSeed,
    uint256 trustAmountSeed,
    uint256 distrustAmountSeed
  ) public view {
    uint256 trust = bound(trustSeed, 100 * WAD, 1e24);
    uint256 distrust = bound(distrustSeed, 100 * WAD, 1e24);
    uint256 trustAmount = bound(trustAmountSeed, WAD, 1e24);
    uint256 distrustAmount = bound(distrustAmountSeed, WAD, 1e24);

    _assertClosedPathNoArbitrage(trust, distrust, trustAmount, distrustAmount, true);
    _assertClosedPathNoArbitrage(trust, distrust, trustAmount, distrustAmount, false);
  }

  function test_getCost_crossSideClosedPath_subWadCounterexample() public view {
    (uint256 buySpend, uint256 sellRevenue) = _closedPathTotals(41, 100, 875, 10_000, false);

    assertGt(sellRevenue, buySpend, "sub-WAD closed path counterexample should stay visible");
  }

  function test_getCost_crossSideClosedPath_dustTradeCounterexample_atProductionScaleSupply() public view {
    uint256 trust = bound(15_901_846_234_150_570_978_712_207, 100 * WAD, 1e24);
    uint256 distrust = bound(type(uint256).max - 2, 100 * WAD, 1e24);
    uint256 trustAmount = bound(182_267_232_574_271_381_521, WAD, 1e24);
    uint256 distrustDust = 126_830;

    (uint256 buySpend, uint256 sellRevenue) = _closedPathTotals(trust, distrust, trustAmount, distrustDust, true);

    assertGt(sellRevenue, buySpend, "dust-sized closed path counterexample should stay visible");
  }

  function _assertClosedPathNoArbitrage(
    uint256 trust,
    uint256 distrust,
    uint256 trustAmount,
    uint256 distrustAmount,
    bool trustFirst
  ) internal view {
    (uint256 buySpend, uint256 sellRevenue) =
      _closedPathTotals(trust, distrust, trustAmount, distrustAmount, trustFirst);

    assertLe(sellRevenue, buySpend, "closed cross-side path must not create value");
  }

  function _closedPathTotals(
    uint256 trust,
    uint256 distrust,
    uint256 trustAmount,
    uint256 distrustAmount,
    bool trustFirst
  ) internal view returns (uint256 buySpend, uint256 sellRevenue) {
    if (trustFirst) {
      buySpend += pricing.getCost(trust, distrust, true, true, trustAmount);
      buySpend += pricing.getCost(trust + trustAmount, distrust, false, true, distrustAmount);

      sellRevenue += pricing.getCost(trust + trustAmount, distrust + distrustAmount, true, false, trustAmount);
      sellRevenue += pricing.getCost(trust, distrust + distrustAmount, false, false, distrustAmount);
    } else {
      buySpend += pricing.getCost(trust, distrust, false, true, distrustAmount);
      buySpend += pricing.getCost(trust, distrust + distrustAmount, true, true, trustAmount);

      sellRevenue += pricing.getCost(trust + trustAmount, distrust + distrustAmount, false, false, distrustAmount);
      sellRevenue += pricing.getCost(trust + trustAmount, distrust, true, false, trustAmount);
    }
  }

  /// @notice Tiny sell crossing the trust = distrust boundary: at the symmetric state, the
  ///         absDiff branch flips between trust > distrust and distrust > trust as `amount`
  ///         crosses zero. Verifies that 1-wei sells stay solvent (revenue ≤ cost would have
  ///         been in the converse buy) and that ZeroPayout-adjacent cases short-circuit.
  function test_getCost_tiny_sell_across_neutral_boundary() public view {
    uint256 supply = 100 * WAD;

    // At qt == qd, a 1-wei sell on the trust side should yield <= the 1-wei buy cost.
    uint256 buyCost = pricing.getCost(supply, supply, true, true, 1);
    uint256 sellRevenue = pricing.getCost(supply, supply, true, false, 1);
    assertLe(sellRevenue, buyCost, "tiny sell revenue <= tiny buy cost at qt=qd");

    // Mirror on distrust side — symmetric.
    uint256 buyCostD = pricing.getCost(supply, supply, false, true, 1);
    uint256 sellRevenueD = pricing.getCost(supply, supply, false, false, 1);
    assertLe(sellRevenueD, buyCostD, "tiny sell revenue <= tiny buy cost at qt=qd, distrust side");

    // A 1-wei sell on a barely-imbalanced state should also stay solvent — Ceil(C(after)) is
    // floor-rounded against Floor(C(before)), so the worst case is sellRevenue == 0 (ZeroPayout).
    uint256 sellRevenueImbalanced = pricing.getCost(supply + 1, supply, true, false, 1);
    uint256 buyCostImbalanced = pricing.getCost(supply, supply, true, true, 1);
    assertLe(sellRevenueImbalanced, buyCostImbalanced, "1-wei sell across boundary stays solvent");
  }

  // --- Argument-order pinning: trustSupply first regardless of side ---

  /// @notice `getCost(trust, distrust, isPositive=false)` reads distrust supply for the curve.
  ///         If we mistakenly swapped to "self-side first", a distrust-side buy at
  ///         (trust=200, distrust=50) would price as if buying with (trust=50, distrust=200) —
  ///         which has very different costs. This test pins the orientation.
  function test_getCost_argument_order_pinned() public view {
    uint256 trust = 200 * WAD;
    uint256 distrust = 50 * WAD;
    uint256 amount = 5 * WAD;

    // distrust-side buy at (trust=200, distrust=50): we price (trust=200, distrust=55) - (trust=200, distrust=50).
    uint256 distrustBuyCost = pricing.getCost(trust, distrust, false, true, amount);

    // The same shape mirrored — trust-side buy at the swapped state — should cost the same
    // since LMSR is symmetric under the qt/qd swap with isPositive flip.
    uint256 trustBuyMirror = pricing.getCost(distrust, trust, true, true, amount);

    assertApproxEqAbs(distrustBuyCost, trustBuyMirror, 1, "trust-first ordering preserved");
  }

  /// @notice Asymmetric pin: at imbalanced state, the abundant side is more expensive
  ///         than the depleted side. A self-side-first inversion bug would silently flip
  ///         this inequality (the symmetry test above passes under such a bug).
  function test_getCost_argument_order_pinned_asymmetric() public view {
    uint256 amount = 5 * WAD;

    // (trust=0, distrust=100*WAD): market leans distrust → distrust spot price > trust spot
    // price, so a distrust-side buy costs MORE than a trust-side buy of equal size.
    uint256 trustBuyAtDistrustHeavy = pricing.getCost(0, 100 * WAD, true, true, amount);
    uint256 distrustBuyAtDistrustHeavy = pricing.getCost(0, 100 * WAD, false, true, amount);
    assertGt(
      distrustBuyAtDistrustHeavy, trustBuyAtDistrustHeavy, "abundant distrust must cost more than depleted trust"
    );

    // Converse: (trust=100*WAD, distrust=0) → trust-side buy is the expensive one.
    uint256 trustBuyAtTrustHeavy = pricing.getCost(100 * WAD, 0, true, true, amount);
    uint256 distrustBuyAtTrustHeavy = pricing.getCost(100 * WAD, 0, false, true, amount);
    assertGt(trustBuyAtTrustHeavy, distrustBuyAtTrustHeavy, "abundant trust must cost more than depleted distrust");
  }

  // --- Fuzz: solvency on getTokensForBudget ---

  /// @notice getCost(getTokensForBudget(budget)) ≤ budget under bounded inputs.
  function testFuzz_getTokensForBudget_solvency(uint256 trustSeed, uint256 distrustSeed, uint256 budgetSeed)
    public
    view
  {
    uint256 trust = bound(trustSeed, 0, 1e21); // up to 1000 tokens
    uint256 distrust = bound(distrustSeed, 0, 1e21);
    // Cap budget so the doubling-search doesn't hit BudgetUpperBoundNotFound.
    uint256 budget = bound(budgetSeed, 1, 1e21);

    uint256 n = pricing.getTokensForBudget(trust, distrust, true, budget);
    if (n == 0) return;
    uint256 cost = pricing.getCost(trust, distrust, true, true, n);
    assertLe(cost, budget, "solvency: getCost(n) <= budget");
  }

  function testFuzz_getTokensForBudget_boundary(
    uint256 trustSeed,
    uint256 distrustSeed,
    uint256 budgetSeed,
    bool isPositive
  ) public view {
    uint256 trust = bound(trustSeed, 0, 1e24);
    uint256 distrust = bound(distrustSeed, 0, 1e24);
    uint256 budget = bound(budgetSeed, 1, 1e24);

    uint256 n = pricing.getTokensForBudget(trust, distrust, isPositive, budget);
    uint256 cost = pricing.getCost(trust, distrust, isPositive, true, n);
    assertLe(cost, budget, "boundary: getCost(n) <= budget");

    assertLt(n, pricing.MAX_TOKENS_PER_TRADE(), "n+1 within strategy domain");
    uint256 nextCost = pricing.getCost(trust, distrust, isPositive, true, n + 1);
    assertGt(nextCost, budget, "boundary: getCost(n+1) > budget");
  }

  function testFuzz_getTokensForBudget_monotonicWithBudget(
    uint256 trustSeed,
    uint256 distrustSeed,
    uint256 lowBudgetSeed,
    uint256 highBudgetSeed,
    bool isPositive
  ) public view {
    uint256 trust = bound(trustSeed, 0, 1e24);
    uint256 distrust = bound(distrustSeed, 0, 1e24);
    uint256 budgetA = bound(lowBudgetSeed, 1, 1e24);
    uint256 budgetB = bound(highBudgetSeed, 1, 1e24);
    if (budgetA > budgetB) {
      (budgetA, budgetB) = (budgetB, budgetA);
    }

    uint256 tokensA = pricing.getTokensForBudget(trust, distrust, isPositive, budgetA);
    uint256 tokensB = pricing.getTokensForBudget(trust, distrust, isPositive, budgetB);

    assertLe(tokensA, tokensB, "larger budget must not buy fewer tokens");
  }

  // --- getPrice vs empirical marginal cost: divergence under adaptive b ---

  /// @notice Under standard (constant-b) LMSR, `getPrice(qt, qd, true)` equals `dC/dqt`
  ///         exactly. Under adaptive `b = b0 + alpha·(qt+qd)/WAD`, the true marginal
  ///         picks up an extra `(alpha/WAD)·ln(1 + exp(-|qt−qd|/b))` term, so the
  ///         empirical per-token cost (via getCost / amount) is larger than `getPrice`
  ///         returns. At the neutral state the extra term equals `(alpha/WAD)·ln(2)`
  ///         exactly; this test pins the equality.
  /// @dev At qt = qd: extra-term = (alpha/WAD)·ln(2) ≈ 0.1·0.693 = 0.0693 WAD.
  ///      At production defaults this means buyers pay ~6.93% MORE per token at the
  ///      neutral state than the displayed spot price suggests. Indexers and UI that
  ///      consume `getPrice` for a "trust price" gauge should treat it as a probability
  ///      readout (sigmoid of the supply gap), NOT as a buy-cost quote — quotes must
  ///      go through `getCost`.
  function test_getPrice_marginal_extra_alphaLn2_at_neutral() public view {
    uint256 qt = 100 * WAD;
    uint256 qd = 100 * WAD;

    uint256 spot = pricing.getPrice(qt, qd, true);
    // Tiny buy: 1e15 wei — exposes the marginal at near-zero amount with negligible Ceil leak.
    uint256 dx = 1e15;
    uint256 emp1 = (pricing.getCost(qt, qd, true, true, dx) * WAD) / dx;
    // Larger buy: 1e18 wei (1 token) — integrated marginal across a meaningful range.
    uint256 dxLarge = WAD;
    uint256 empN = (pricing.getCost(qt, qd, true, true, dxLarge) * WAD) / dxLarge;

    assertApproxEqAbs(spot, HALF_WAD, 1, "spot at neutral");

    // Empirical marginal exceeds spot by exactly the adaptive-b correction
    // (alpha/WAD)·ln(2) ≈ 6.93e16 at neutral. Allow a +/- 1% band to account for
    // Ceil rounding and the larger-dx term picking up second-order effects.
    uint256 expectedExtra = (ALPHA * pricing.LN2_WAD()) / WAD; // (alpha/WAD) * ln(2) WAD
    assertApproxEqAbs(emp1 - spot, expectedExtra, WAD / 100, "tiny-buy emp marginal = spot + alpha*ln2");
    // The 1-token integrated marginal is also above spot, by approximately the same
    // amount (the integral averages slightly more because b grows during the buy).
    assertGt(empN, spot, "1-token integrated marginal > spot");
    assertLe(empN - spot, expectedExtra + WAD / 100, "integrated marginal within tolerance");
  }

  /// @notice Imbalanced state: same-direction divergence stays bounded by `(alpha/WAD)·ln(2)`.
  ///         Extra term = (alpha/WAD)·ln(1 + exp(-(qt-qd)/b)). For qt=200, qd=100,
  ///         b≈130e18 → ratio ≈ 100/130 ≈ 0.769 → ln(1+exp(-0.769)) ≈ 0.376
  ///         → extra ≈ 0.1·0.376 ≈ 0.0376 WAD ≈ 3.76% of WAD.
  function test_getPrice_marginal_extra_imbalanced_within_alphaLn2() public view {
    uint256 qt = 200 * WAD;
    uint256 qd = 100 * WAD;

    uint256 spot = pricing.getPrice(qt, qd, true);
    uint256 dx = 1e15;
    uint256 emp1 = (pricing.getCost(qt, qd, true, true, dx) * WAD) / dx;

    // Empirical strictly above spot.
    assertGt(emp1, spot, "empirical marginal > spot at imbalanced state");
    // Divergence stays bounded by the worst-case extra ≈ alpha·ln(2)/WAD.
    uint256 divergence = emp1 - spot;
    uint256 alphaLn2 = (ALPHA * pricing.LN2_WAD()) / WAD;
    assertLe(divergence, alphaLn2 + WAD / 100, "divergence bounded by alpha*ln(2)");
  }

  /// @notice Sanity check: monotonicity of empirical marginal across a buy.
  ///         As trust supply grows, trust-side marginal cost rises monotonically
  ///         (sigmoid in (qt-qd)/b is monotone increasing in qt). This is the
  ///         baseline property `getPrice` claims to expose.
  function test_getPrice_monotonic_along_trust_axis() public view {
    uint256 qd = 100 * WAD;
    uint256 priceLow = pricing.getPrice(50 * WAD, qd, true);
    uint256 priceMid = pricing.getPrice(100 * WAD, qd, true);
    uint256 priceHigh = pricing.getPrice(200 * WAD, qd, true);
    assertLt(priceLow, priceMid, "spot rises with trust supply");
    assertLt(priceMid, priceHigh, "spot rises with trust supply (further)");
    // All in (0, WAD).
    assertGt(priceLow, 0);
    assertLt(priceHigh, WAD);
  }
}
