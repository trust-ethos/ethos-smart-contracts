// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {SD59x18, sd, intoUint256, UNIT as SD_UNIT} from "@prb/math/src/SD59x18.sol";
import {IReputationPricing} from "./interfaces/IReputationPricing.sol";
import {
  BudgetUpperBoundNotFound,
  InsufficientSupplyToSell,
  InvalidAlphaParameter,
  InvalidBaseLiquidityParameter,
  SuppliesExceedArithmeticLimit,
  SuppliesExceedSafeLimit
} from "./errors/PricingErrors.sol";
import {HALF_WAD, WAD} from "./utils/MathConstants.sol";

/// @title AdaptiveLMSRPricing
/// @author Ethos Network
/// @notice LMSR bonding curve where liquidity scales with total supply. Use
///         `getCost` for buy/sell quotes; `getPrice` is a UI signal, not a quote.
/// @dev Joint cost surface `C(qt, qd) = b · ln(exp(qt/b) + exp(qd/b))` with
///      `b = b0 + alpha · (qt + qd) / WAD`. Because `b` grows with supply, the
///      `getPrice` sigmoid drifts from per-token marginal cost by up to
///      `(alpha/WAD)·ln(2)` — fine for display, wrong for accounting.
///
///      Safe-domain invariant: `|qt − qd| ≤ 41 · b`; `MIN_ALPHA` keeps legal
///      strategies below PRBMath's silent `exp` underflow edge.
/// @custom:security-contact security@ethos.network
contract AdaptiveLMSRPricing is IReputationPricing {
  // --- Constants ---

  /// @notice Per-trade token cap for quote search and arithmetic safety.
  uint256 public constant MAX_TOKENS_PER_TRADE = 1e33;

  /// @notice Misconfiguration guard on `b0`, set far above the production default.
  /// @dev Participates in `MAX_ALPHA` so `b0 + alpha·sum/WAD` stays safe.
  uint256 public constant MAX_B0 = 1e30;

  /// @notice Maximum `|qt − qd| / b` ratio (WAD-scaled) before reverting.
  /// @dev PRBMath `SD59x18.exp(x)` returns 0 silently for `x < -41.447e18`. We revert
  ///      at 41e18 with ~0.45 WAD headroom so the silent-zero regime is unreachable
  ///      from `getPrice` / `getCost`.
  uint256 private constant SAFE_RATIO = 41;
  uint256 private constant SAFE_RATIO_WAD = SAFE_RATIO * WAD;

  /// @notice Minimum `alpha` that keeps the asymptotic `|qt - qd| / b` ratio safe.
  uint256 public constant MIN_ALPHA = (WAD + SAFE_RATIO - 1) / SAFE_RATIO;

  /// @notice Maximum trust+distrust supply covered by buy-cost arithmetic.
  uint256 public constant MAX_SAFE_SUPPLY_SUM = 3 * MAX_TOKENS_PER_TRADE;

  /// @notice Maximum `alpha` that keeps `b` arithmetic safe over the capped domain.
  uint256 public constant MAX_ALPHA = (type(uint256).max - MAX_B0) / (MAX_SAFE_SUPPLY_SUM / WAD);

  /// @notice `ln(2)` WAD-scaled. Used in the equal-supply branch: `C = q + b · ln(2)`.
  /// @dev `public` so tests pin against the same constant the cost path uses.
  uint256 public constant LN2_WAD = 693147180559945309;

  // --- Immutable parameters ---

  /// @notice Base liquidity parameter (WAD-scaled). Constructor enforces `(0, MAX_B0]`.
  uint256 public immutable b0;

  /// @notice Adaptive liquidity scaling coefficient (WAD-scaled). Constructor enforces `[MIN_ALPHA, MAX_ALPHA]`.
  uint256 public immutable alpha;

  // --- Constructor ---

  /// @notice Deploys with the given base liquidity and adaptive scaling.
  /// @param b0_ Base liquidity (WAD). Reverts `InvalidBaseLiquidityParameter` outside `(0, MAX_B0]`.
  /// @param alpha_ Adaptive scaling coefficient (WAD). Reverts outside `[MIN_ALPHA, MAX_ALPHA]`.
  constructor(uint256 b0_, uint256 alpha_) {
    if (b0_ == 0 || b0_ > MAX_B0) revert InvalidBaseLiquidityParameter();
    if (alpha_ < MIN_ALPHA || alpha_ > MAX_ALPHA) revert InvalidAlphaParameter();
    b0 = b0_;
    alpha = alpha_;
  }

  // --- IReputationPricing ---

  /// @inheritdoc IReputationPricing
  /// @notice UI/indexer signal — sigmoid of the supply gap. **Not a quote**; use
  ///         `getCost` for buy/sell pricing.
  function getPrice(uint256 trustSupply, uint256 distrustSupply, bool isPositive)
    external
    view
    override
    returns (uint256)
  {
    if (isPositive) {
      return _sigmoid(trustSupply, distrustSupply);
    }
    return _sigmoid(distrustSupply, trustSupply);
  }

  /// @inheritdoc IReputationPricing
  /// @dev Rounding always favors the protocol — sub-wei trades round to free, never to a credit.
  function getCost(uint256 trustSupply, uint256 distrustSupply, bool isPositive, bool isBuy, uint256 amount)
    external
    view
    override
    returns (uint256)
  {
    if (amount == 0) return 0;

    if (isBuy) {
      return _buyCostCeil(trustSupply, distrustSupply, isPositive, amount);
    }

    uint256 newTrust = trustSupply;
    uint256 newDistrust = distrustSupply;
    if (isPositive) {
      if (amount > trustSupply) revert InsufficientSupplyToSell(trustSupply, amount);
      newTrust = trustSupply - amount;
    } else {
      if (amount > distrustSupply) revert InsufficientSupplyToSell(distrustSupply, amount);
      newDistrust = distrustSupply - amount;
    }

    uint256 cBefore = _costFunction(trustSupply, distrustSupply, Math.Rounding.Floor);
    uint256 cAfter = _costFunction(newTrust, newDistrust, Math.Rounding.Ceil);
    return Math.saturatingSub(cBefore, cAfter);
  }

  /// @inheritdoc IReputationPricing
  function getSignal(uint256 trustSupply, uint256 distrustSupply) external view override returns (uint256) {
    if (trustSupply == 0 && distrustSupply == 0) return HALF_WAD;
    return _sigmoid(trustSupply, distrustSupply);
  }

  /// @inheritdoc IReputationPricing
  /// @dev LMSR has no closed-form inverse: `_findUpperBoundForBudget` doubles to bracket,
  ///      then binary search refines. The cap (`MAX_TOKENS_PER_TRADE` = `1e33`) is sized
  ///      so any budget a 256-bit ERC20 balance can fund brackets well before it.
  function getTokensForBudget(uint256 trustSupply, uint256 distrustSupply, bool isPositive, uint256 budget)
    external
    view
    override
    returns (uint256)
  {
    if (budget == 0) return 0;

    (uint256 hi, uint256 cBeforeFloor) = _findUpperBoundForBudget(trustSupply, distrustSupply, isPositive, budget);

    // Postcondition of _findUpperBoundForBudget: hi >= WAD and _buyCostCeil(hi) > budget.
    uint256 lo = 0;
    for (uint256 i = 0; i < 256 && lo < hi; ++i) {
      uint256 mid = (lo + hi + 1) / 2;
      if (_buyCostCeil(trustSupply, distrustSupply, isPositive, mid, cBeforeFloor) <= budget) {
        lo = mid;
      } else {
        hi = mid - 1;
      }
    }
    return lo;
  }

  /// @inheritdoc IReputationPricing
  function name() external pure override returns (string memory) {
    return "AdaptiveLMSR";
  }

  // --- Internal: LMSR math ---

  /// @dev `b = b0 + alpha · (trust + distrust) / WAD`. The sum-divided-by-WAD term reads
  ///      as "total tokens of liquidity" — the unit `b0` and `alpha` are denominated in.
  function _computeB(uint256 trustSupply, uint256 distrustSupply) internal view returns (uint256) {
    if (distrustSupply > type(uint256).max - trustSupply) {
      revert SuppliesExceedArithmeticLimit(trustSupply, distrustSupply, MAX_SAFE_SUPPLY_SUM);
    }

    uint256 supplySum = trustSupply + distrustSupply;
    if (supplySum > MAX_SAFE_SUPPLY_SUM) {
      revert SuppliesExceedArithmeticLimit(trustSupply, distrustSupply, MAX_SAFE_SUPPLY_SUM);
    }

    return b0 + Math.mulDiv(alpha, supplySum, WAD);
  }

  function _absDiff(uint256 a, uint256 b) private pure returns (uint256) {
    return a > b ? a - b : b - a;
  }

  /// @dev Log-sum-exp form: `C = qmax + b · ln(1 + exp(-|qt − qd| / b))`. Avoids the
  ///      `exp(qt/b)` overflow of the naive `b · ln(exp(qt/b) + exp(qd/b))`. `qmax` is
  ///      added exactly; only the `b · ln(...)` term carries rounding.
  function _costFunction(uint256 trustSupply, uint256 distrustSupply, Math.Rounding rounding)
    internal
    view
    returns (uint256)
  {
    uint256 b = _computeB(trustSupply, distrustSupply);

    uint256 qmax = Math.max(trustSupply, distrustSupply);
    uint256 absDiff = _absDiff(trustSupply, distrustSupply);

    if (absDiff == 0) {
      return qmax + Math.mulDiv(b, LN2_WAD, WAD, rounding);
    }

    uint256 ratioWad = Math.mulDiv(absDiff, WAD, b);
    if (ratioWad > SAFE_RATIO_WAD) revert SuppliesExceedSafeLimit(absDiff, b);

    SD59x18 expVal = sd(-SafeCast.toInt256(ratioWad)).exp();
    SD59x18 lnTerm = (SD_UNIT + expVal).ln();
    uint256 bLnTerm = Math.mulDiv(b, intoUint256(lnTerm), WAD, rounding);
    return qmax + bLnTerm;
  }

  /// @dev Sigmoid `1 / (1 + exp((qOther − qSelf) / b))` — probability the `qSelf` side
  ///      dominates under LMSR. May revert `SuppliesExceedSafeLimit`; callers needing
  ///      best-effort reads wrap in try/catch.
  function _sigmoid(uint256 qSelf, uint256 qOther) internal view returns (uint256) {
    uint256 b = _computeB(qSelf, qOther);
    uint256 absDiff = _absDiff(qSelf, qOther);
    uint256 ratioWad = Math.mulDiv(absDiff, WAD, b);
    if (ratioWad > SAFE_RATIO_WAD) revert SuppliesExceedSafeLimit(absDiff, b);

    // Recover sign of (qOther − qSelf) from the unsigned absDiff.
    int256 diff;
    if (qOther >= qSelf) {
      diff = SafeCast.toInt256(ratioWad);
    } else {
      diff = -SafeCast.toInt256(ratioWad);
    }

    SD59x18 expVal = sd(diff).exp();
    SD59x18 denom = SD_UNIT + expVal;
    SD59x18 result = SD_UNIT.div(denom);
    return intoUint256(result);
  }

  function _buyCostCeil(uint256 trustSupply, uint256 distrustSupply, bool isPositive, uint256 amount)
    internal
    view
    returns (uint256)
  {
    uint256 cBeforeFloor = _costFunction(trustSupply, distrustSupply, Math.Rounding.Floor);
    return _buyCostCeil(trustSupply, distrustSupply, isPositive, amount, cBeforeFloor);
  }

  /// @dev Canonical buy-cost — single source of truth for `getCost`'s buy quote and
  ///      `getTokensForBudget`'s searches, so a quoted cost matches what a buy charges.
  ///      `cBeforeFloor` must be `_costFunction(trustSupply, distrustSupply, Floor)`,
  ///      hoisted by the searches since it's invariant across probes.
  function _buyCostCeil(
    uint256 trustSupply,
    uint256 distrustSupply,
    bool isPositive,
    uint256 amount,
    uint256 cBeforeFloor
  ) internal view returns (uint256) {
    if (amount == 0) return 0;
    uint256 newTrust = trustSupply;
    uint256 newDistrust = distrustSupply;
    if (isPositive) {
      newTrust = trustSupply + amount;
    } else {
      newDistrust = distrustSupply + amount;
    }
    uint256 cAfter = _costFunction(newTrust, newDistrust, Math.Rounding.Ceil);
    return Math.saturatingSub(cAfter, cBeforeFloor);
  }

  /// @dev Doubling search from `WAD` to bracket `budget` for the binary search in
  ///      `getTokensForBudget`. The probe is bounded by `maxAmount` — the smaller of
  ///      `MAX_TOKENS_PER_TRADE` and the remaining headroom to `MAX_SAFE_SUPPLY_SUM`.
  ///      Clamping to the headroom keeps `existingSupply + probe` inside `_computeB`'s
  ///      arithmetic domain so a near-cap market cleanly returns `BudgetUpperBoundNotFound`
  ///      rather than reverting `SuppliesExceedArithmeticLimit` mid-search.
  ///
  ///      Also returns the Floor-rounded before-cost so the binary search reuses it,
  ///      computed only after the guards to preserve the at-cap revert.
  function _findUpperBoundForBudget(uint256 trustSupply, uint256 distrustSupply, bool isPositive, uint256 budget)
    internal
    view
    returns (uint256, uint256)
  {
    // Existing supply is already in-domain for any market `_computeB` has priced;
    // guard the overflow/at-cap edges so the probe never leaves the arithmetic domain.
    if (distrustSupply > type(uint256).max - trustSupply) {
      revert BudgetUpperBoundNotFound(budget);
    }
    uint256 existingSum = trustSupply + distrustSupply;
    if (existingSum >= MAX_SAFE_SUPPLY_SUM) {
      revert BudgetUpperBoundNotFound(budget);
    }
    uint256 maxAmount = Math.min(MAX_TOKENS_PER_TRADE, MAX_SAFE_SUPPLY_SUM - existingSum);

    uint256 hi = WAD;
    if (hi > maxAmount) {
      revert BudgetUpperBoundNotFound(budget);
    }

    uint256 cBeforeFloor = _costFunction(trustSupply, distrustSupply, Math.Rounding.Floor);
    if (_buyCostCeil(trustSupply, distrustSupply, isPositive, hi, cBeforeFloor) > budget) {
      return (hi, cBeforeFloor);
    }

    while (hi < maxAmount) {
      uint256 next = hi * 2;
      if (next > maxAmount) next = maxAmount;
      if (_buyCostCeil(trustSupply, distrustSupply, isPositive, next, cBeforeFloor) > budget) {
        return (next, cBeforeFloor);
      }
      hi = next;
    }
    revert BudgetUpperBoundNotFound(budget);
  }
}
