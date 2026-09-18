// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {PositionToken} from "../src/PositionToken.sol";
import {EthosMarket} from "../src/EthosMarket.sol";
import {AdaptiveLMSRPricing} from "../src/AdaptiveLMSRPricing.sol";
import {SuppliesExceedArithmeticLimit} from "../src/errors/PricingErrors.sol";
import {LMSRTestConstants} from "./helpers/LMSRTestConstants.sol";
import {MarketStackFixture} from "./helpers/MarketStackFixture.sol";

/// @title EthosMarketNearCapBuyDoS — M-3 regression
/// @notice Regression guard for audit finding M-3: the near-cap BUY-side DoS.
///
///         Defect (src/AdaptiveLMSRPricing.sol):
///           - `_findUpperBoundForBudget` (:257-276) doubles its probe `next`
///             against the EXISTING supply, capping only at MAX_TOKENS_PER_TRADE
///             (1e33) — NOT at MAX_SAFE_SUPPLY_SUM (3e33). The binary search in
///             `getTokensForBudget` (:148-156) likewise adds its midpoint to the
///             existing supply unclamped.
///           - On a near-cap market the probe pushes `existingSupply + next` past
///             MAX_SAFE_SUPPLY_SUM, so `_computeB` (:168-179) reverts
///             SuppliesExceedArithmeticLimit mid-search instead of returning the
///             documented BudgetUpperBoundNotFound (:275, dead code at high supply).
///           - The buy path is not try/catch-wrapped (src/EthosMarket.sol:471
///             `quoteBuy`, :519 `openPosition`, :551-552 `_tokensForBudget`), so the
///             wrong revert propagates and permanently bricks the BUY side while the
///             SELL side keeps working.
///
///         This test asserts the INTENDED SECURE behavior: a large in-domain buy on
///         a near-cap market must EITHER succeed with a sane in-domain result OR
///         revert with the documented BudgetUpperBoundNotFound — it must NEVER
///         surface SuppliesExceedArithmeticLimit. Against the unfixed curve it fails
///         precisely because the curve reverts SuppliesExceedArithmeticLimit.
contract EthosMarketNearCapBuyDoS is MarketStackFixture {
  uint256 constant B0 = LMSRTestConstants.B0; // 100e18 (production default)
  uint256 constant ALPHA = LMSRTestConstants.ALPHA; // 0.1e18 (production default)
  uint256 constant INITIAL_SUPPLY = 100e18;
  uint256 constant INITIAL_BACKING = 1000e18;

  // EthosMarket.markets mapping lives at storage slot 57 (forge inspect storageLayout).
  uint256 constant MARKETS_SLOT = 57;
  // MarketState field offsets within its slot run: 0 userkeyHash, 1 packed
  // (trustToken|exists|pauseState), 2 distrustToken, 3 pricingContract,
  // 4 trustSupply, 5 distrustSupply, 6 poolBacking, 7 totalVolume.
  uint256 constant TRUST_SUPPLY_OFFSET = 4;

  // The near-cap state an ordinary one-sided trust market drifts into over time
  // (2.5e33 < MAX_SAFE_SUPPLY_SUM 3e33: in-domain, the curve prices fine at it).
  uint256 constant NEAR_CAP_TRUST_SUPPLY = 2.5e33;

  AdaptiveLMSRPricing internal pricing;
  uint256 internal marketId;

  function setUp() public {
    _deployStack(INITIAL_SUPPLY);

    pricing = new AdaptiveLMSRPricing(B0, ALPHA);
    _setPricingAllowed(address(pricing), true);

    // Fund actors and the admin (admin seeds the market backing).
    address[3] memory actors = [alice, bob, carol];
    for (uint256 i; i < actors.length; i++) {
      vm.prank(_owner);
      whuffie.mint(actors[i], 1e36); // ample to fund a near-cap-sized budget
      vm.prank(actors[i]);
      whuffie.approve(address(market), type(uint256).max);
    }
    vm.prank(_owner);
    whuffie.mint(_admin, INITIAL_BACKING);
    vm.prank(_admin);
    whuffie.approve(address(market), INITIAL_BACKING);

    vm.prank(_admin);
    market.createMarketAdmin("address:0xNearCap", "near-cap", INITIAL_BACKING, address(pricing));
    marketId = market.marketCount();

    // Drive the trust side near the safe-supply cap. A market reaches this by
    // ordinary one-sided trust buying; we set it directly (vm.store) so the test
    // stays fast and deterministic instead of looping thousands of sub-cap buys.
    bytes32 base = keccak256(abi.encode(marketId, MARKETS_SLOT));
    bytes32 trustSupplySlot = bytes32(uint256(base) + TRUST_SUPPLY_OFFSET);
    bytes32 distrustSupplySlot = bytes32(uint256(base) + TRUST_SUPPLY_OFFSET + 1);
    vm.store(address(market), trustSupplySlot, bytes32(NEAR_CAP_TRUST_SUPPLY));
    // Zero the distrust side so this is a clean one-sided near-cap market (the
    // initial seed minted 100e18 to both sides at creation).
    vm.store(address(market), distrustSupplySlot, bytes32(uint256(0)));

    MarketSnapshot memory s = _snapshot(marketId);
    assertEq(s.trustSupply, NEAR_CAP_TRUST_SUPPLY, "setup: trust supply driven near cap");
    assertEq(s.distrustSupply, 0, "setup: distrust side untouched");
    assertLt(s.trustSupply, pricing.MAX_SAFE_SUPPLY_SUM(), "setup: state is in-domain (below 3e33 cap)");
  }

  /// @notice SECURE behavior: a large in-domain buy on a near-cap market must not be
  ///         DoS'd with the internal arithmetic-limit error. It must either quote a
  ///         sane in-domain result or surface the documented BudgetUpperBoundNotFound,
  ///         and the sell side must stay available in the same state.
  function test_M3_nearCapBuy_noArithmeticLimitDoS_sellStillWorks() public {
    // Headroom exists: buying 0.4e33 trust keeps the sum at 2.9e33 < 3e33 and the
    // curve prices it with a finite, positive cost. The buyer funds exactly this
    // in-domain cost, so the TRUE answer (~0.4e33 tokens) is provably in-domain.
    uint256 inDomainAmount = 0.4e33;
    uint256 inDomainCost = pricing.getCost(NEAR_CAP_TRUST_SUPPLY, 0, true, true, inDomainAmount);
    assertGt(inDomainCost, 0, "headroom: an in-domain buy has a finite, positive cost");
    assertLt(NEAR_CAP_TRUST_SUPPLY + inDomainAmount, pricing.MAX_SAFE_SUPPLY_SUM(), "answer is in-domain");

    uint256 buyerBudget = inDomainCost;
    assertGt(buyerBudget, market.MIN_BUY(), "buyer budget is a real, above-minimum trade");

    // --- quoteBuy (read path, EthosMarket.sol:471) ---
    (bool okQuote, bytes memory quoteRet) =
      address(market).staticcall(abi.encodeWithSelector(market.quoteBuy.selector, marketId, true, buyerBudget));

    // The defining M-3 assertion: the buy must NEVER surface the internal
    // arithmetic-limit error. Against the unfixed curve this fails here.
    assertFalse(
      !okQuote && bytes4(quoteRet) == SuppliesExceedArithmeticLimit.selector,
      "M-3: near-cap quoteBuy must not DoS with SuppliesExceedArithmeticLimit"
    );

    // This budget is provably in-domain (true answer ~0.4e33 -> sum 2.9e33 < 3e33),
    // so the ONLY correct outcome is a successful quote of a positive, in-domain
    // amount. A BudgetUpperBoundNotFound here would mean the clamp over-restricted
    // and starved a legitimate buy, so reject that too — don't let it pass as secure.
    assertTrue(okQuote, "secure: an in-domain near-cap buy must quote, not revert");
    (uint256 tokensMinted,,) = abi.decode(quoteRet, (uint256, uint256, uint256));
    assertGt(tokensMinted, 0, "secure: in-domain quote returns positive tokens");
    assertLe(
      NEAR_CAP_TRUST_SUPPLY + tokensMinted,
      pricing.MAX_SAFE_SUPPLY_SUM(),
      "secure: quoted amount stays within the arithmetic domain"
    );

    // --- openPosition (write path, EthosMarket.sol:519) ---
    address trustTokenAddr = _trustToken(marketId);
    uint256 buyerTokensBefore = PositionToken(trustTokenAddr).balanceOf(alice);

    vm.prank(alice);
    (bool okOpen, bytes memory openRet) = address(market)
      .call(abi.encodeWithSelector(market.openPosition.selector, marketId, true, buyerBudget, uint256(0)));

    assertFalse(
      !okOpen && bytes4(openRet) == SuppliesExceedArithmeticLimit.selector,
      "M-3: near-cap openPosition must not DoS with SuppliesExceedArithmeticLimit"
    );

    // Same reasoning as the quote path: an in-domain buy must execute and mint a
    // positive position — not revert, not no-op.
    assertTrue(okOpen, "secure: an in-domain near-cap buy must execute, not revert");
    assertGt(
      PositionToken(trustTokenAddr).balanceOf(alice),
      buyerTokensBefore,
      "secure: a successful buy mints a positive position"
    );

    // --- The SELL side must keep working in the same near-cap state ---
    // The market self-owns INITIAL_SUPPLY trust tokens; hand some to carol so she
    // has a real position to liquidate. (Sells subtract from supply -> never
    // overshoot the cap -> never DoS'd.)
    uint256 sellAmount = INITIAL_SUPPLY / 2; // 50e18, within the seeded supply
    vm.prank(address(market));
    PositionToken(trustTokenAddr).transfer(carol, sellAmount);
    assertEq(PositionToken(trustTokenAddr).balanceOf(carol), sellAmount, "seller holds a real position");

    (,, uint256 netCreditsOut,) = market.quoteSell(marketId, true, sellAmount, carol);
    assertGt(netCreditsOut, 0, "sell quote is finite and positive at near-cap supply");

    uint256 carolWhuffieBefore = whuffie.balanceOf(carol);
    vm.prank(carol);
    market.closePosition(marketId, true, sellAmount, 0);

    assertEq(PositionToken(trustTokenAddr).balanceOf(carol), 0, "seller's position burned");
    assertEq(
      whuffie.balanceOf(carol) - carolWhuffieBefore, netCreditsOut, "seller received exactly the quoted net payout"
    );
  }
}
