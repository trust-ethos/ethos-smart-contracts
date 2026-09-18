// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {Vm} from "forge-std/Vm.sol";
import {stdError} from "forge-std/StdError.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Burnable} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {AdaptiveLMSRPricing} from "../src/AdaptiveLMSRPricing.sol";
import {EthosMarket} from "../src/EthosMarket.sol";
import {PositionToken} from "../src/PositionToken.sol";
import {MarketPaused, PricingNotAllowed, SlippageExceeded, ZeroPayout} from "../src/errors/MarketErrors.sol";
import {LMSRTestConstants} from "./helpers/LMSRTestConstants.sol";
import {MarketStackFixture} from "./helpers/MarketStackFixture.sol";
import {MockPricingBase} from "./helpers/MockPricingBase.sol";

/// @dev Pricing contract that switches from a healthy linear curve to revert-on-every-call
///      after `setBroken(true)` is invoked. Lets us simulate a market that becomes orphaned
///      when its pricing strategy is decommissioned post-deploy.
contract ToggleablePricing is MockPricingBase {
  error PricingDecommissioned();

  bool public broken;

  function setBroken(bool b) external {
    broken = b;
  }

  function name() external pure override returns (string memory) {
    return "ToggleablePricing";
  }

  function getPrice(uint256, uint256, bool) external view override returns (uint256) {
    if (broken) revert PricingDecommissioned();
    return 1e17; // 0.1 WHUF/token
  }

  function getCost(uint256, uint256, bool, bool, uint256 amount) external view override returns (uint256) {
    if (broken) revert PricingDecommissioned();
    return amount / 10; // linear: 10% of amount
  }

  function getTokensForBudget(uint256, uint256, bool, uint256 budget) external view override returns (uint256) {
    if (broken) revert PricingDecommissioned();
    return budget * 10;
  }
}

/// @dev Fake spot prices with executable quotes; accounting must ignore `getPrice`.
contract MisleadingPricePricing is MockPricingBase {
  function name() external pure override returns (string memory) {
    return "MisleadingPricePricing";
  }

  function getPrice(uint256, uint256, bool isPositive) external pure override returns (uint256) {
    return isPositive ? type(uint256).max : 0;
  }

  function getCost(uint256, uint256, bool, bool, uint256 amount) external pure override returns (uint256) {
    return amount / 10;
  }

  function getTokensForBudget(uint256, uint256, bool, uint256 budget) external pure override returns (uint256) {
    return budget * 10;
  }
}

/// @dev Strategy that quotes sell revenue above market backing.
contract OverpayingSellPricing is MockPricingBase {
  function name() external pure override returns (string memory) {
    return "OverpayingSellPricing";
  }

  function getPrice(uint256, uint256, bool) external pure override returns (uint256) {
    return 0.5e18;
  }

  function getCost(uint256, uint256, bool, bool isBuy, uint256 amount) external pure override returns (uint256) {
    return isBuy ? amount : amount * 100;
  }

  function getTokensForBudget(uint256, uint256, bool, uint256 budget) external pure override returns (uint256) {
    return budget;
  }
}

/// @dev Strategy that can drain seeded backing if governance allows it.
contract SeedDrainingPricing is MockPricingBase {
  function name() external pure override returns (string memory) {
    return "SeedDrainingPricing";
  }

  function getPrice(uint256, uint256, bool) external pure override returns (uint256) {
    return 0.5e18;
  }

  function getCost(uint256, uint256, bool, bool, uint256 amount) external pure override returns (uint256) {
    return amount;
  }

  function getTokensForBudget(uint256, uint256, bool, uint256) external pure override returns (uint256) {
    return 1000e18;
  }
}

contract FeeOnTransferBurnableToken is ERC20Burnable {
  constructor() ERC20("FeeOnTransfer", "FEE") {}

  function mint(address to, uint256 amount) external {
    _mint(to, amount);
  }

  function _update(address from, address to, uint256 value) internal override {
    if (from == address(0) || to == address(0) || value == 0) {
      super._update(from, to, value);
      return;
    }

    uint256 fee = value / 100;
    super._update(from, address(0), fee);
    super._update(from, to, value - fee);
  }
}

/// @notice Integration tests covering EthosMarket + AdaptiveLMSRPricing.
/// @dev Deploys its own stack so AdaptiveLMSR is the only allowlisted pricing strategy.
contract EthosMarketAdaptiveLMSRTest is MarketStackFixture {
  uint256 constant B0 = LMSRTestConstants.B0;
  uint256 constant ALPHA = LMSRTestConstants.ALPHA;
  uint256 constant INITIAL_SUPPLY = 100e18;
  uint256 constant INITIAL_BACKING = 1000e18;
  uint256 internal constant CREATE_MARKET_ADMIN_GAS_CEILING = 4_000_000;
  uint256 internal constant PERMIT_USER_PRIVATE_KEY = 0xBEEFCAFE;
  bytes32 internal constant PERMIT_TYPEHASH =
    keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

  AdaptiveLMSRPricing internal pricing;

  struct SandwichWealth {
    uint256 uStart;
    uint256 vStart;
    uint256 supplyStart;
    uint256 contractStart;
    uint256 uEnd;
    uint256 vEnd;
    uint256 supplyEnd;
    uint256 contractEnd;
  }

  function setUp() public {
    _deployStack(INITIAL_SUPPLY);

    pricing = new AdaptiveLMSRPricing(B0, ALPHA);
    _setPricingAllowed(address(pricing), true);

    address[3] memory actors = [alice, bob, carol];
    for (uint256 i; i < actors.length; i++) {
      vm.prank(_owner);
      whuffie.mint(actors[i], 100_000e18);
      vm.prank(actors[i]);
      whuffie.approve(address(market), type(uint256).max);
    }

    // _admin needs funds + approval because every test calls createMarketAdmin via
    // _createLmsrMarket (which pranks as _admin), and _createMarket transferFrom's
    // initialBacking from msg.sender.
    vm.prank(_owner);
    whuffie.mint(_admin, 100_000e18);
    vm.prank(_admin);
    whuffie.approve(address(market), type(uint256).max);
  }

  function _createLmsrMarket(string memory userkey, string memory subjectName, uint256 initialBacking)
    internal
    returns (uint256 marketId)
  {
    vm.prank(_admin);
    market.createMarketAdmin(userkey, subjectName, initialBacking, address(pricing));
    marketId = market.marketCount();
  }

  function _sandwichWealthStart(address u, address v) internal view returns (SandwichWealth memory wealth) {
    wealth.uStart = whuffie.balanceOf(u);
    wealth.vStart = whuffie.balanceOf(v);
    wealth.supplyStart = whuffie.totalSupply();
    wealth.contractStart = whuffie.balanceOf(address(market));
  }

  function _sandwichWealthEnd(SandwichWealth memory wealth, address u, address v)
    internal
    view
    returns (SandwichWealth memory)
  {
    wealth.uEnd = whuffie.balanceOf(u);
    wealth.vEnd = whuffie.balanceOf(v);
    wealth.supplyEnd = whuffie.totalSupply();
    wealth.contractEnd = whuffie.balanceOf(address(market));
    return wealth;
  }

  function _assertSandwichWealthConserved(SandwichWealth memory wealth, bool assertMinimumULoss) internal pure {
    int256 uDelta = int256(wealth.uEnd) - int256(wealth.uStart);
    int256 vDelta = int256(wealth.vEnd) - int256(wealth.vStart);
    int256 contractDelta = int256(wealth.contractEnd) - int256(wealth.contractStart);
    uint256 burned = wealth.supplyStart - wealth.supplyEnd;
    assertEq(uDelta + vDelta + contractDelta, -int256(burned), "wealth not conserved");

    if (assertMinimumULoss) {
      assertLe(wealth.uEnd, wealth.uStart - 1e18, "U should lose at least the entry fee");
    }

    if (wealth.vEnd > wealth.vStart) {
      uint256 vGain = wealth.vEnd - wealth.vStart;
      uint256 othersLoss = uint256(-uDelta) + (contractDelta < 0 ? uint256(0) : uint256(contractDelta));
      assertLe(vGain, othersLoss + burned, "V gain exceeds others' loss: money created");
    }
  }

  function _assertClosedSequenceNoMoneyCreation(SandwichWealth memory wealth) internal pure {
    int256 actorDelta = int256(wealth.uEnd) - int256(wealth.uStart) + int256(wealth.vEnd) - int256(wealth.vStart);
    int256 contractDelta = int256(wealth.contractEnd) - int256(wealth.contractStart);
    uint256 burned = wealth.supplyStart - wealth.supplyEnd;

    assertEq(actorDelta + contractDelta, -int256(burned), "wealth not conserved");
    assertLe(wealth.uEnd + wealth.vEnd, wealth.uStart + wealth.vStart, "closed sequence created actor wealth");
  }

  function _permitSigner() internal pure returns (address) {
    return vm.addr(PERMIT_USER_PRIVATE_KEY);
  }

  function _fundPermitSigner() internal {
    vm.prank(_owner);
    whuffie.mint(_permitSigner(), 100_000e18);
  }

  function _signPermit(address owner_, uint256 ownerPk, address spender, uint256 value, uint256 deadline)
    internal
    view
    returns (uint8 v, bytes32 r, bytes32 s)
  {
    uint256 nonce = whuffie.nonces(owner_);
    bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner_, spender, value, nonce, deadline));
    bytes32 digest = MessageHashUtils.toTypedDataHash(whuffie.DOMAIN_SEPARATOR(), structHash);
    (v, r, s) = vm.sign(ownerPk, digest);
  }

  // --- Market creation under LMSR ---

  function test_createMarketAdmin_productionAdaptiveLmsrGasWithinBudget() public {
    vm.prank(_admin);
    uint256 gasBefore = gasleft();
    market.createMarketAdmin("address:0xLmsrGas", "lmsr-gas", INITIAL_BACKING, address(pricing));
    uint256 gasUsed = gasBefore - gasleft();

    assertEq(market.marketCount(), 1, "market created");
    assertLt(gasUsed, CREATE_MARKET_ADMIN_GAS_CEILING, "createMarketAdmin gas budget");
  }

  // --- Buys/sells under LMSR ---

  /// @notice Basic buy + sell on both sides under AdaptiveLMSR pricing.
  function test_buy_then_sell_each_side_succeeds() public {
    uint256 m = _createLmsrMarket("address:0xLmsr1", "lmsr1", INITIAL_BACKING);

    uint256 aliceTrust = _approveAndBuy(alice, m, true, 50e18);
    assertGt(aliceTrust, 0, "trust buy should mint tokens");

    uint256 bobDistrust = _approveAndBuy(bob, m, false, 50e18);
    assertGt(bobDistrust, 0, "distrust buy should mint tokens");

    vm.prank(alice);
    market.closePosition(m, true, aliceTrust, 0);
    assertEq(PositionToken(_trustToken(m)).balanceOf(alice), 0, "alice trust burned");

    vm.prank(bob);
    market.closePosition(m, false, bobDistrust, 0);
    assertEq(PositionToken(_distrustToken(m)).balanceOf(bob), 0, "bob distrust burned");

    _assertSolvent(m);
  }

  function testFuzz_buyAccounting_exact(uint256 paymentSeed, uint256 entryFeeSeed, bool isPositive) public {
    uint256 entryFeeBps = bound(entryFeeSeed, 0, market.MAX_PROTOCOL_FEE_BPS());
    vm.prank(_owner);
    market.setEntryFeeBasisPoints(entryFeeBps);

    uint256 m = _createLmsrMarket("address:0xLmsrBuyAccounting", "lmsr-buy-accounting", INITIAL_BACKING);
    uint256 payment = bound(paymentSeed, market.MIN_BUY(), 10_000e18);

    MarketSnapshot memory beforeTrade = _snapshot(m);
    uint256 whuffieSupplyBefore = whuffie.totalSupply();
    uint256 marketBalanceBefore = whuffie.balanceOf(address(market));
    uint256 buyerBalanceBefore = whuffie.balanceOf(alice);

    (uint256 quotedTokens,, uint256 entryFee) = market.quoteBuy(m, isPositive, payment);
    address tokenAddr = isPositive ? _trustToken(m) : _distrustToken(m);
    uint256 positionBalanceBefore = PositionToken(tokenAddr).balanceOf(alice);
    vm.prank(alice);
    market.openPosition(m, isPositive, payment, quotedTokens);
    uint256 minted = PositionToken(tokenAddr).balanceOf(alice) - positionBalanceBefore;
    MarketSnapshot memory afterTrade = _snapshot(m);

    assertEq(minted, quotedTokens, "buy minted exactly quoted tokens");
    assertEq(afterTrade.poolBacking, beforeTrade.poolBacking + payment - entryFee, "buy backing delta");
    assertEq(afterTrade.totalVolume, beforeTrade.totalVolume + payment, "buy volume delta");
    assertEq(whuffieSupplyBefore - whuffie.totalSupply(), entryFee, "entry fee burned once");
    assertEq(whuffie.balanceOf(address(market)), marketBalanceBefore + payment - entryFee, "market balance delta");
    assertEq(buyerBalanceBefore - whuffie.balanceOf(alice), payment, "buyer paid full amount");

    if (isPositive) {
      assertEq(afterTrade.trustSupply, beforeTrade.trustSupply + minted, "trust supply delta");
      assertEq(afterTrade.distrustSupply, beforeTrade.distrustSupply, "distrust supply unchanged");
    } else {
      assertEq(afterTrade.distrustSupply, beforeTrade.distrustSupply + minted, "distrust supply delta");
      assertEq(afterTrade.trustSupply, beforeTrade.trustSupply, "trust supply unchanged");
    }
  }

  function testFuzz_sellAccounting_exact(
    uint256 paymentSeed,
    uint256 entryFeeSeed,
    uint256 exitFeeSeed,
    bool isPositive
  ) public {
    uint256 entryFeeBps = bound(entryFeeSeed, 0, market.MAX_PROTOCOL_FEE_BPS());
    uint256 exitFeeBps = bound(exitFeeSeed, 0, market.MAX_PROTOCOL_FEE_BPS());
    vm.startPrank(_owner);
    market.setEntryFeeBasisPoints(entryFeeBps);
    market.setExitFeeBasisPoints(exitFeeBps);
    vm.stopPrank();

    uint256 m = _createLmsrMarket("address:0xLmsrSellAccounting", "lmsr-sell-accounting", INITIAL_BACKING);
    uint256 payment = bound(paymentSeed, 1e18, 10_000e18);
    uint256 minted = _approveAndBuy(alice, m, isPositive, payment);

    MarketSnapshot memory beforeTrade = _snapshot(m);
    uint256 whuffieSupplyBefore = whuffie.totalSupply();
    uint256 marketBalanceBefore = whuffie.balanceOf(address(market));
    uint256 sellerBalanceBefore = whuffie.balanceOf(alice);

    (uint256 curveRevenue, uint256 exitFee, uint256 netCreditsOut,) = market.quoteSell(m, isPositive, minted, alice);
    assertGt(netCreditsOut, 0, "full sell should have non-zero payout");

    vm.prank(alice);
    market.closePosition(m, isPositive, minted, netCreditsOut);
    MarketSnapshot memory afterTrade = _snapshot(m);

    assertEq(afterTrade.poolBacking, beforeTrade.poolBacking - curveRevenue, "sell backing delta");
    assertEq(afterTrade.totalVolume, beforeTrade.totalVolume, "sell does not change volume");
    assertEq(whuffieSupplyBefore - whuffie.totalSupply(), exitFee, "exit fee burned once");
    assertEq(whuffie.balanceOf(address(market)), marketBalanceBefore - curveRevenue, "market balance delta");
    assertEq(whuffie.balanceOf(alice) - sellerBalanceBefore, netCreditsOut, "seller received net payout");

    if (isPositive) {
      assertEq(afterTrade.trustSupply, beforeTrade.trustSupply - minted, "trust supply delta");
      assertEq(afterTrade.distrustSupply, beforeTrade.distrustSupply, "distrust supply unchanged");
      assertEq(PositionToken(afterTrade.trustToken).balanceOf(alice), 0, "trust position burned");
    } else {
      assertEq(afterTrade.distrustSupply, beforeTrade.distrustSupply - minted, "distrust supply delta");
      assertEq(afterTrade.trustSupply, beforeTrade.trustSupply, "trust supply unchanged");
      assertEq(PositionToken(afterTrade.distrustToken).balanceOf(alice), 0, "distrust position burned");
    }

    _assertSolvent(m);
  }

  function test_openPositionWithPermit_exactQuoteMinTokens_underLmsr() public {
    uint256 m = _createLmsrMarket("address:0xLmsrPermit", "lmsr-permit", INITIAL_BACKING);
    address user = _permitSigner();
    _fundPermitSigner();

    uint256 payment = 100e18;
    uint256 deadline = block.timestamp + 1 hours;
    (uint256 quotedTokens,,) = market.quoteBuy(m, true, payment);
    (uint8 v, bytes32 r, bytes32 s) = _signPermit(user, PERMIT_USER_PRIVATE_KEY, address(market), payment, deadline);

    PositionToken trustToken = PositionToken(_trustToken(m));
    uint256 balanceBefore = trustToken.balanceOf(user);

    vm.prank(user);
    market.openPositionWithPermit(m, true, payment, quotedTokens, deadline, v, r, s);

    assertEq(trustToken.balanceOf(user) - balanceBefore, quotedTokens, "permit path minted exact quoted tokens");
    assertEq(whuffie.allowance(user, address(market)), 0, "permit allowance consumed");
    _assertSolvent(m);
  }

  function test_directWhuffieTransfer_doesNotIncreasePoolBackingOrSellQuote() public {
    uint256 m = _createLmsrMarket("address:0xLmsrDirectTransfer", "lmsr-direct-transfer", INITIAL_BACKING);
    uint256 minted = _approveAndBuy(alice, m, true, 100e18);
    uint256 donation = 500e18;

    MarketSnapshot memory beforeDonation = _snapshot(m);
    (uint256 curveRevenueBefore,, uint256 netCreditsBefore,) = market.quoteSell(m, true, minted, alice);

    vm.prank(bob);
    whuffie.transfer(address(market), donation);

    MarketSnapshot memory afterDonation = _snapshot(m);
    (uint256 curveRevenueAfter,, uint256 netCreditsAfter,) = market.quoteSell(m, true, minted, alice);

    assertEq(afterDonation.poolBacking, beforeDonation.poolBacking, "direct transfer does not change backing");
    assertEq(curveRevenueAfter, curveRevenueBefore, "direct transfer does not change curve revenue");
    assertEq(netCreditsAfter, netCreditsBefore, "direct transfer does not change net sell quote");
    assertEq(
      whuffie.balanceOf(address(market)), afterDonation.poolBacking + donation, "direct transfer remains surplus"
    );

    vm.prank(alice);
    market.closePosition(m, true, minted, netCreditsBefore);

    MarketSnapshot memory afterSell = _snapshot(m);
    assertEq(
      whuffie.balanceOf(address(market)), afterSell.poolBacking + donation, "surplus remains outside market accounting"
    );
  }

  function test_feeOnTransferBackingToken_breaksAccounting_trustBoundary() public {
    FeeOnTransferBurnableToken feeToken = new FeeOnTransferBurnableToken();
    EthosMarket feeMarket = EthosMarket(_deployProxy(address(new EthosMarket())));
    feeMarket.initialize(_defaultInitParams(), address(feeToken), INITIAL_SUPPLY);

    vm.prank(_owner);
    feeMarket.setPricingAllowed(address(pricing), true);

    feeToken.mint(_admin, INITIAL_BACKING);
    vm.prank(_admin);
    feeToken.approve(address(feeMarket), INITIAL_BACKING);

    vm.prank(_admin);
    feeMarket.createMarketAdmin("address:0xFeeToken", "fee-token", INITIAL_BACKING, address(pricing));
    uint256 m = feeMarket.marketCount();

    uint256 poolBacking;
    (,,,,,,,, poolBacking,) = feeMarket.markets(m);

    assertEq(poolBacking, INITIAL_BACKING, "market records nominal transfer amount");
    assertLt(feeToken.balanceOf(address(feeMarket)), poolBacking, "fee-on-transfer token makes market insolvent");
  }

  // --- MarketUpdated emits prices from AdaptiveLMSR ---

  /// @notice After a trust-side buy, the emitted MarketUpdated event carries prices
  ///         fetched from the strategy: trust price > 0.5e18, distrust price < 0.5e18,
  ///         sum to ~1 WAD. Verifies via log decode that indexers see strategy values.
  function test_marketUpdated_emitsAdaptiveLMSRPrices() public {
    uint256 m = _createLmsrMarket("address:0xLmsrPrice", "lmsr-price", INITIAL_BACKING);

    vm.recordLogs();
    _approveAndBuy(alice, m, true, 50e18);

    bytes32 sig = keccak256("MarketUpdated(uint256,uint256,uint256,uint256,uint256,uint256)");
    Vm.Log[] memory logs = vm.getRecordedLogs();
    uint256 trustPrice;
    uint256 distrustPrice;
    bool found;
    for (uint256 i; i < logs.length; ++i) {
      if (logs[i].topics.length > 0 && logs[i].topics[0] == sig && uint256(logs[i].topics[1]) == m) {
        (,, trustPrice, distrustPrice,) = abi.decode(logs[i].data, (uint256, uint256, uint256, uint256, uint256));
        found = true;
      }
    }
    assertTrue(found, "MarketUpdated emitted for this market");

    assertGt(trustPrice, 0.5e18, "trust price > 0.5 after a trust buy");
    assertLt(distrustPrice, 0.5e18, "distrust price < 0.5 after a trust buy");
    assertApproxEqAbs(trustPrice + distrustPrice, 1e18, 2, "prices sum to ~1 WAD");
  }

  function test_misleadingGetPrice_doesNotAffectAccounting() public {
    MisleadingPricePricing misleading = new MisleadingPricePricing();
    vm.prank(_owner);
    market.setPricingAllowed(address(misleading), true);

    vm.prank(_admin);
    market.createMarketAdmin("address:0xMisleadingPrice", "misleading-price", INITIAL_BACKING, address(misleading));
    uint256 m = market.marketCount();

    uint256 aliceStart = whuffie.balanceOf(alice);
    uint256 minted = _approveAndBuy(alice, m, true, 100e18);
    MarketSnapshot memory afterBuy = _snapshot(m);

    assertEq(minted, 1000e18, "buy uses getTokensForBudget, not getPrice");
    assertEq(afterBuy.poolBacking, INITIAL_BACKING + 100e18, "pool backing follows payment amount");

    vm.prank(alice);
    market.closePosition(m, true, minted, 0);

    assertEq(whuffie.balanceOf(alice), aliceStart, "round trip follows getCost, not getPrice");
    assertEq(_snapshot(m).poolBacking, INITIAL_BACKING, "pool backing restored after sell");
  }

  // --- Stale quote slippage ---

  function test_staleBuyQuote_revertsAfterSameSideTradeMovesPrice() public {
    uint256 m = _createLmsrMarket("address:0xLmsrStaleBuy", "lmsr-stale-buy", INITIAL_BACKING);
    uint256 payment = 100e18;

    (uint256 quotedTokens,,) = market.quoteBuy(m, true, payment);
    _approveAndBuy(bob, m, true, 10_000e18);
    (uint256 currentTokens,,) = market.quoteBuy(m, true, payment);

    assertLt(currentTokens, quotedTokens, "same-side buy should make stale buy quote worse");

    vm.prank(alice);
    whuffie.approve(address(market), payment);
    vm.expectRevert(abi.encodeWithSelector(SlippageExceeded.selector, currentTokens, quotedTokens));
    vm.prank(alice);
    market.openPosition(m, true, payment, quotedTokens);
  }

  function test_staleSellQuote_revertsAfterOppositeSideTradeMovesPrice() public {
    uint256 m = _createLmsrMarket("address:0xLmsrStaleSell", "lmsr-stale-sell", INITIAL_BACKING);
    uint256 aliceTrust = _approveAndBuy(alice, m, true, 1_000e18);
    uint256 sellAmount = aliceTrust / 2;

    (,, uint256 quotedCredits,) = market.quoteSell(m, true, sellAmount, alice);
    _approveAndBuy(bob, m, false, 10_000e18);
    (,, uint256 currentCredits,) = market.quoteSell(m, true, sellAmount, alice);

    assertLt(currentCredits, quotedCredits, "opposite-side buy should make stale sell quote worse");

    vm.expectRevert(abi.encodeWithSelector(SlippageExceeded.selector, currentCredits, quotedCredits));
    vm.prank(alice);
    market.closePosition(m, true, sellAmount, quotedCredits);
  }

  function test_staleBuyQuote_revertsAfterEntryFeeIncrease() public {
    uint256 m = _createLmsrMarket("address:0xLmsrStaleBuyFee", "lmsr-stale-buy-fee", INITIAL_BACKING);
    uint256 payment = 100e18;
    uint256 maxFeeBps = market.MAX_PROTOCOL_FEE_BPS();

    (uint256 quotedTokens,,) = market.quoteBuy(m, true, payment);

    vm.prank(_owner);
    market.setEntryFeeBasisPoints(maxFeeBps);
    (uint256 currentTokens,,) = market.quoteBuy(m, true, payment);

    assertLt(currentTokens, quotedTokens, "entry fee increase should make stale buy quote worse");

    vm.prank(alice);
    whuffie.approve(address(market), payment);
    vm.expectRevert(abi.encodeWithSelector(SlippageExceeded.selector, currentTokens, quotedTokens));
    vm.prank(alice);
    market.openPosition(m, true, payment, quotedTokens);
  }

  function test_staleSellQuote_revertsAfterExitFeeIncrease() public {
    uint256 m = _createLmsrMarket("address:0xLmsrStaleSellFee", "lmsr-stale-sell-fee", INITIAL_BACKING);
    uint256 aliceTrust = _approveAndBuy(alice, m, true, 1_000e18);
    uint256 maxFeeBps = market.MAX_PROTOCOL_FEE_BPS();

    (,, uint256 quotedCredits,) = market.quoteSell(m, true, aliceTrust, alice);

    vm.prank(_owner);
    market.setExitFeeBasisPoints(maxFeeBps);
    (,, uint256 currentCredits,) = market.quoteSell(m, true, aliceTrust, alice);

    assertLt(currentCredits, quotedCredits, "exit fee increase should make stale sell quote worse");

    vm.expectRevert(abi.encodeWithSelector(SlippageExceeded.selector, currentCredits, quotedCredits));
    vm.prank(alice);
    market.closePosition(m, true, aliceTrust, quotedCredits);
  }

  // --- Cross-side sandwich slippage (safety: wealth conservation) ---

  /// @notice Cross-side sandwich: U buys trust, V buys distrust, U sells trust, V sells distrust.
  ///         Asserts contract solvency at every step and wealth conservation across the four trades.
  function test_sandwich_cross_side_solvent_and_wealthConserved() public {
    vm.startPrank(_owner);
    market.setEntryFeeBasisPoints(100); // 1 %
    market.setExitFeeBasisPoints(100);
    vm.stopPrank();

    uint256 m = _createLmsrMarket("address:0xLmsrSandwich", "lmsr-sandwich", INITIAL_BACKING);

    address U = alice;
    address V = bob;
    SandwichWealth memory wealth = _sandwichWealthStart(U, V);

    uint256 uTrust = _approveAndBuy(U, m, true, 100e18);
    _assertSolvent(m);

    uint256 vDistrust = _approveAndBuy(V, m, false, 100e18);
    _assertSolvent(m);

    vm.prank(U);
    market.closePosition(m, true, uTrust, 0);
    _assertSolvent(m);

    vm.prank(V);
    market.closePosition(m, false, vDistrust, 0);
    _assertSolvent(m);

    // Wealth conservation: burned fees are the only value leaving actors + contract.
    // U is harmed by at least the entry fee on U's buy (1 % of 100e18 = 1e18),
    // and V's profit is bounded by U's loss + contract gain + burned fees.
    _assertSandwichWealthConserved(_sandwichWealthEnd(wealth, U, V), true);
  }

  /// @notice Same-side sandwich: U buys trust → V buys trust → U sells trust → V sells trust.
  ///         Same safety bound: solvency + wealth conservation.
  function test_sandwich_same_side_solvent_and_wealthConserved() public {
    vm.startPrank(_owner);
    market.setEntryFeeBasisPoints(100);
    market.setExitFeeBasisPoints(100);
    vm.stopPrank();

    uint256 m = _createLmsrMarket("address:0xLmsrSandwich2", "lmsr-sandwich2", INITIAL_BACKING);

    address U = alice;
    address V = bob;
    SandwichWealth memory wealth = _sandwichWealthStart(U, V);

    uint256 uTrust = _approveAndBuy(U, m, true, 100e18);
    _assertSolvent(m);
    uint256 vTrust = _approveAndBuy(V, m, true, 100e18);
    _assertSolvent(m);

    vm.prank(U);
    market.closePosition(m, true, uTrust, 0);
    _assertSolvent(m);

    vm.prank(V);
    market.closePosition(m, true, vTrust, 0);
    _assertSolvent(m);

    // For same-side trades, the second buyer (V) pays a higher LMSR cost than the first
    // and sells at a lower one — so V should be harmed, not profit. Assert V is bounded.
    _assertSandwichWealthConserved(_sandwichWealthEnd(wealth, U, V), false);
  }

  function testFuzz_twoActorClosedSequence_noMoneyCreation(
    uint256 uPaymentSeed,
    uint256 vPaymentSeed,
    bool uSide,
    bool sameSide
  ) public {
    uint256 m = _createLmsrMarket("address:0xLmsrTwoActor", "lmsr-two-actor", INITIAL_BACKING);
    bool vSide = sameSide ? uSide : !uSide;
    uint256 uPayment = bound(uPaymentSeed, market.MIN_BUY(), 10_000e18);
    uint256 vPayment = bound(vPaymentSeed, market.MIN_BUY(), 10_000e18);
    SandwichWealth memory wealth = _sandwichWealthStart(alice, bob);

    {
      uint256 uTokens = _approveAndBuy(alice, m, uSide, uPayment);
      uint256 vTokens = _approveAndBuy(bob, m, vSide, vPayment);

      vm.prank(alice);
      market.closePosition(m, uSide, uTokens, 0);
      vm.prank(bob);
      market.closePosition(m, vSide, vTokens, 0);
    }

    _assertClosedSequenceNoMoneyCreation(_sandwichWealthEnd(wealth, alice, bob));
    _assertSolvent(m);
  }

  /// @notice Market MIN_BUY makes sub-WAD pricing dust unreachable through trades.
  function testFuzz_crossSideRoundTrip_viaMarket_noProfit(
    uint256 firstPaymentSeed,
    uint256 secondPaymentSeed,
    bool trustFirst
  ) public {
    uint256 m = _createLmsrMarket("address:0xLmsrRoundTrip", "lmsr-round-trip", INITIAL_BACKING);
    uint256 firstPayment = bound(firstPaymentSeed, market.MIN_BUY(), 10_000e18);
    uint256 secondPayment = bound(secondPaymentSeed, market.MIN_BUY(), 10_000e18);

    _assertCrossSideRoundTripNoProfit(m, firstPayment, secondPayment, trustFirst);
  }

  function testFuzz_crossSideRoundTrip_minInitialBacking_viaMarket_noProfit(
    uint256 firstPaymentSeed,
    uint256 secondPaymentSeed,
    bool trustFirst
  ) public {
    uint256 m = _createLmsrMarket("address:0xLmsrMinBacking", "lmsr-min-backing", market.MIN_BUY());
    uint256 firstPayment = bound(firstPaymentSeed, market.MIN_BUY(), 10_000e18);
    uint256 secondPayment = bound(secondPaymentSeed, market.MIN_BUY(), 10_000e18);

    _assertCrossSideRoundTripNoProfit(m, firstPayment, secondPayment, trustFirst);
  }

  function test_crossSideRoundTrip_minBuyDustLeg_viaMarket_noProfit() public {
    uint256 m = _createLmsrMarket("address:0xLmsrMinBuyDust", "lmsr-min-buy-dust", INITIAL_BACKING);

    _assertCrossSideRoundTripNoProfit(m, 80e18, market.MIN_BUY(), true);
    _assertCrossSideRoundTripNoProfit(m, 80e18, market.MIN_BUY(), false);
  }

  function _assertCrossSideRoundTripNoProfit(
    uint256 marketId,
    uint256 firstPayment,
    uint256 secondPayment,
    bool trustFirst
  ) internal {
    bool firstSide = trustFirst;
    bool secondSide = !trustFirst;

    uint256 startBalance = whuffie.balanceOf(alice);
    uint256 firstTokens = _approveAndBuy(alice, marketId, firstSide, firstPayment);
    uint256 secondTokens = _approveAndBuy(alice, marketId, secondSide, secondPayment);

    vm.prank(alice);
    market.closePosition(marketId, firstSide, firstTokens, 0);
    vm.prank(alice);
    market.closePosition(marketId, secondSide, secondTokens, 0);

    assertLe(whuffie.balanceOf(alice), startBalance, "market round trip created Whuffie");
    _assertSolvent(marketId);
  }

  // --- Orphaned-market admin pause ---

  /// @notice A market pinned to a pricing contract that later reverts is dead-on-arrival.
  ///         Trades revert with the strategy's error. De-allowlisting doesn't unpin the
  ///         existing market (pricingContract is immutable per market) — admin pause is
  ///         the only recourse to halt further deposit attempts. Funds remain stuck.
  function test_orphanedMarket_revertingPricingTrapsFunds_onlyAdminPauseRecourse() public {
    // 1. Deploy + allowlist a pricing contract that initially works.
    ToggleablePricing toggleable = new ToggleablePricing();
    vm.prank(_owner);
    market.setPricingAllowed(address(toggleable), true);

    // 2. Create a market with the toggleable pricing contract; alice opens a position.
    uint256 aliceStart = whuffie.balanceOf(alice);
    vm.prank(_admin);
    market.createMarketAdmin("address:0xOrphan", "orphan", INITIAL_BACKING, address(toggleable));
    uint256 m = market.marketCount();
    vm.prank(alice);
    market.openPosition(m, true, 100e18, 0);
    uint256 aliceAfterOpen = whuffie.balanceOf(alice);
    uint256 marketAfterOpen = whuffie.balanceOf(address(market));
    assertLt(aliceAfterOpen, aliceStart, "alice spent whuffie to open position");

    // 3. Decommission the pricing contract — it now reverts on every priced call.
    toggleable.setBroken(true);

    // 4. Subsequent trades revert with the strategy's error.
    vm.expectRevert(ToggleablePricing.PricingDecommissioned.selector);
    vm.prank(bob);
    market.openPosition(m, true, 10e18, 0);
    vm.expectRevert(ToggleablePricing.PricingDecommissioned.selector);
    vm.prank(alice);
    market.closePosition(m, true, 1e18, 0);

    // Funds are trapped: alice's whuffie balance is unchanged from before the failed
    // sell, and the market still holds her backing.
    assertEq(whuffie.balanceOf(alice), aliceAfterOpen, "alice cannot recover whuffie via sell");
    assertEq(whuffie.balanceOf(address(market)), marketAfterOpen, "market still holds alice's backing");

    // 5. De-allowlist the broken pricing contract — existing market's pricingContract
    //    field is unchanged (immutable per market); only future market creation is blocked.
    vm.prank(_owner);
    market.setPricingAllowed(address(toggleable), false);
    vm.prank(_admin);
    vm.expectRevert(abi.encodeWithSelector(PricingNotAllowed.selector, address(toggleable)));
    market.createMarketAdmin("address:0xNoOrphan", "no-orphan", INITIAL_BACKING, address(toggleable));

    // 6. Admin pause is the only recourse — post-pause, trades revert cleanly with MarketPaused
    //    (early check before any pricing call).
    vm.prank(_admin);
    market.setMarketPauseState(m, EthosMarket.PauseState.PAUSED);
    vm.expectRevert(abi.encodeWithSelector(MarketPaused.selector, m));
    vm.prank(alice);
    market.openPosition(m, true, 10e18, 0);
    vm.expectRevert(abi.encodeWithSelector(MarketPaused.selector, m));
    vm.prank(alice);
    market.closePosition(m, true, 1e18, 0);
  }

  function test_pricingDeallowlist_blocksNewMarkets_butExistingMarketKeepsPinnedStrategy() public {
    uint256 existing = _createLmsrMarket("address:0xLmsrPinned", "lmsr-pinned", INITIAL_BACKING);

    vm.prank(_owner);
    market.setPricingAllowed(address(pricing), false);

    vm.expectRevert(abi.encodeWithSelector(PricingNotAllowed.selector, address(pricing)));
    vm.prank(_admin);
    market.createMarketAdmin("address:0xLmsrBlocked", "lmsr-blocked", INITIAL_BACKING, address(pricing));

    uint256 minted = _approveAndBuy(alice, existing, true, 100e18);
    assertGt(minted, 0, "existing pinned market can still buy");

    vm.prank(alice);
    market.closePosition(existing, true, minted, 0);
    _assertSolvent(existing);
  }

  function test_maliciousPricing_sellQuoteAboveBacking_revertsBeforeTransfer() public {
    OverpayingSellPricing overpaying = new OverpayingSellPricing();
    vm.prank(_owner);
    market.setPricingAllowed(address(overpaying), true);

    vm.prank(_admin);
    market.createMarketAdmin("address:0xOverpaying", "overpaying", INITIAL_BACKING, address(overpaying));
    uint256 m = market.marketCount();

    uint256 minted = _approveAndBuy(alice, m, true, 100e18);
    uint256 aliceBefore = whuffie.balanceOf(alice);
    uint256 marketBefore = whuffie.balanceOf(address(market));
    uint256 poolBefore = _snapshot(m).poolBacking;

    vm.expectRevert(stdError.arithmeticError);
    vm.prank(alice);
    market.closePosition(m, true, minted, 0);

    assertEq(whuffie.balanceOf(alice), aliceBefore, "seller received no transfer");
    assertEq(whuffie.balanceOf(address(market)), marketBefore, "market balance unchanged");
    assertEq(_snapshot(m).poolBacking, poolBefore, "pool backing unchanged");
    assertEq(PositionToken(_trustToken(m)).balanceOf(alice), minted, "position not burned");
    _assertSolvent(m);
  }

  function test_maliciousAllowedPricing_canDrainSeedBacking_trustBoundary() public {
    SeedDrainingPricing draining = new SeedDrainingPricing();
    vm.prank(_owner);
    market.setPricingAllowed(address(draining), true);

    vm.prank(_admin);
    market.createMarketAdmin("address:0xDraining", "draining", INITIAL_BACKING, address(draining));
    uint256 m = market.marketCount();

    uint256 aliceStart = whuffie.balanceOf(alice);
    uint256 minted = _approveAndBuy(alice, m, true, market.MIN_BUY());
    assertEq(minted, INITIAL_BACKING, "malicious strategy minted seed-sized position");

    vm.prank(alice);
    market.closePosition(m, true, minted, 0);

    assertGt(whuffie.balanceOf(alice), aliceStart, "allowlisted malicious pricing drained backing");
    assertEq(_snapshot(m).poolBacking, market.MIN_BUY(), "only attacker's payment remains backing the market");
    _assertSolvent(m);
  }

  // --- ZeroPayout interaction across qt = qd boundary ---

  /// @notice Tiny sells across the qt=qd symmetric boundary: at the symmetric state
  ///         a 1-wei sell yields a near-zero curve revenue. If the post-fee net payout
  ///         collapses to 0, `closePosition` reverts ZeroPayout.
  ///         Pins the contract-favorable interaction between LMSR rounding and the
  ///         ZeroPayout guard.
  function test_tinySell_acrossNeutralBoundary_revertsZeroPayout_or_solventPayout() public {
    uint256 m = _createLmsrMarket("address:0xLmsrTinySell", "lmsr-tiny-sell", INITIAL_BACKING);

    // Mint a small position on the trust side so we have units to attempt to sell.
    uint256 aliceTrust = _approveAndBuy(alice, m, true, 10e18);
    assertGt(aliceTrust, 0, "alice has trust tokens to sell");

    // Mint a small position on the opposite side to exercise the balanced-market path.
    _approveAndBuy(bob, m, false, 10e18);

    // Try to sell 1 wei. The curve revenue at this scale rounds to ~0; either the call
    // reverts ZeroPayout (preferred contract-favorable outcome) or it succeeds and
    // pays a positive net amount. Other revert reasons fail the test.
    vm.prank(alice);
    try market.closePosition(m, true, 1, 0) {}
    catch (bytes memory reason) {
      assertEq(bytes4(reason), ZeroPayout.selector, "tiny sell must revert ZeroPayout, not another error");
    }
    _assertSolvent(m);
  }

  function test_liquidationReplay_zeroPayoutDustCannotMutateSupplyOrCreateWealth() public {
    uint256 m = _createLmsrMarket("address:0xLmsrReplayZeroPayout", "lmsr-replay-zero-payout", 100e18);
    uint256 carolPayment = 50_000_000e18 + 5;
    uint256 bobPayment = market.MIN_BUY();
    uint256 transferredTrust = 51_966;

    vm.prank(_owner);
    whuffie.mint(carol, 1e30);
    vm.prank(_owner);
    whuffie.mint(bob, 1e30);

    uint256 traderStart = whuffie.balanceOf(bob) + whuffie.balanceOf(carol);

    uint256 carolTrust = _approveAndBuy(carol, m, true, carolPayment);
    uint256 bobDistrust = _approveAndBuy(bob, m, false, bobPayment);
    assertGt(carolTrust, transferredTrust, "replay setup needs transferable dust");

    address trustToken = _trustToken(m);
    vm.prank(carol);
    assertTrue(PositionToken(trustToken).transfer(bob, transferredTrust), "dust transfer failed");

    uint256 trustSupplyBeforeDustSell = _snapshot(m).trustSupply;
    (,, uint256 dustPayout,) = market.quoteSell(m, true, transferredTrust, bob);
    assertEq(dustPayout, 0, "dust sell should not be executable");

    vm.expectRevert(ZeroPayout.selector);
    vm.prank(bob);
    market.closePosition(m, true, transferredTrust, 0);
    assertEq(_snapshot(m).trustSupply, trustSupplyBeforeDustSell, "zero-payout sell mutated trust supply");

    vm.prank(bob);
    market.closePosition(m, false, bobDistrust, 0);
    vm.prank(carol);
    market.closePosition(m, true, carolTrust - transferredTrust, 0);

    (,, uint256 finalDustPayout,) = market.quoteSell(m, true, transferredTrust, bob);
    if (finalDustPayout > 0) {
      vm.prank(bob);
      market.closePosition(m, true, transferredTrust, 0);
    }

    assertLe(whuffie.balanceOf(bob) + whuffie.balanceOf(carol), traderStart, "valid liquidation created wealth");
    _assertSolvent(m);
  }

  function test_liquidationReplay_abandonedDustProfitBoundedByStrandedDust() public {
    uint256 m = _createLmsrMarket("address:0xLmsrReplayDustBound", "lmsr-replay-dust-bound", 100e18);
    uint256 payment = 50_000_000e18 + 746;
    uint256 transferredTrust = 1_100;

    vm.prank(_owner);
    whuffie.mint(alice, 1e30);
    vm.prank(_owner);
    whuffie.mint(carol, 1e30);

    uint256 traderStart = whuffie.balanceOf(alice) + whuffie.balanceOf(carol);

    uint256 aliceTrust = _approveAndBuy(alice, m, true, payment);
    assertGt(aliceTrust, transferredTrust, "replay setup needs transferable dust");

    address trustToken = _trustToken(m);
    vm.prank(alice);
    assertTrue(PositionToken(trustToken).transfer(carol, transferredTrust), "dust transfer failed");

    vm.prank(alice);
    market.closePosition(m, true, aliceTrust - transferredTrust, 0);

    (,, uint256 dustPayout,) = market.quoteSell(m, true, transferredTrust, carol);
    assertEq(dustPayout, 0, "stranded dust should not be executable");

    uint256 traderEnd = whuffie.balanceOf(alice) + whuffie.balanceOf(carol);
    uint256 excess = traderEnd - traderStart;
    assertGt(excess, 0, "replay should expose the abandoned-dust rounding residual");
    assertLe(excess, transferredTrust * 2, "profit must stay bounded by stranded dust");
    _assertSolvent(m);
  }
}
