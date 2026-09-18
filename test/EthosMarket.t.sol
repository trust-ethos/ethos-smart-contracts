// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {EthosMarket} from "../src/EthosMarket.sol";
import {PositionToken} from "../src/PositionToken.sol";
import {SignatureControl} from "../src/utils/SignatureControl.sol";
import {ETHOS_MARKET} from "../src/utils/Constants.sol";
import {
  AmountBelowMinimum,
  FeeBpsTooHigh,
  InsufficientPositionTokens,
  MarketAlreadyExists,
  MarketDoesNotExist,
  MarketPaused,
  MarketSellOnly,
  PricingNotAllowed,
  SlippageExceeded,
  TokenNotBurnable,
  ZeroInitialSupply,
  ZeroPayout,
  ZeroSellAmount,
  ZeroTokensMinted
} from "../src/errors/MarketErrors.sol";
import {Vm} from "forge-std/Vm.sol";
import {TransferToMarket} from "../src/errors/PositionTokenErrors.sol";
import {SignatureExpired} from "../src/errors/SignatureErrors.sol";
import {MarketTestFixture} from "./helpers/MarketTestFixture.sol";
import {MockPricingBase} from "./helpers/MockPricingBase.sol";

/// @dev Mock pricing that always returns 0 tokens for any budget.
contract ZeroTokenPricing is MockPricingBase {
  function name() external pure override returns (string memory) {
    return "ZeroTokenPricing";
  }

  function getPrice(uint256, uint256, bool) external pure override returns (uint256) {
    return 0;
  }

  function getCost(uint256, uint256, bool, bool, uint256) external pure override returns (uint256) {
    return 0;
  }

  function getTokensForBudget(uint256, uint256, bool, uint256) external pure override returns (uint256) {
    return 0;
  }
}

/// @dev Mock pricing that reverts on getPrice but otherwise behaves like a 1:1 mint/burn curve.
///      Used to exercise EthosMarket._emitMarketUpdated's try/catch and the paired
///      MarketUpdateFailed event without breaking the trade path.
contract RevertingGetPricePricing is MockPricingBase {
  error PriceUnavailable();

  function name() external pure override returns (string memory) {
    return "RevertingGetPricePricing";
  }

  function getPrice(uint256, uint256, bool) external pure override returns (uint256) {
    revert PriceUnavailable();
  }
}

/// @dev Mock pricing that mints tokens 1:1 on buy and returns 1 wei curve revenue on any sell.
///      Used to construct the M-3 audit case: fees collapse the 1-wei revenue to zero payout.
contract DustSellPricing is MockPricingBase {
  function name() external pure override returns (string memory) {
    return "DustSellPricing";
  }

  function getPrice(uint256, uint256, bool) external pure override returns (uint256) {
    return 1;
  }

  function getCost(uint256, uint256, bool, bool isBuy, uint256 amount) external pure override returns (uint256) {
    return isBuy ? amount : 1;
  }
}

contract NonBurnableToken is ERC20 {
  constructor() ERC20("NonBurnable", "NB") {}
}

contract EthosMarketTest is MarketTestFixture {
  uint256 public constant INITIAL_BACKING = 1000e18;
  uint256 public constant INITIAL_SUPPLY = 100e18;
  string public constant USERKEY = "address:0xAlice";
  bytes32 public constant USERKEY_HASH = keccak256(bytes(USERKEY));
  string public constant SUBJECT_NAME = "Alice";

  function setUp() public {
    _deployMarketStack(INITIAL_SUPPLY);

    address[] memory actors = new address[](4);
    actors[0] = alice;
    actors[1] = bob;
    actors[2] = carol;
    actors[3] = _admin;
    _fundActors(actors, 100_000e18);

    vm.prank(_admin);
    whuffie.approve(address(market), type(uint256).max);
  }

  // --- Helpers ---

  function _createMarket() internal returns (uint256 marketId) {
    return _createMarketAdmin(USERKEY, SUBJECT_NAME, INITIAL_BACKING);
  }

  // --- Initialization ---

  function test_initialize_sets_roles() public view {
    assertTrue(market.hasRole(market.OWNER_ROLE(), _owner));
    assertTrue(market.hasRole(market.ADMIN_ROLE(), _admin));
  }

  function test_initialize_sets_token() public view {
    assertEq(address(market.token()), address(whuffie));
  }

  function test_initialize_sets_initialSupply() public view {
    assertEq(market.initialSupplyPerSide(), INITIAL_SUPPLY);
  }

  function test_initialize_sets_marketCount() public view {
    assertEq(market.marketCount(), 0);
  }

  function test_initialize_sets_version() public view {
    assertEq(market.VERSION(), 1);
  }

  function test_initialize_reverts_on_double_init() public {
    vm.expectRevert(Initializable.InvalidInitialization.selector);
    market.initialize(_defaultInitParams(), address(whuffie), INITIAL_SUPPLY);
  }

  function test_initialize_reverts_on_zero_token() public {
    EthosMarket m = EthosMarket(_deployProxy(address(new EthosMarket())));
    vm.expectRevert(SignatureControl.ZeroAddress.selector);
    m.initialize(_defaultInitParams(), address(0), INITIAL_SUPPLY);
  }

  function test_initialize_reverts_on_zero_supply() public {
    EthosMarket m = EthosMarket(_deployProxy(address(new EthosMarket())));
    vm.expectRevert(ZeroInitialSupply.selector);
    m.initialize(_defaultInitParams(), address(whuffie), 0);
  }

  function test_initialize_reverts_on_non_burnable_token() public {
    NonBurnableToken nonBurnable = new NonBurnableToken();
    EthosMarket m = EthosMarket(_deployProxy(address(new EthosMarket())));
    vm.expectRevert(abi.encodeWithSelector(TokenNotBurnable.selector, address(nonBurnable)));
    m.initialize(_defaultInitParams(), address(nonBurnable), INITIAL_SUPPLY);
  }

  // --- Market creation ---

  function test_createMarketAdmin_succeeds() public {
    uint256 id = _createMarket();
    assertEq(id, 1);

    MarketSnapshot memory s = _snapshot(id);
    assertTrue(s.exists);
    assertEq(s.userkeyHash, USERKEY_HASH);
  }

  function test_createMarketAdmin_deploysPositionTokens() public {
    uint256 id = _createMarket();
    MarketSnapshot memory s = _snapshot(id);
    assertTrue(s.trustToken != address(0));
    assertTrue(s.distrustToken != address(0));
    assertTrue(s.trustToken != s.distrustToken);
  }

  function test_createMarketAdmin_mintsInitialSupplyToContract() public {
    uint256 id = _createMarket();
    MarketSnapshot memory s = _snapshot(id);
    assertEq(PositionToken(s.trustToken).balanceOf(address(market)), INITIAL_SUPPLY);
    assertEq(PositionToken(s.distrustToken).balanceOf(address(market)), INITIAL_SUPPLY);
  }

  function test_createMarketAdmin_pullsInitialBacking() public {
    uint256 adminBalBefore = whuffie.balanceOf(_admin);
    _createMarket();
    assertEq(whuffie.balanceOf(_admin), adminBalBefore - INITIAL_BACKING);
    assertEq(whuffie.balanceOf(address(market)), INITIAL_BACKING);
  }

  function test_createMarketAdmin_revertsOnDuplicateUserkeyHash() public {
    _createMarket();
    vm.expectRevert(abi.encodeWithSelector(MarketAlreadyExists.selector, USERKEY_HASH));
    vm.prank(_admin);
    market.createMarketAdmin(USERKEY, SUBJECT_NAME, INITIAL_BACKING, address(pricing));
  }

  function test_createMarketAdmin_revertsOnUnallowedPricing() public {
    address fake = address(0xDEAD);
    vm.expectRevert(abi.encodeWithSelector(PricingNotAllowed.selector, fake));
    vm.prank(_admin);
    market.createMarketAdmin("other", "Other", INITIAL_BACKING, fake);
  }

  function test_createMarketAdmin_revertsOnDustBacking() public {
    vm.expectRevert(abi.encodeWithSelector(AmountBelowMinimum.selector, 0, market.MIN_BUY()));
    vm.prank(_admin);
    market.createMarketAdmin("other", "Other", 0, address(pricing));
  }

  function test_createMarketAdmin_revertsForNonAdmin() public {
    vm.expectRevert(
      abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, alice, market.ADMIN_ROLE())
    );
    vm.prank(alice);
    market.createMarketAdmin(USERKEY, SUBJECT_NAME, INITIAL_BACKING, address(pricing));
  }

  function test_createMarketAdmin_emitsMarketCreated() public {
    vm.recordLogs();
    vm.prank(_admin);
    market.createMarketAdmin(USERKEY, SUBJECT_NAME, INITIAL_BACKING, address(pricing));

    Vm.Log[] memory logs = vm.getRecordedLogs();
    // MarketCreated is the first event emitted by _createMarket
    bytes32 expectedSig = keccak256("MarketCreated(uint256,bytes32,address,address,address,address,string)");
    bool found = false;

    for (uint256 i = 0; i < logs.length; i++) {
      if (logs[i].topics[0] == expectedSig) {
        // Verify indexed topics
        assertEq(logs[i].topics[1], bytes32(uint256(1))); // marketId = 1
        assertEq(logs[i].topics[2], USERKEY_HASH);
        // Decode non-indexed data to verify userkey string
        (,,, string memory userkey) = abi.decode(logs[i].data, (address, address, address, string));
        assertEq(userkey, USERKEY);
        found = true;
        break;
      }
    }

    assertTrue(found, "MarketCreated event not emitted");
  }

  // --- Buy (openPosition) ---

  function test_buy_mintsTokensToBuyer() public {
    uint256 id = _createMarket();
    uint256 minted = _approveAndBuy(alice, id, true, 50e18);
    assertGt(minted, 0);
    assertEq(PositionToken(_trustToken(id)).balanceOf(alice), minted);
  }

  function test_buy_increasesTrustSupply() public {
    uint256 id = _createMarket();
    uint256 supplyBefore = _snapshot(id).trustSupply;
    uint256 minted = _approveAndBuy(alice, id, true, 50e18);
    assertEq(_snapshot(id).trustSupply, supplyBefore + minted);
  }

  function test_buy_increasesPoolBacking() public {
    uint256 id = _createMarket();
    uint256 backingBefore = _snapshot(id).poolBacking;
    _approveAndBuy(alice, id, true, 50e18);
    assertGt(_snapshot(id).poolBacking, backingBefore);
  }

  function test_buy_revertsOnDustAmount() public {
    uint256 id = _createMarket();
    vm.prank(alice);
    whuffie.approve(address(market), 1e14);
    vm.expectRevert(abi.encodeWithSelector(AmountBelowMinimum.selector, 1e14, market.MIN_BUY()));
    vm.prank(alice);
    market.openPosition(id, true, 1e14, 0);
  }

  function test_buy_revertsOnZeroAmount() public {
    uint256 id = _createMarket();
    vm.expectRevert(abi.encodeWithSelector(AmountBelowMinimum.selector, 0, market.MIN_BUY()));
    vm.prank(alice);
    market.openPosition(id, true, 0, 0);
  }

  function test_buy_revertsOnZeroTokensMinted() public {
    ZeroTokenPricing zeroPricing = new ZeroTokenPricing();
    vm.prank(_owner);
    market.setPricingAllowed(address(zeroPricing), true);

    vm.prank(_admin);
    whuffie.approve(address(market), INITIAL_BACKING);
    vm.prank(_admin);
    market.createMarketAdmin("zero", "Zero", INITIAL_BACKING, address(zeroPricing));
    uint256 id = market.marketCount();

    vm.prank(alice);
    whuffie.approve(address(market), 50e18);
    vm.expectRevert(abi.encodeWithSelector(ZeroTokensMinted.selector, 50e18));
    vm.prank(alice);
    market.openPosition(id, true, 50e18, 0);
  }

  function test_buy_revertsOnSlippage() public {
    uint256 id = _createMarket();
    vm.prank(alice);
    whuffie.approve(address(market), 50e18);
    (uint256 expectedTokens,,) = market.quoteBuy(id, true, 50e18);
    vm.expectRevert(abi.encodeWithSelector(SlippageExceeded.selector, expectedTokens, type(uint256).max));
    vm.prank(alice);
    market.openPosition(id, true, 50e18, type(uint256).max);
  }

  function test_buy_revertsOnNonExistentMarket() public {
    vm.expectRevert(abi.encodeWithSelector(MarketDoesNotExist.selector, 999));
    vm.prank(alice);
    market.openPosition(999, true, 50e18, 0);
  }

  function test_buy_solvencyMaintained() public {
    uint256 id = _createMarket();
    _approveAndBuy(alice, id, true, 50e18);
    _approveAndBuy(bob, id, false, 30e18);
    _assertMarketBacked(id);
  }

  // --- Sell (closePosition) ---

  function test_sell_returnsCredits() public {
    uint256 id = _createMarket();
    uint256 minted = _approveAndBuy(alice, id, true, 50e18);

    uint256 aliceBalBefore = whuffie.balanceOf(alice);
    vm.prank(alice);
    market.closePosition(id, true, minted, 0);

    assertGt(whuffie.balanceOf(alice), aliceBalBefore);
  }

  function test_sell_burnsPositionTokens() public {
    uint256 id = _createMarket();
    uint256 minted = _approveAndBuy(alice, id, true, 50e18);

    vm.prank(alice);
    market.closePosition(id, true, minted, 0);

    assertEq(PositionToken(_trustToken(id)).balanceOf(alice), 0);
  }

  function test_sell_decreasesTrustSupply() public {
    uint256 id = _createMarket();
    uint256 minted = _approveAndBuy(alice, id, true, 50e18);
    uint256 supplyBefore = _snapshot(id).trustSupply;

    vm.prank(alice);
    market.closePosition(id, true, minted, 0);

    assertEq(_snapshot(id).trustSupply, supplyBefore - minted);
  }

  function test_sell_revertsOnInsufficientTokens() public {
    uint256 id = _createMarket();
    uint256 minted = _approveAndBuy(alice, id, true, 50e18);

    vm.expectRevert(abi.encodeWithSelector(InsufficientPositionTokens.selector, minted, type(uint256).max));
    vm.prank(alice);
    market.closePosition(id, true, type(uint256).max, 0);
  }

  function test_sell_revertsOnSlippage() public {
    uint256 id = _createMarket();
    uint256 minted = _approveAndBuy(alice, id, true, 50e18);

    (,, uint256 expectedCredits,) = market.quoteSell(id, true, minted, alice);
    vm.expectRevert(abi.encodeWithSelector(SlippageExceeded.selector, expectedCredits, type(uint256).max));
    vm.prank(alice);
    market.closePosition(id, true, minted, type(uint256).max);
  }

  function test_sell_revertsOnNonExistentMarket() public {
    vm.expectRevert(abi.encodeWithSelector(MarketDoesNotExist.selector, 999));
    vm.prank(alice);
    market.closePosition(999, true, 1e18, 0);
  }

  function test_sell_revertsOnZeroAmount() public {
    uint256 id = _createMarket();
    vm.expectRevert(ZeroSellAmount.selector);
    vm.prank(alice);
    market.closePosition(id, true, 0, 0);
  }

  function test_buyThenSell_returnsLessThanSpent() public {
    uint256 id = _createMarket();
    uint256 spend = 100e18;
    uint256 aliceBalBefore = whuffie.balanceOf(alice);
    uint256 minted = _approveAndBuy(alice, id, true, spend);
    vm.prank(alice);
    market.closePosition(id, true, minted, 0);
    assertLt(whuffie.balanceOf(alice), aliceBalBefore, "round-trip should cost credits (fees)");
  }

  function test_sell_solvencyMaintained() public {
    uint256 id = _createMarket();
    uint256 aMinted = _approveAndBuy(alice, id, true, 100e18);
    uint256 bMinted = _approveAndBuy(bob, id, false, 80e18);

    vm.prank(alice);
    market.closePosition(id, true, aMinted, 0);
    vm.prank(bob);
    market.closePosition(id, false, bMinted, 0);

    _assertMarketBacked(id);
  }

  /// @dev Transferring position tokens to the market contract itself is rejected
  ///      because the market contract already holds the locked supply floor.
  function test_transfer_revertsWhenToIsMarket() public {
    uint256 id = _createMarket();
    uint256 aliceMinted = _approveAndBuy(alice, id, true, 100e18);

    address trustAddr = _trustToken(id);
    vm.prank(alice);
    vm.expectRevert(TransferToMarket.selector);
    PositionToken(trustAddr).transfer(address(market), aliceMinted);
  }

  // --- Protocol fees ---

  function test_entryFee_burnsWhuffie() public {
    vm.prank(_owner);
    market.setEntryFeeBasisPoints(100); // 1 %

    uint256 id = _createMarket();
    uint256 payment = 100e18;
    (,, uint256 expectedFee) = market.quoteBuy(id, true, payment);

    uint256 supplyBefore = whuffie.totalSupply();
    uint256 recipientBefore = whuffie.balanceOf(feeRecipient);
    uint256 backingBefore = _snapshot(id).poolBacking;
    _approveAndBuy(alice, id, true, payment);

    assertEq(supplyBefore - whuffie.totalSupply(), expectedFee);
    assertEq(whuffie.balanceOf(feeRecipient), recipientBefore);
    assertEq(_snapshot(id).poolBacking, backingBefore + payment - expectedFee);
  }

  function test_exitFee_burnsWhuffie() public {
    uint256 id = _createMarket();
    uint256 minted = _approveAndBuy(alice, id, true, 100e18);

    vm.prank(_owner);
    market.setExitFeeBasisPoints(200); // 2 %

    (uint256 curveRevenue, uint256 expectedFee,,) = market.quoteSell(id, true, minted, alice);

    uint256 supplyBefore = whuffie.totalSupply();
    uint256 recipientBefore = whuffie.balanceOf(feeRecipient);
    uint256 backingBefore = _snapshot(id).poolBacking;
    vm.prank(alice);
    market.closePosition(id, true, minted, 0);

    assertEq(supplyBefore - whuffie.totalSupply(), expectedFee);
    assertEq(whuffie.balanceOf(feeRecipient), recipientBefore);
    assertEq(_snapshot(id).poolBacking, backingBefore - curveRevenue);
  }

  function test_setEntryFee_revertsAboveMax() public {
    uint256 max = market.MAX_PROTOCOL_FEE_BPS();
    vm.expectRevert(abi.encodeWithSelector(FeeBpsTooHigh.selector, max + 1, max));
    vm.prank(_owner);
    market.setEntryFeeBasisPoints(max + 1);
  }

  function test_setExitFee_revertsAboveMax() public {
    uint256 max = market.MAX_PROTOCOL_FEE_BPS();
    vm.expectRevert(abi.encodeWithSelector(FeeBpsTooHigh.selector, max + 1, max));
    vm.prank(_owner);
    market.setExitFeeBasisPoints(max + 1);
  }

  // --- Per-market pause states ---

  function test_pause_blocksOpenAndClose() public {
    uint256 id = _createMarket();
    uint256 minted = _approveAndBuy(alice, id, true, 50e18);

    vm.prank(_admin);
    market.setMarketPauseState(id, EthosMarket.PauseState.PAUSED);

    vm.prank(alice);
    whuffie.approve(address(market), 50e18);
    vm.expectRevert(abi.encodeWithSelector(MarketPaused.selector, id));
    vm.prank(alice);
    market.openPosition(id, true, 50e18, 0);

    vm.expectRevert(abi.encodeWithSelector(MarketPaused.selector, id));
    vm.prank(alice);
    market.closePosition(id, true, minted, 0);
  }

  function test_sellOnly_blocksOpenAllowsClose() public {
    uint256 id = _createMarket();
    uint256 minted = _approveAndBuy(alice, id, true, 50e18);

    vm.prank(_admin);
    market.setMarketPauseState(id, EthosMarket.PauseState.SELL_ONLY);

    vm.prank(alice);
    whuffie.approve(address(market), 50e18);
    vm.expectRevert(abi.encodeWithSelector(MarketSellOnly.selector, id));
    vm.prank(alice);
    market.openPosition(id, true, 50e18, 0);

    // closePosition should succeed
    vm.prank(alice);
    market.closePosition(id, true, minted, 0);
  }

  function test_active_allowsAll() public {
    uint256 id = _createMarket();
    uint256 minted = _approveAndBuy(alice, id, true, 50e18);

    vm.prank(_admin);
    market.setMarketPauseState(id, EthosMarket.PauseState.ACTIVE);

    uint256 minted2 = _approveAndBuy(alice, id, true, 50e18);
    assertGt(minted2, 0);

    vm.prank(alice);
    market.closePosition(id, true, minted, 0);
  }

  function test_pauseState_revertsForNonAdmin() public {
    uint256 id = _createMarket();
    vm.expectRevert();
    vm.prank(alice);
    market.setMarketPauseState(id, EthosMarket.PauseState.PAUSED);
  }

  // --- Global pause (InteractionControl) ---

  function test_globalPause_blocksOpenPosition() public {
    uint256 id = _createMarket();
    _pauseContract(ETHOS_MARKET);

    vm.prank(alice);
    whuffie.approve(address(market), 50e18);
    vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
    vm.prank(alice);
    market.openPosition(id, true, 50e18, 0);
  }

  function test_globalPause_blocksClosePosition() public {
    uint256 id = _createMarket();
    uint256 minted = _approveAndBuy(alice, id, true, 50e18);

    _pauseContract(ETHOS_MARKET);

    vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
    vm.prank(alice);
    market.closePosition(id, true, minted, 0);
  }

  function test_globalPause_blocksCreateMarket() public {
    _pauseContract(ETHOS_MARKET);

    vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
    vm.prank(_admin);
    market.createMarketAdmin(USERKEY, SUBJECT_NAME, INITIAL_BACKING, address(pricing));
  }

  function test_globalUnpause_restoresTrading() public {
    uint256 id = _createMarket();
    _pauseContract(ETHOS_MARKET);
    _unpauseContract(ETHOS_MARKET);

    uint256 minted = _approveAndBuy(alice, id, true, 50e18);
    assertGt(minted, 0);
  }

  // --- Quote functions ---

  function test_quoteBuy_matchesActualBuy() public {
    uint256 id = _createMarket();
    uint256 payment = 50e18;

    (uint256 qTokens, uint256 qPrice, uint256 qProtocol) = market.quoteBuy(id, true, payment);

    assertGt(qTokens, 0);
    assertEq(qProtocol, 0); // no entry fee set

    uint256 actualMinted = _approveAndBuy(alice, id, true, payment);
    assertEq(actualMinted, qTokens, "quote should match actual");
    assertGt(qPrice, 0);
  }

  function test_quoteSell_matchesActualSell() public {
    uint256 id = _createMarket();
    uint256 minted = _approveAndBuy(alice, id, true, 50e18);

    (,, uint256 totalOut,) = market.quoteSell(id, true, minted, alice);

    uint256 aliceBefore = whuffie.balanceOf(alice);
    vm.prank(alice);
    market.closePosition(id, true, minted, 0);

    assertEq(whuffie.balanceOf(alice) - aliceBefore, totalOut, "quote should match actual payout");
  }

  function test_quoteBuy_zeroAmount() public {
    uint256 id = _createMarket();
    (uint256 t, uint256 p, uint256 pf) = market.quoteBuy(id, true, 0);
    assertEq(t, 0);
    assertEq(p, 0);
    assertEq(pf, 0);
  }

  function test_quoteBuy_belowMinimumReturnsZeros() public {
    uint256 id = _createMarket();
    uint256 dustPayment = market.MIN_BUY() - 1;

    (uint256 t, uint256 p, uint256 pf) = market.quoteBuy(id, true, dustPayment);

    assertEq(t, 0);
    assertEq(p, 0);
    assertEq(pf, 0);
  }

  function test_quoteSell_zeroAmount() public {
    uint256 id = _createMarket();
    (uint256 curveRev, uint256 exitFee, uint256 totalOut, uint256 price) = market.quoteSell(id, true, 0, alice);
    assertEq(curveRev, 0);
    assertEq(exitFee, 0);
    assertEq(totalOut, 0);
    assertEq(price, 0);
  }

  // --- UUPS upgrade ---

  function test_upgrade_preservesStorage() public {
    uint256 id = _createMarket();
    _approveAndBuy(alice, id, true, 50e18);

    uint256 trustSupplyBefore = _snapshot(id).trustSupply;

    EthosMarket newImpl = new EthosMarket();
    vm.prank(_owner);
    market.upgradeToAndCall(address(newImpl), "");

    assertEq(_snapshot(id).trustSupply, trustSupplyBefore);
  }

  function test_upgrade_revertsForNonOwner() public {
    EthosMarket newImpl = new EthosMarket();
    vm.expectRevert();
    vm.prank(alice);
    market.upgradeToAndCall(address(newImpl), "");
  }

  // --- Admin configuration ---

  function test_setPricingAllowed_toggles() public {
    assertFalse(market.pricingAllowed(address(0xBEEF)));
    vm.prank(_owner);
    market.setPricingAllowed(address(0xBEEF), true);
    assertTrue(market.pricingAllowed(address(0xBEEF)));
    vm.prank(_owner);
    market.setPricingAllowed(address(0xBEEF), false);
    assertFalse(market.pricingAllowed(address(0xBEEF)));
  }

  function test_feeSetters_revertForNonOwner() public {
    vm.expectRevert();
    vm.prank(alice);
    market.setEntryFeeBasisPoints(100);

    vm.expectRevert();
    vm.prank(alice);
    market.setExitFeeBasisPoints(100);
  }

  function test_pricingAllowed_revertsForNonOwner() public {
    vm.expectRevert();
    vm.prank(alice);
    market.setPricingAllowed(address(pricing), true);
  }

  // --- Multiple markets ---

  function test_multipleMarkets_independentState() public {
    vm.prank(_admin);
    market.createMarketAdmin("subject1", "Subject1", INITIAL_BACKING, address(pricing));
    vm.prank(_admin);
    market.createMarketAdmin("subject2", "Subject2", INITIAL_BACKING, address(pricing));

    _approveAndBuy(alice, 1, true, 100e18);
    _approveAndBuy(bob, 2, false, 100e18);

    MarketSnapshot memory m1 = _snapshot(1);
    MarketSnapshot memory m2 = _snapshot(2);

    assertGt(m1.trustSupply, INITIAL_SUPPLY);
    assertEq(m1.distrustSupply, INITIAL_SUPPLY);
    assertEq(m2.trustSupply, INITIAL_SUPPLY);
    assertGt(m2.distrustSupply, INITIAL_SUPPLY);

    _assertMarketBacked(1);
    _assertMarketBacked(2);
    _assertGloballySolvent();
  }

  // --- Fuzz ---

  function testFuzz_solvency(uint256 buyAmount, uint256 sellFraction) public {
    buyAmount = bound(buyAmount, market.MIN_BUY(), 10_000e18);
    sellFraction = bound(sellFraction, 1, 100);

    uint256 id = _createMarket();
    uint256 minted = _approveAndBuy(carol, id, true, buyAmount);

    uint256 sellAmount = (minted * sellFraction) / 100;
    if (sellAmount == 0) sellAmount = 1;

    vm.prank(carol);
    market.closePosition(id, true, sellAmount, 0);

    _assertMarketBacked(id);
  }

  function testFuzz_buyCostMonotone(uint256 amountA, uint256 amountB) public {
    amountA = bound(amountA, market.MIN_BUY(), 1_000e18);
    amountB = bound(amountB, market.MIN_BUY(), 1_000e18);

    uint256 id = _createMarket();

    (uint256 tokensA,,) = market.quoteBuy(id, true, amountA);
    (uint256 tokensB,,) = market.quoteBuy(id, true, amountB);

    if (amountA < amountB) {
      assertLe(tokensA, tokensB, "more credits should buy at least as many tokens");
    } else if (amountA > amountB) {
      assertGe(tokensA, tokensB);
    }
  }

  // --- Signature-gated market creation (createMarket) ---

  function test_createMarket_succeeds() public {
    uint256 id = _createMarketWithSig(alice, USERKEY, SUBJECT_NAME, INITIAL_BACKING, 1);
    assertEq(id, 1);

    MarketSnapshot memory s = _snapshot(id);
    assertTrue(s.exists);
    assertEq(s.userkeyHash, USERKEY_HASH);
  }

  function test_createMarket_setsCorrectTokenNames() public {
    uint256 id = _createMarketWithSig(alice, USERKEY, "vitalik.eth", INITIAL_BACKING, 1);
    PositionToken t = PositionToken(_trustToken(id));
    PositionToken d = PositionToken(_distrustToken(id));
    assertEq(t.name(), "Trust: vitalik.eth");
    assertEq(t.symbol(), "TRUST-vitalik.eth");
    assertEq(d.name(), "Distrust: vitalik.eth");
    assertEq(d.symbol(), "DISTRUST-vitalik.eth");
  }

  function test_createMarket_revertsOnExpiredSignature() public {
    uint256 deadline = block.timestamp - 1;
    bytes memory sig = _signCreateMarket(alice, USERKEY, SUBJECT_NAME, INITIAL_BACKING, address(pricing), deadline, 1);

    vm.prank(alice);
    whuffie.approve(address(market), INITIAL_BACKING);
    vm.expectRevert(abi.encodeWithSelector(SignatureExpired.selector, deadline, block.timestamp));
    vm.prank(alice);
    market.createMarket(USERKEY, SUBJECT_NAME, INITIAL_BACKING, address(pricing), deadline, 1, sig);
  }

  function test_createMarket_revertsOnReplayedSignature() public {
    // Generate signature manually so we can re-use the exact bytes
    uint256 deadline = block.timestamp + 1 hours;
    bytes memory sig = _signCreateMarket(alice, USERKEY, SUBJECT_NAME, INITIAL_BACKING, address(pricing), deadline, 1);

    // First call succeeds
    vm.prank(alice);
    whuffie.approve(address(market), INITIAL_BACKING * 2);
    vm.prank(alice);
    market.createMarket(USERKEY, SUBJECT_NAME, INITIAL_BACKING, address(pricing), deadline, 1, sig);

    // Same signature bytes — should revert (signatureUsed check fires before userkeyHashUsed)
    vm.expectRevert(SignatureControl.SignatureWasUsed.selector);
    vm.prank(alice);
    market.createMarket(USERKEY, SUBJECT_NAME, INITIAL_BACKING, address(pricing), deadline, 1, sig);
  }

  function test_createMarket_revertsOnWrongCaller() public {
    uint256 deadline = block.timestamp + 1 hours;
    bytes memory sig = _signCreateMarket(alice, USERKEY, SUBJECT_NAME, INITIAL_BACKING, address(pricing), deadline, 1);

    vm.prank(bob);
    whuffie.approve(address(market), INITIAL_BACKING);
    vm.expectRevert(SignatureControl.InvalidSignature.selector);
    vm.prank(bob);
    market.createMarket(USERKEY, SUBJECT_NAME, INITIAL_BACKING, address(pricing), deadline, 1, sig);
  }

  function test_createMarket_revertsOnDuplicateUserkeyHash() public {
    _createMarketWithSig(alice, USERKEY, SUBJECT_NAME, INITIAL_BACKING, 1);

    uint256 deadline = block.timestamp + 1 hours;
    bytes memory sig = _signCreateMarket(alice, USERKEY, SUBJECT_NAME, INITIAL_BACKING, address(pricing), deadline, 2);

    vm.prank(alice);
    whuffie.approve(address(market), INITIAL_BACKING);
    vm.expectRevert(abi.encodeWithSelector(MarketAlreadyExists.selector, USERKEY_HASH));
    vm.prank(alice);
    market.createMarket(USERKEY, SUBJECT_NAME, INITIAL_BACKING, address(pricing), deadline, 2, sig);
  }

  function test_createMarket_revertsWhenGloballyPaused() public {
    _pauseContract(ETHOS_MARKET);

    uint256 deadline = block.timestamp + 1 hours;
    bytes memory sig = _signCreateMarket(alice, USERKEY, SUBJECT_NAME, INITIAL_BACKING, address(pricing), deadline, 1);

    vm.prank(alice);
    whuffie.approve(address(market), INITIAL_BACKING);
    vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
    vm.prank(alice);
    market.createMarket(USERKEY, SUBJECT_NAME, INITIAL_BACKING, address(pricing), deadline, 1, sig);
  }

  function test_createMarketAdmin_stillWorks() public {
    uint256 id = _createMarket();
    assertEq(id, 1);
    assertTrue(_snapshot(id).exists);
  }

  // --- Distrust-side trading ---

  function test_buy_distrust_mintsTokens() public {
    uint256 id = _createMarket();
    uint256 minted = _approveAndBuy(alice, id, false, 50e18);
    assertGt(minted, 0);
    assertEq(PositionToken(_distrustToken(id)).balanceOf(alice), minted);
  }

  function test_sell_distrust_returnsCredits() public {
    uint256 id = _createMarket();
    uint256 minted = _approveAndBuy(alice, id, false, 50e18);

    uint256 aliceBalBefore = whuffie.balanceOf(alice);
    vm.prank(alice);
    market.closePosition(id, false, minted, 0);

    assertGt(whuffie.balanceOf(alice), aliceBalBefore);
    assertEq(PositionToken(_distrustToken(id)).balanceOf(alice), 0);
    _assertMarketBacked(id);
  }

  // --- Transferred token sell ---

  function test_transferredToken_sellWorks() public {
    uint256 id = _createMarket();
    uint256 minted = _approveAndBuy(alice, id, true, 50_000e18);
    assertGt(minted, 1, "need at least 2 tokens for transfer test");
    uint256 half = minted / 2;
    address trustAddr = _trustToken(id);

    // Alice transfers half to Bob
    vm.prank(alice);
    PositionToken(trustAddr).transfer(bob, half);
    assertEq(PositionToken(trustAddr).balanceOf(bob), half);

    // Bob sells the transferred tokens
    uint256 bobBefore = whuffie.balanceOf(bob);
    vm.prank(bob);
    market.closePosition(id, true, half, 0);

    assertGt(whuffie.balanceOf(bob) - bobBefore, 0);
    _assertMarketBacked(id);
  }

  // --- quoteSell with exit fees ---

  function test_quoteSell_matchesActualSell_withExitFee() public {
    uint256 id = _createMarket();
    uint256 minted = _approveAndBuy(alice, id, true, 100e18);

    vm.prank(_owner);
    market.setExitFeeBasisPoints(200); // 2%

    (,, uint256 totalOut,) = market.quoteSell(id, true, minted, alice);

    uint256 aliceBefore = whuffie.balanceOf(alice);
    vm.prank(alice);
    market.closePosition(id, true, minted, 0);

    assertEq(whuffie.balanceOf(alice) - aliceBefore, totalOut, "quote should match actual with exit fee");
  }

  // --- setMarketPauseState on non-existent market ---

  function test_pauseState_revertsOnNonExistentMarket() public {
    vm.expectRevert(abi.encodeWithSelector(MarketDoesNotExist.selector, 999));
    vm.prank(_admin);
    market.setMarketPauseState(999, EthosMarket.PauseState.PAUSED);
  }

  // --- quoteBuy/quoteSell on non-existent market ---

  function test_quoteBuy_revertsOnNonExistentMarket() public {
    vm.expectRevert(abi.encodeWithSelector(MarketDoesNotExist.selector, 999));
    market.quoteBuy(999, true, 50e18);
  }

  function test_quoteSell_revertsOnNonExistentMarket() public {
    vm.expectRevert(abi.encodeWithSelector(MarketDoesNotExist.selector, 999));
    market.quoteSell(999, true, 1e18, alice);
  }

  // --- Event emissions for admin setters ---

  function test_setEntryFee_emitsEvent() public {
    vm.expectEmit(false, false, false, true);
    emit EthosMarket.EntryFeeUpdated(100);
    vm.prank(_owner);
    market.setEntryFeeBasisPoints(100);
  }

  function test_setExitFee_emitsEvent() public {
    vm.expectEmit(false, false, false, true);
    emit EthosMarket.ExitFeeUpdated(200);
    vm.prank(_owner);
    market.setExitFeeBasisPoints(200);
  }

  function test_setPricingAllowed_emitsEvent() public {
    vm.expectEmit(true, false, false, true);
    emit EthosMarket.PricingAllowlistUpdated(address(0xBEEF), true);
    vm.prank(_owner);
    market.setPricingAllowed(address(0xBEEF), true);
  }

  // --- Max fee boundary combos ---

  function test_maxFees_buyStillWorks() public {
    uint256 maxProto = market.MAX_PROTOCOL_FEE_BPS();
    vm.prank(_owner);
    market.setEntryFeeBasisPoints(maxProto);

    uint256 id = _createMarket();
    uint256 minted = _approveAndBuy(alice, id, true, 100e18);
    assertGt(minted, 0, "should still mint tokens at max fees");
    _assertMarketBacked(id);
  }

  function test_maxFees_minBuy_stillWorks() public {
    uint256 maxProto = market.MAX_PROTOCOL_FEE_BPS();
    vm.prank(_owner);
    market.setEntryFeeBasisPoints(maxProto);

    uint256 id = _createMarket();
    uint256 minted = _approveAndBuy(alice, id, true, market.MIN_BUY());
    assertGt(minted, 0, "MIN_BUY should still mint tokens at max fees");
    _assertMarketBacked(id);
  }

  function test_maxFees_sellStillWorks() public {
    uint256 maxProto = market.MAX_PROTOCOL_FEE_BPS();
    vm.prank(_owner);
    market.setEntryFeeBasisPoints(maxProto);
    vm.prank(_owner);
    market.setExitFeeBasisPoints(maxProto);

    uint256 id = _createMarket();

    uint256 aliceTrust = _approveAndBuy(alice, id, true, 100e18);
    _approveAndBuy(bob, id, false, 50e18);

    // Sell at max fees.
    vm.prank(alice);
    market.closePosition(id, true, aliceTrust, 0);

    _assertMarketBacked(id);
  }

  // --- Transfer edge cases ---

  function test_quoteSell_insufficientBalance_returnsZeros() public {
    uint256 id = _createMarket();
    _approveAndBuy(alice, id, true, 50e18);

    // Bob has no tokens — quoteSell should return all zeros
    (uint256 cr, uint256 ef, uint256 net, uint256 p) = market.quoteSell(id, true, 1e18, bob);
    assertEq(cr, 0);
    assertEq(ef, 0);
    assertEq(net, 0);
    assertEq(p, 0);
  }

  function test_quoteSell_insufficientBalanceAboveSupply_returnsZeros() public {
    uint256 id = _createMarket();
    _approveAndBuy(alice, id, true, 50e18);

    uint256 amountAboveSupply = _snapshot(id).trustSupply + 1;
    (uint256 cr, uint256 ef, uint256 net, uint256 p) = market.quoteSell(id, true, amountAboveSupply, bob);

    assertEq(cr, 0);
    assertEq(ef, 0);
    assertEq(net, 0);
    assertEq(p, 0);
  }

  function test_transfer_worksWhileMarketPaused() public {
    uint256 id = _createMarket();
    uint256 aliceMinted = _approveAndBuy(alice, id, true, 100e18);

    // Pause the market
    vm.prank(_admin);
    market.setMarketPauseState(id, EthosMarket.PauseState.PAUSED);

    // Transfer should still work while trading is paused.
    address trustAddr = _trustToken(id);
    vm.prank(alice);
    PositionToken(trustAddr).transfer(bob, aliceMinted);

    // Unpause and verify Bob can sell the transferred position.
    vm.prank(_admin);
    market.setMarketPauseState(id, EthosMarket.PauseState.ACTIVE);

    vm.prank(bob);
    market.closePosition(id, true, aliceMinted, 0);
    assertGt(whuffie.balanceOf(bob), 0, "Bob received payout after pause");
    _assertMarketBacked(id);
  }

  // --- openPositionWithPermit ---

  /// @dev Private key for permit-signing actor.
  uint256 internal constant PERMIT_USER_PRIVATE_KEY = 0xBEEFCAFE;

  /// @dev EIP-2612 permit typehash.
  bytes32 internal constant PERMIT_TYPEHASH =
    keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

  function _permitSigner() internal pure returns (address) {
    return vm.addr(PERMIT_USER_PRIVATE_KEY);
  }

  function _setupPermitSigner() internal {
    address[] memory actors = new address[](1);
    actors[0] = _permitSigner();
    _fundActors(actors, 100_000e18);
  }

  /// @dev Build and sign an EIP-2612 permit for the Whuffie token.
  function _signPermit(address owner_, uint256 ownerPk, address spender, uint256 value, uint256 deadline)
    internal
    view
    returns (uint8 v, bytes32 r, bytes32 s)
  {
    uint256 nonce = whuffie.nonces(owner_);

    bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner_, spender, value, nonce, deadline));
    bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), whuffie.DOMAIN_SEPARATOR(), structHash));

    (v, r, s) = vm.sign(ownerPk, digest);
  }

  function test_openPositionWithPermit_mintsTokens() public {
    uint256 id = _createMarket();
    address user = _permitSigner();
    _setupPermitSigner();

    uint256 buyAmount = 50e18;
    uint256 deadline = block.timestamp + 1 hours;
    (uint8 v, bytes32 r, bytes32 s) = _signPermit(user, PERMIT_USER_PRIVATE_KEY, address(market), buyAmount, deadline);

    address tokenAddr = _trustToken(id);
    uint256 balBefore = PositionToken(tokenAddr).balanceOf(user);

    vm.prank(user);
    market.openPositionWithPermit(id, true, buyAmount, 0, deadline, v, r, s);

    uint256 balAfter = PositionToken(tokenAddr).balanceOf(user);
    assertGt(balAfter, balBefore, "should have minted position tokens");
    // Allowance should have been consumed
    assertEq(whuffie.allowance(user, address(market)), 0, "allowance consumed");
  }

  function test_openPositionWithPermit_worksWithPreApproval() public {
    uint256 id = _createMarket();
    address user = _permitSigner();
    _setupPermitSigner();

    uint256 buyAmount = 50e18;

    // Pre-approve instead of using permit
    vm.prank(user);
    whuffie.approve(address(market), buyAmount);

    // Use a dead signature (0 values) — permit will fail, but pre-approval makes it work
    vm.prank(user);
    market.openPositionWithPermit(id, true, buyAmount, 0, 0, 0, bytes32(0), bytes32(0));

    assertGt(PositionToken(_trustToken(id)).balanceOf(user), 0, "should have minted via pre-approval");
  }

  function test_openPositionWithPermit_emitsPositionOpened() public {
    uint256 id = _createMarket();
    address user = _permitSigner();
    _setupPermitSigner();

    uint256 buyAmount = 50e18;
    uint256 deadline = block.timestamp + 1 hours;
    (uint8 v, bytes32 r, bytes32 s) = _signPermit(user, PERMIT_USER_PRIVATE_KEY, address(market), buyAmount, deadline);

    vm.expectEmit(true, true, true, false);
    emit EthosMarket.PositionOpened(id, user, true, buyAmount, 0);

    vm.prank(user);
    market.openPositionWithPermit(id, true, buyAmount, 0, deadline, v, r, s);
  }

  function test_openPositionWithPermit_revertsWithExpiredDeadline() public {
    uint256 id = _createMarket();
    address user = _permitSigner();
    _setupPermitSigner();

    uint256 buyAmount = 50e18;
    uint256 deadline = block.timestamp - 1;
    (uint8 v, bytes32 r, bytes32 s) = _signPermit(user, PERMIT_USER_PRIVATE_KEY, address(market), buyAmount, deadline);

    // Permit fails (expired), no pre-approval → transferFrom reverts
    vm.prank(user);
    vm.expectRevert();
    market.openPositionWithPermit(id, true, buyAmount, 0, deadline, v, r, s);
  }

  function test_openPositionWithPermit_revertsWithWrongAmount() public {
    uint256 id = _createMarket();
    address user = _permitSigner();
    _setupPermitSigner();

    uint256 buyAmount = 50e18;
    uint256 deadline = block.timestamp + 1 hours;
    // Sign permit for half the amount
    (uint8 v, bytes32 r, bytes32 s) =
      _signPermit(user, PERMIT_USER_PRIVATE_KEY, address(market), buyAmount / 2, deadline);

    // Permit sets allowance to half → transferFrom reverts on full amount
    vm.prank(user);
    vm.expectRevert();
    market.openPositionWithPermit(id, true, buyAmount, 0, deadline, v, r, s);
  }

  function test_openPositionWithPermit_revertsOnSlippage() public {
    uint256 id = _createMarket();
    address user = _permitSigner();
    _setupPermitSigner();

    uint256 buyAmount = 50e18;
    uint256 deadline = block.timestamp + 1 hours;
    (uint8 v, bytes32 r, bytes32 s) = _signPermit(user, PERMIT_USER_PRIVATE_KEY, address(market), buyAmount, deadline);

    // Set minTokensOut impossibly high to trigger slippage
    vm.prank(user);
    vm.expectRevert();
    market.openPositionWithPermit(id, true, buyAmount, type(uint256).max, deadline, v, r, s);
  }

  function test_openPositionWithPermit_revertsWhenMarketPaused() public {
    uint256 id = _createMarket();
    address user = _permitSigner();
    _setupPermitSigner();

    vm.prank(_admin);
    market.setMarketPauseState(id, EthosMarket.PauseState.PAUSED);

    uint256 buyAmount = 50e18;
    uint256 deadline = block.timestamp + 1 hours;
    (uint8 v, bytes32 r, bytes32 s) = _signPermit(user, PERMIT_USER_PRIVATE_KEY, address(market), buyAmount, deadline);

    vm.prank(user);
    vm.expectRevert(abi.encodeWithSelector(MarketPaused.selector, id));
    market.openPositionWithPermit(id, true, buyAmount, 0, deadline, v, r, s);
  }

  function test_openPositionWithPermit_revertsWhenSellOnly() public {
    uint256 id = _createMarket();
    address user = _permitSigner();
    _setupPermitSigner();

    vm.prank(_admin);
    market.setMarketPauseState(id, EthosMarket.PauseState.SELL_ONLY);

    uint256 buyAmount = 50e18;
    uint256 deadline = block.timestamp + 1 hours;
    (uint8 v, bytes32 r, bytes32 s) = _signPermit(user, PERMIT_USER_PRIVATE_KEY, address(market), buyAmount, deadline);

    vm.prank(user);
    vm.expectRevert(abi.encodeWithSelector(MarketSellOnly.selector, id));
    market.openPositionWithPermit(id, true, buyAmount, 0, deadline, v, r, s);
  }

  function test_openPositionWithPermit_revertsOnReplay() public {
    uint256 id = _createMarket();
    address user = _permitSigner();
    _setupPermitSigner();

    uint256 buyAmount = 50e18;
    uint256 deadline = block.timestamp + 1 hours;
    (uint8 v, bytes32 r, bytes32 s) = _signPermit(user, PERMIT_USER_PRIVATE_KEY, address(market), buyAmount, deadline);

    // First call succeeds
    vm.prank(user);
    market.openPositionWithPermit(id, true, buyAmount, 0, deadline, v, r, s);

    // Second call with same signature: permit fails (nonce consumed), no remaining allowance → reverts
    vm.prank(user);
    vm.expectRevert();
    market.openPositionWithPermit(id, true, buyAmount, 0, deadline, v, r, s);
  }

  /// @dev Permit succeeds (valid signature) but transferFrom reverts because
  /// the signer has zero WHUF balance. Confirms the revert surfaces as a
  /// balance error — not an allowance error — which was the symptom of the
  /// silent-permit-failure bug fixed in the E2E pass (wrong EIP-712 domain).
  ///
  /// The starting-zero-allowance precondition closes the loophole where a
  /// pre-existing allowance could mask a silent permit failure: if permit
  /// didn't set the allowance, transferFrom would surface `ERC20InsufficientAllowance`
  /// and this test's exact-selector `expectRevert` would fail.
  function test_openPositionWithPermit_revertsWithInsufficientBalance() public {
    uint256 id = _createMarket();
    address user = _permitSigner();
    // Intentionally skip _setupPermitSigner — user has 0 WHUF.

    uint256 buyAmount = 50e18;
    uint256 deadline = block.timestamp + 1 hours;
    (uint8 v, bytes32 r, bytes32 s) = _signPermit(user, PERMIT_USER_PRIVATE_KEY, address(market), buyAmount, deadline);

    assertEq(whuffie.allowance(user, address(market)), 0, "no pre-existing allowance");

    vm.prank(user);
    vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InsufficientBalance.selector, user, 0, buyAmount));
    market.openPositionWithPermit(id, true, buyAmount, 0, deadline, v, r, s);
  }

  /// @dev Two fresh permits with consecutive nonces both succeed. Guards
  /// against off-chain nonce readers staying stuck on a stale value after
  /// the first tx lands.
  function test_openPositionWithPermit_successiveCallsUseIncrementingNonces() public {
    uint256 id = _createMarket();
    address user = _permitSigner();
    _setupPermitSigner();
    PositionToken trustToken = PositionToken(_trustToken(id));

    uint256 buyAmount = 50e18;
    uint256 deadline = block.timestamp + 1 hours;
    uint256 nonceBefore = whuffie.nonces(user);
    uint256 balBefore = trustToken.balanceOf(user);

    (uint8 v1, bytes32 r1, bytes32 s1) =
      _signPermit(user, PERMIT_USER_PRIVATE_KEY, address(market), buyAmount, deadline);
    vm.prank(user);
    market.openPositionWithPermit(id, true, buyAmount, 0, deadline, v1, r1, s1);
    assertEq(whuffie.nonces(user), nonceBefore + 1, "nonce incremented after first call");
    uint256 balAfter1 = trustToken.balanceOf(user);
    assertGt(balAfter1, balBefore, "first call credited position tokens");

    // _signPermit re-reads the current nonce, so this permit carries nonce+1.
    (uint8 v2, bytes32 r2, bytes32 s2) =
      _signPermit(user, PERMIT_USER_PRIVATE_KEY, address(market), buyAmount, deadline);
    vm.prank(user);
    market.openPositionWithPermit(id, true, buyAmount, 0, deadline, v2, r2, s2);
    assertEq(whuffie.nonces(user), nonceBefore + 2, "nonce incremented after second call");
    uint256 balAfter2 = trustToken.balanceOf(user);
    assertGt(balAfter2, balAfter1, "second call credited additional position tokens");
  }

  // --- Audit remediation: finding M-1 (solvency) ---

  /// @dev A sell that rounds to zero net credits out must revert, even when the
  ///      caller leaves minCreditsOut at 0. The DustSellPricing mock returns 1 wei of
  ///      curve revenue on any sell; with max exit fees, the payout collapses to zero
  ///      and the seller would otherwise burn tokens for nothing.
  function test_audit_sellWithZeroNetPayout_reverts() public {
    DustSellPricing dust = new DustSellPricing();
    vm.startPrank(_owner);
    market.setPricingAllowed(address(dust), true);
    market.setExitFeeBasisPoints(market.MAX_PROTOCOL_FEE_BPS()); // 5 %
    vm.stopPrank();

    vm.prank(_admin);
    market.createMarketAdmin(USERKEY, SUBJECT_NAME, INITIAL_BACKING, address(dust));
    uint256 id = market.marketCount();

    _approveAndBuy(bob, id, false, 100e18);
    _approveAndBuy(alice, id, true, 100e18);

    // 1 wei curveRevenue -> ceil(1 * 500 / 10000) = 1 exit fee -> 0 net.
    vm.prank(alice);
    vm.expectRevert(ZeroPayout.selector);
    market.closePosition(id, true, 1, 0);
  }

  /// @dev M-1: global solvency holds across full trade lifecycles in multiple markets
  ///      (buy + partial sell + full sell). The pre-fix `_assertMarketBacked`
  ///      could miss a drain on market A while selling on market B; the test fixture's
  ///      `_assertGloballySolvent` sums obligations across every market and would catch it.
  function test_audit_globalSolvency_fullLifecycleAcrossMarkets() public {
    vm.startPrank(_owner);
    market.setEntryFeeBasisPoints(100);
    market.setExitFeeBasisPoints(200);
    vm.stopPrank();

    uint256 m1 = _createMarketAdmin("address:0xAlice", "Alice", INITIAL_BACKING);
    uint256 m2 = _createMarketAdmin("address:0xBob", "Bob", INITIAL_BACKING);

    _approveAndBuy(alice, m1, true, 400e18);
    _approveAndBuy(bob, m1, false, 250e18);
    _approveAndBuy(alice, m2, true, 300e18);
    _approveAndBuy(carol, m2, false, 150e18);

    // Sell half of Alice's trust position on market 1.
    uint256 aliceTrustM1 = PositionToken(_trustToken(m1)).balanceOf(alice);
    vm.prank(alice);
    market.closePosition(m1, true, aliceTrustM1 / 2, 0);

    // Close all of Carol's distrust on market 2.
    uint256 carolDistrustM2 = PositionToken(_distrustToken(m2)).balanceOf(carol);
    vm.prank(carol);
    market.closePosition(m2, false, carolDistrustM2, 0);

    _assertGloballySolvent();
  }

  /// @dev M-1: global solvency holds even when one market sells immediately after another's buy.
  ///      Pre-fix per-market check would pass as long as the selling market's own obligations
  ///      stayed below the contract balance. Fuzzed coverage lives in EthosMarket.invariant.t.sol.
  function test_audit_globalSolvency_preservedAcrossMarkets() public {
    uint256 m1 = _createMarketAdmin("address:0xAlice", "Alice", INITIAL_BACKING);
    uint256 m2 = _createMarketAdmin("address:0xBob", "Bob", INITIAL_BACKING);

    uint256 aMinted = _approveAndBuy(alice, m1, true, 500e18);
    _approveAndBuy(bob, m2, false, 500e18);

    vm.prank(alice);
    market.closePosition(m1, true, aMinted, 0);

    _assertGloballySolvent();
    _assertMarketBacked(m1);
    _assertMarketBacked(m2);
  }

  // --- _emitMarketUpdated try/catch + MarketUpdateFailed pairing ---

  /// @dev When the pricing contract reverts on getPrice, EthosMarket emits MarketUpdateFailed
  ///      with the revert reason for each failed side and still emits MarketUpdated with
  ///      trustPrice = 0 / distrustPrice = 0. Indexers must consume the paired failed event
  ///      to disambiguate "price unavailable" from a confirmed-zero reading.
  function test_emitMarketUpdated_emitsMarketUpdateFailed_onPriceRevert() public {
    RevertingGetPricePricing reverting = new RevertingGetPricePricing();
    vm.prank(_owner);
    market.setPricingAllowed(address(reverting), true);

    vm.prank(_admin);
    market.createMarketAdmin(USERKEY, SUBJECT_NAME, INITIAL_BACKING, address(reverting));
    uint256 id = market.marketCount();

    bytes memory expectedReason = abi.encodeWithSelector(RevertingGetPricePricing.PriceUnavailable.selector);

    // Buy emits MarketUpdated; the try/catch around getPrice fires MarketUpdateFailed
    // for both sides (trust then distrust). The pricingContract address is the second
    // indexed topic so indexers can correlate failures with the strategy contract.
    vm.prank(alice);
    whuffie.approve(address(market), 100e18);

    vm.expectEmit(true, true, false, true);
    emit EthosMarket.MarketUpdateFailed(id, address(reverting), true, expectedReason);
    vm.expectEmit(true, true, false, true);
    emit EthosMarket.MarketUpdateFailed(id, address(reverting), false, expectedReason);
    // MarketUpdated carries trustPrice = 0 and distrustPrice = 0 because both getPrice calls reverted.
    // We don't bind the supply / pool fields here — we only assert the price fields are 0
    // by checking the event signature with topic-only matching plus a follow-up data parse below.
    vm.recordLogs();
    vm.prank(alice);
    market.openPosition(id, true, 100e18, 0);

    Vm.Log[] memory logs = vm.getRecordedLogs();
    bytes32 marketUpdatedSig = keccak256("MarketUpdated(uint256,uint256,uint256,uint256,uint256,uint256)");
    bool foundUpdated;
    for (uint256 i; i < logs.length; ++i) {
      if (logs[i].topics[0] == marketUpdatedSig) {
        (,, uint256 trustPrice, uint256 distrustPrice,) =
          abi.decode(logs[i].data, (uint256, uint256, uint256, uint256, uint256));
        assertEq(trustPrice, 0, "trustPrice 0 when getPrice reverts");
        assertEq(distrustPrice, 0, "distrustPrice 0 when getPrice reverts");
        foundUpdated = true;
        break;
      }
    }
    assertTrue(foundUpdated, "MarketUpdated emitted alongside the failed events");
  }
}
