// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

import {AccessControlV2} from "../src/utils/AccessControlV2.sol";
import {SignatureControl} from "../src/utils/SignatureControl.sol";
import {EthosRewards} from "../src/EthosRewards.sol";
import {BPS_DENOMINATOR, SECONDS_PER_YEAR, WAD} from "../src/utils/MathConstants.sol";
import {ETHOS_REWARDS, ETHOS_VOUCH_V2} from "../src/utils/Constants.sol";
import {
  EmissionRateTooHigh,
  InsufficientCommittedBalance,
  InsufficientRewardBalance,
  NoRewardsToClaim,
  UnauthorizedAccruingCaller,
  ZeroAmount
} from "../src/errors/RewardsErrors.sol";
import {V2TestFixture} from "./helpers/V2TestFixture.sol";
import {InteractionControlFixture} from "./helpers/InteractionControlFixture.sol";

// ---------------------------------------------------------------------------
// Mock helpers
// ---------------------------------------------------------------------------

contract MockERC20 is ERC20 {
  constructor() ERC20("RewardToken", "RWD") {}

  function mint(address to, uint256 amount) external {
    _mint(to, amount);
  }
}

/// @dev Empty contract used as a stand-in for a real accruing contract,
///      registered in ContractAddressManager under ETHOS_VOUCH_V2.
contract MockAccruingContract {}

/// @dev Reward token whose transfer hook re-enters the configured rewards
///      contract on demand. Used to verify the nonReentrant guard on `claim`.
///      The `_reentered` latch prevents infinite recursion if the guard breaks.
contract MaliciousReentrantRewardToken is ERC20 {
  address public targetVault;
  bool public armedForClaim;
  bool internal _reentered;

  constructor() ERC20("Malicious", "MAL") {}

  function setTarget(address t) external {
    targetVault = t;
  }

  function armClaim() external {
    armedForClaim = true;
    _reentered = false;
  }

  function mint(address to, uint256 amount) external {
    _mint(to, amount);
  }

  function _update(address from, address to, uint256 value) internal override {
    super._update(from, to, value);
    if (!armedForClaim || _reentered || targetVault == address(0)) return;
    if (from != targetVault) return;
    _reentered = true;
    EthosRewards(targetVault).claim();
  }
}

// ---------------------------------------------------------------------------
// Test contract
// ---------------------------------------------------------------------------

contract EthosRewardsTest is V2TestFixture, InteractionControlFixture {
  EthosRewards internal rewards;
  MockERC20 internal token;

  address internal alice = address(0xA11CE);
  address internal bob = address(0xB0B);
  address internal carol = address(0xCAF01);
  address internal accruingContract;
  address internal otherAccruingContract;
  address internal nonAccruing = address(0xBAD);

  uint256 internal constant INITIAL_RATE_BPS = 2000;
  uint256 internal constant INITIAL_POOL = 1000e18;

  // -------------------------------------------------------------------------
  // Setup
  // -------------------------------------------------------------------------

  function setUp() public {
    _deployInfra();

    token = new MockERC20();

    EthosRewards impl = new EthosRewards();
    rewards = EthosRewards(_deployProxy(address(impl)));
    rewards.initialize(_defaultInitParams(), address(token), INITIAL_RATE_BPS);

    _setupInteractionControl(_cam);
    _registerControlledContract(ETHOS_REWARDS, address(rewards));

    accruingContract = address(new MockAccruingContract());
    otherAccruingContract = address(new MockAccruingContract());

    _registerAccruingContract(accruingContract);

    token.mint(address(rewards), INITIAL_POOL);
    _syncRewardBalance();
  }

  /// @dev Registers `addr` in ContractAddressManager under ETHOS_VOUCH_V2 so it
  ///      is recognised as the authorized accruing contract by EthosRewards.
  ///      Overwrites any prior registration under the same name.
  function _registerAccruingContract(address addr) internal {
    address[] memory addrs = new address[](1);
    string[] memory names = new string[](1);
    addrs[0] = addr;
    names[0] = ETHOS_VOUCH_V2;
    _cam.updateContractAddressesForNames(addrs, names);
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  function _credit(address user, uint256 amount) internal {
    vm.prank(accruingContract);
    rewards.credit(user, amount);
  }

  function _debit(address user, uint256 amount) internal {
    vm.prank(accruingContract);
    rewards.debit(user, amount);
  }

  function _claim(address user) internal {
    vm.prank(user);
    rewards.claim();
  }

  function _syncRewardBalance() internal {
    vm.prank(_admin);
    rewards.syncRewardBalance();
  }

  /// @dev Closed-form expected accrual for a user over `dt` seconds against
  ///      a fixed pool, totalCommitted, and the contract's current emission
  ///      rate. Mirrors the contract math; tolerates only WAD-rounding error.
  function _expectedEarned(uint256 userCommitted, uint256 totalCommitted, uint256 pool, uint256 dt)
    internal
    view
    returns (uint256)
  {
    if (totalCommitted == 0 || pool == 0 || dt == 0 || rewards.emissionRateBps() == 0) return 0;
    uint256 rpt =
      (dt * pool * uint256(rewards.emissionRateBps()) * WAD) / (totalCommitted * BPS_DENOMINATOR * SECONDS_PER_YEAR);
    return (userCommitted * rpt) / WAD;
  }

  // -------------------------------------------------------------------------
  // Initialization
  // -------------------------------------------------------------------------

  function test_initialize_setsRoles() public view {
    assertTrue(rewards.hasRole(rewards.OWNER_ROLE(), _owner));
    assertTrue(rewards.hasRole(rewards.ADMIN_ROLE(), _admin));
  }

  function test_initialize_setsRewardToken() public view {
    assertEq(address(rewards.rewardToken()), address(token));
  }

  function test_initialize_setsEmissionRate() public view {
    assertEq(rewards.emissionRateBps(), INITIAL_RATE_BPS);
  }

  function test_initialize_setsAccountedRewardBalance() public view {
    assertEq(rewards.accountedRewardBalance(), INITIAL_POOL);
  }

  function test_initialize_revertsOnZeroToken() public {
    EthosRewards impl = new EthosRewards();
    EthosRewards proxy = EthosRewards(_deployProxy(address(impl)));
    vm.expectRevert(SignatureControl.ZeroAddress.selector);
    proxy.initialize(_defaultInitParams(), address(0), INITIAL_RATE_BPS);
  }

  function test_initialize_revertsOnRateAboveCap() public {
    EthosRewards impl = new EthosRewards();
    EthosRewards proxy = EthosRewards(_deployProxy(address(impl)));
    uint256 cap = rewards.MAX_EMISSION_RATE_BPS();
    vm.expectRevert(abi.encodeWithSelector(EmissionRateTooHigh.selector, cap + 1, cap));
    proxy.initialize(_defaultInitParams(), address(token), cap + 1);
  }

  function test_initialize_acceptsRateAtCap() public {
    EthosRewards impl = new EthosRewards();
    EthosRewards proxy = EthosRewards(_deployProxy(address(impl)));
    uint256 cap = rewards.MAX_EMISSION_RATE_BPS();
    proxy.initialize(_defaultInitParams(), address(token), cap);
    assertEq(proxy.emissionRateBps(), cap);
  }

  function test_initialize_acceptsZeroRate() public {
    EthosRewards impl = new EthosRewards();
    EthosRewards proxy = EthosRewards(_deployProxy(address(impl)));
    proxy.initialize(_defaultInitParams(), address(token), 0);
    assertEq(proxy.emissionRateBps(), 0);
  }

  function test_initialize_emitsEmissionRateUpdated() public {
    EthosRewards impl = new EthosRewards();
    EthosRewards proxy = EthosRewards(_deployProxy(address(impl)));
    vm.expectEmit(true, true, true, true);
    emit EthosRewards.EmissionRateUpdated(0, INITIAL_RATE_BPS);
    proxy.initialize(_defaultInitParams(), address(token), INITIAL_RATE_BPS);
  }

  function test_initialize_revertsOnDoubleInit() public {
    vm.expectRevert(Initializable.InvalidInitialization.selector);
    rewards.initialize(_defaultInitParams(), address(token), INITIAL_RATE_BPS);
  }

  function test_initialize_revertsOnDirectImplInit() public {
    EthosRewards impl = new EthosRewards();
    vm.expectRevert(Initializable.InvalidInitialization.selector);
    impl.initialize(_defaultInitParams(), address(token), INITIAL_RATE_BPS);
  }

  // -------------------------------------------------------------------------
  // CAM-based accruing-contract authorization
  // -------------------------------------------------------------------------

  function test_camRegistration_authorizesCredit() public {
    _credit(alice, 100e18);
    assertEq(rewards.committedBalance(alice), 100e18);
  }

  function test_camRotation_revokesPriorCaller() public {
    _registerAccruingContract(otherAccruingContract);

    vm.expectRevert(
      abi.encodeWithSelector(UnauthorizedAccruingCaller.selector, accruingContract, otherAccruingContract)
    );
    vm.prank(accruingContract);
    rewards.credit(alice, 100e18);
  }

  function test_camRotation_authorizesNewCaller() public {
    _registerAccruingContract(otherAccruingContract);

    vm.prank(otherAccruingContract);
    rewards.credit(alice, 100e18);
    assertEq(rewards.committedBalance(alice), 100e18);
  }

  function test_camRotation_preservesExistingBalances() public {
    _credit(alice, 100e18);
    skip(SECONDS_PER_YEAR / 4);
    uint256 priorEarned = rewards.earned(alice);

    _registerAccruingContract(otherAccruingContract);

    assertEq(rewards.committedBalance(alice), 100e18);
    assertEq(rewards.totalCommitted(), 100e18);
    skip(SECONDS_PER_YEAR / 4);
    assertGt(rewards.earned(alice), priorEarned);

    _claim(alice);
    assertGt(token.balanceOf(alice), 0);
  }

  function test_camRotation_reRegisterRestoresAuthority() public {
    _registerAccruingContract(otherAccruingContract);
    _registerAccruingContract(accruingContract);

    _credit(alice, 100e18);
    assertEq(rewards.committedBalance(alice), 100e18);
  }

  function test_credit_revertsWhenNoAccruingContractRegistered() public {
    _registerAccruingContract(address(0));

    vm.expectRevert(abi.encodeWithSelector(UnauthorizedAccruingCaller.selector, accruingContract, address(0)));
    vm.prank(accruingContract);
    rewards.credit(alice, 100e18);
  }

  // -------------------------------------------------------------------------
  // credit
  // -------------------------------------------------------------------------

  function test_credit_incrementsBalances() public {
    _credit(alice, 100e18);
    assertEq(rewards.committedBalance(alice), 100e18);
    assertEq(rewards.totalCommitted(), 100e18);
  }

  function test_credit_emitsEvent() public {
    vm.expectEmit(true, true, true, true);
    emit EthosRewards.Credited(accruingContract, alice, 100e18, 100e18);
    vm.prank(accruingContract);
    rewards.credit(alice, 100e18);
  }

  function test_credit_accumulates() public {
    _credit(alice, 100e18);
    _credit(alice, 50e18);
    assertEq(rewards.committedBalance(alice), 150e18);
    assertEq(rewards.totalCommitted(), 150e18);
  }

  function test_credit_revertsOnZeroAmount() public {
    vm.expectRevert(ZeroAmount.selector);
    vm.prank(accruingContract);
    rewards.credit(alice, 0);
  }

  function test_credit_revertsOnZeroUser() public {
    vm.expectRevert(SignatureControl.ZeroAddress.selector);
    vm.prank(accruingContract);
    rewards.credit(address(0), 100e18);
  }

  function test_credit_revertsForUnauthorizedCaller() public {
    vm.expectRevert(abi.encodeWithSelector(UnauthorizedAccruingCaller.selector, nonAccruing, accruingContract));
    vm.prank(nonAccruing);
    rewards.credit(alice, 100e18);
  }

  function test_credit_revertsWhenPaused() public {
    _pauseContract(ETHOS_REWARDS);
    vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
    vm.prank(accruingContract);
    rewards.credit(alice, 100e18);
  }

  // -------------------------------------------------------------------------
  // debit
  // -------------------------------------------------------------------------

  function test_debit_decrementsBalances() public {
    _credit(alice, 100e18);
    _debit(alice, 30e18);
    assertEq(rewards.committedBalance(alice), 70e18);
    assertEq(rewards.totalCommitted(), 70e18);
  }

  function test_debit_emitsEvent() public {
    _credit(alice, 100e18);
    vm.expectEmit(true, true, true, true);
    emit EthosRewards.Debited(accruingContract, alice, 30e18, 70e18);
    vm.prank(accruingContract);
    rewards.debit(alice, 30e18);
  }

  function test_debit_revertsOnInsufficient() public {
    _credit(alice, 100e18);
    vm.expectRevert(abi.encodeWithSelector(InsufficientCommittedBalance.selector, alice, 200e18, 100e18));
    vm.prank(accruingContract);
    rewards.debit(alice, 200e18);
  }

  function test_debit_revertsOnZero() public {
    _credit(alice, 100e18);
    vm.expectRevert(ZeroAmount.selector);
    vm.prank(accruingContract);
    rewards.debit(alice, 0);
  }

  function test_debit_revertsOnZeroUser() public {
    vm.expectRevert(SignatureControl.ZeroAddress.selector);
    vm.prank(accruingContract);
    rewards.debit(address(0), 50e18);
  }

  function test_debit_revertsForUnauthorizedCaller() public {
    _credit(alice, 100e18);
    vm.expectRevert(abi.encodeWithSelector(UnauthorizedAccruingCaller.selector, nonAccruing, accruingContract));
    vm.prank(nonAccruing);
    rewards.debit(alice, 50e18);
  }

  function test_debit_revertsWhenPaused() public {
    _credit(alice, 100e18);
    _pauseContract(ETHOS_REWARDS);
    vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
    vm.prank(accruingContract);
    rewards.debit(alice, 50e18);
  }

  function test_debit_preservesPendingRewards() public {
    _credit(alice, 100e18);
    skip(SECONDS_PER_YEAR / 2);
    uint256 pending = rewards.earned(alice);
    assertGt(pending, 0);

    _debit(alice, 100e18);

    assertEq(rewards.committedBalance(alice), 0);
    assertEq(rewards.totalCommitted(), 0);
    assertEq(rewards.rewards(alice), pending);
    assertEq(rewards.earned(alice), pending);
  }

  // -------------------------------------------------------------------------
  // Reward accrual
  // -------------------------------------------------------------------------

  function test_rewardPerToken_zeroWhenNothingCommitted() public {
    skip(30 days);
    assertEq(rewards.rewardPerToken(), 0);
    assertEq(rewards.earned(alice), 0);
  }

  function test_rewardPerToken_zeroDtReturnsStored() public {
    _credit(alice, 100e18);
    assertEq(rewards.rewardPerToken(), 0);
  }

  function test_rewardPerToken_growsWithTime() public {
    _credit(alice, 100e18);
    uint256 before = rewards.rewardPerToken();
    skip(1 days);
    assertGt(rewards.rewardPerToken(), before);
  }

  function test_earned_singleUserOverYear() public {
    _credit(alice, 100e18);
    uint256 pool = INITIAL_POOL;
    skip(SECONDS_PER_YEAR);

    uint256 expected = _expectedEarned(100e18, 100e18, pool, SECONDS_PER_YEAR);
    assertEq(expected, 200e18);
    assertApproxEqAbs(rewards.earned(alice), expected, 1);
  }

  function test_earned_proportionalAcrossUsers() public {
    _credit(alice, 100e18);
    _credit(bob, 300e18);
    skip(SECONDS_PER_YEAR / 4);

    uint256 aliceEarned = rewards.earned(alice);
    uint256 bobEarned = rewards.earned(bob);

    assertApproxEqRel(bobEarned, aliceEarned * 3, 1e12);
  }

  function test_earned_decaysWithPool() public {
    _credit(alice, 100e18);
    skip(SECONDS_PER_YEAR);
    _claim(alice);

    uint256 firstInterval = 200e18;
    uint256 newPool = token.balanceOf(address(rewards));
    assertEq(newPool, INITIAL_POOL - firstInterval);

    skip(SECONDS_PER_YEAR);
    uint256 secondInterval = rewards.earned(alice);
    assertApproxEqAbs(secondInterval, newPool * INITIAL_RATE_BPS / BPS_DENOMINATOR, 1);
    assertLt(secondInterval, firstInterval);
  }

  function test_earned_zeroRateNoAccrual() public {
    vm.prank(_admin);
    rewards.setEmissionRate(0);

    _credit(alice, 100e18);
    skip(SECONDS_PER_YEAR);
    assertEq(rewards.earned(alice), 0);
  }

  function test_earned_cappedAtPoolUnderSparseUpdates() public {
    uint256 cap = rewards.MAX_EMISSION_RATE_BPS();
    vm.prank(_admin);
    rewards.setEmissionRate(cap);

    _credit(alice, 1e18);
    skip(SECONDS_PER_YEAR * 100);

    uint256 poolBefore = token.balanceOf(address(rewards));
    uint256 earned = rewards.earned(alice);
    assertLe(earned, poolBefore, "earned should never exceed pool");

    _claim(alice);
    assertLe(token.balanceOf(alice), poolBefore);
  }

  function test_solvency_totalAccruedNotPaidNeverExceedsBalance() public {
    _credit(alice, 100e18);
    _credit(bob, 200e18);
    skip(SECONDS_PER_YEAR / 2);

    _debit(alice, 50e18);
    assertLe(rewards.totalAccruedNotPaid(), token.balanceOf(address(rewards)));

    skip(SECONDS_PER_YEAR / 2);
    _claim(bob);
    assertLe(rewards.totalAccruedNotPaid(), token.balanceOf(address(rewards)));
  }

  function test_earned_zeroPoolNoAccrual() public {
    vm.prank(address(rewards));
    token.transfer(address(0xdead), INITIAL_POOL);
    _syncRewardBalance();

    _credit(alice, 100e18);
    skip(SECONDS_PER_YEAR);
    assertEq(rewards.earned(alice), 0);
  }

  function test_earned_ignoresDirectTransferBeforeSync() public {
    _credit(alice, INITIAL_POOL);
    skip(30 days);
    uint256 earnedBefore = rewards.earned(alice);

    token.mint(address(rewards), INITIAL_POOL);

    assertEq(token.balanceOf(address(rewards)) - rewards.accountedRewardBalance(), INITIAL_POOL);
    assertEq(rewards.earned(alice), earnedBefore);
  }

  function test_earned_creditMidIntervalSettlesCleanly() public {
    _credit(alice, 100e18);
    skip(SECONDS_PER_YEAR / 2);
    uint256 aliceMid = rewards.earned(alice);

    _credit(bob, 100e18);
    assertEq(rewards.earned(bob), 0);

    skip(SECONDS_PER_YEAR / 2);

    uint256 aliceFinal = rewards.earned(alice);
    uint256 bobFinal = rewards.earned(bob);

    assertGt(aliceFinal, aliceMid);
    assertGt(bobFinal, 0);
    // Alice's tail and bob's full window are equal-stake over the same dt.
    assertApproxEqAbs(aliceFinal - aliceMid, bobFinal, 1);
  }

  // -------------------------------------------------------------------------
  // claim
  // -------------------------------------------------------------------------

  function test_claim_transfersRewards() public {
    _credit(alice, 100e18);
    skip(SECONDS_PER_YEAR);

    uint256 expected = rewards.earned(alice);
    _claim(alice);

    assertEq(token.balanceOf(alice), expected);
    assertEq(rewards.rewards(alice), 0);
  }

  function test_claim_decrementsAccountedRewardBalance() public {
    _credit(alice, 100e18);
    skip(SECONDS_PER_YEAR);

    uint256 expected = rewards.earned(alice);
    uint256 accountedBefore = rewards.accountedRewardBalance();
    _claim(alice);

    assertEq(rewards.accountedRewardBalance(), accountedBefore - expected);
    assertEq(rewards.totalAccruedNotPaid(), 0);
  }

  function test_claim_emitsEvent() public {
    _credit(alice, 100e18);
    skip(SECONDS_PER_YEAR);
    uint256 expected = rewards.earned(alice);

    vm.expectEmit(true, true, true, true);
    emit EthosRewards.RewardClaimed(alice, expected);
    _claim(alice);
  }

  function test_claim_revertsWithoutRewards() public {
    vm.expectRevert(NoRewardsToClaim.selector);
    _claim(alice);
  }

  function test_claim_secondClaimAfterMoreAccrual() public {
    _credit(alice, 100e18);
    skip(SECONDS_PER_YEAR);
    _claim(alice);
    uint256 firstClaim = token.balanceOf(alice);

    skip(SECONDS_PER_YEAR);
    uint256 expected = rewards.earned(alice);
    assertGt(expected, 0);

    _claim(alice);
    assertEq(token.balanceOf(alice), firstClaim + expected);
    assertEq(rewards.rewards(alice), 0);
  }

  function test_claim_revertsWhenSecondClaimInSameBlock() public {
    _credit(alice, 100e18);
    skip(SECONDS_PER_YEAR);
    _claim(alice);

    vm.expectRevert(NoRewardsToClaim.selector);
    _claim(alice);
  }

  function test_claim_afterDebitDrainsPending() public {
    _credit(alice, 100e18);
    skip(SECONDS_PER_YEAR / 2);
    _debit(alice, 100e18);

    uint256 pending = rewards.rewards(alice);
    assertGt(pending, 0);

    _claim(alice);
    assertEq(token.balanceOf(alice), pending);
  }

  function test_claim_revertsWhenPaused() public {
    _credit(alice, 100e18);
    skip(1 days);
    _pauseContract(ETHOS_REWARDS);

    vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
    _claim(alice);
  }

  function test_claim_succeedsAfterUnpause_withFullAccrual() public {
    _credit(alice, 100e18);
    _pauseContract(ETHOS_REWARDS);
    skip(SECONDS_PER_YEAR / 2);
    _unpauseContract(ETHOS_REWARDS);

    uint256 expected = _expectedEarned(100e18, 100e18, INITIAL_POOL, SECONDS_PER_YEAR / 2);
    assertApproxEqAbs(rewards.earned(alice), expected, 1);

    _claim(alice);
    assertApproxEqAbs(token.balanceOf(alice), expected, 1);
  }

  function test_claim_isReentrancyGuarded() public {
    MaliciousReentrantRewardToken malToken = new MaliciousReentrantRewardToken();
    EthosRewards impl = new EthosRewards();
    EthosRewards malRewards = EthosRewards(_deployProxy(address(impl)));
    malRewards.initialize(_defaultInitParams(), address(malToken), INITIAL_RATE_BPS);
    _registerControlledContract("ETHOS_REWARDS_MAL", address(malRewards));

    // accruingContract is already the ETHOS_VOUCH_V2 registration in the
    // shared CAM (set up in setUp), so it can call credit on malRewards too.

    malToken.mint(address(malRewards), INITIAL_POOL);
    vm.prank(_admin);
    malRewards.syncRewardBalance();
    malToken.setTarget(address(malRewards));

    vm.prank(accruingContract);
    malRewards.credit(alice, 100e18);
    skip(SECONDS_PER_YEAR / 2);

    malToken.armClaim();

    vm.expectRevert(ReentrancyGuardUpgradeable.ReentrancyGuardReentrantCall.selector);
    vm.prank(alice);
    malRewards.claim();
  }

  // -------------------------------------------------------------------------
  // setEmissionRate
  // -------------------------------------------------------------------------

  function test_setEmissionRate_updatesValue() public {
    vm.expectEmit(true, true, true, true);
    emit EthosRewards.EmissionRateUpdated(INITIAL_RATE_BPS, 500);
    vm.prank(_admin);
    rewards.setEmissionRate(500);
    assertEq(rewards.emissionRateBps(), 500);
  }

  function test_setEmissionRate_revertsAboveCap() public {
    uint256 cap = rewards.MAX_EMISSION_RATE_BPS();
    vm.expectRevert(abi.encodeWithSelector(EmissionRateTooHigh.selector, cap + 1, cap));
    vm.prank(_admin);
    rewards.setEmissionRate(cap + 1);
  }

  function test_setEmissionRate_revertsForNonAdmin() public {
    vm.expectRevert(
      abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, alice, rewards.ADMIN_ROLE())
    );
    vm.prank(alice);
    rewards.setEmissionRate(500);
  }

  function test_setEmissionRate_integratesPriorAccrualAtOldRate() public {
    _credit(alice, 100e18);
    skip(SECONDS_PER_YEAR / 2);

    uint256 expectedAtOldRate = _expectedEarned(100e18, 100e18, INITIAL_POOL, SECONDS_PER_YEAR / 2);

    vm.prank(_admin);
    rewards.setEmissionRate(0);

    assertApproxEqAbs(rewards.earned(alice), expectedAtOldRate, 1);

    skip(SECONDS_PER_YEAR);
    assertApproxEqAbs(rewards.earned(alice), expectedAtOldRate, 1);
  }

  // -------------------------------------------------------------------------
  // syncRewardBalance
  // -------------------------------------------------------------------------

  function test_syncRewardBalance_revertsForNonAdmin() public {
    vm.expectRevert(
      abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, alice, rewards.ADMIN_ROLE())
    );
    vm.prank(alice);
    rewards.syncRewardBalance();
  }

  function test_syncRewardBalance_accountsDirectTransfer() public {
    uint256 added = 50e18;
    token.mint(address(rewards), added);

    assertEq(token.balanceOf(address(rewards)) - rewards.accountedRewardBalance(), added);

    vm.expectEmit(true, true, true, true);
    emit EthosRewards.RewardBalanceSynced(_admin, INITIAL_POOL, INITIAL_POOL + added);
    _syncRewardBalance();

    assertEq(rewards.accountedRewardBalance(), INITIAL_POOL + added);
    assertEq(token.balanceOf(address(rewards)), rewards.accountedRewardBalance());
  }

  function test_syncRewardBalance_isIdempotent() public {
    _syncRewardBalance();

    assertEq(rewards.accountedRewardBalance(), INITIAL_POOL);
    assertEq(token.balanceOf(address(rewards)), rewards.accountedRewardBalance());
  }

  function test_syncRewardBalance_revertsWhenPaused() public {
    token.mint(address(rewards), 50e18);
    _pauseContract(ETHOS_REWARDS);

    vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
    _syncRewardBalance();
  }

  function test_syncRewardBalance_revertsWhenBalanceCannotCoverAccruedRewards() public {
    _credit(alice, INITIAL_POOL);
    skip(SECONDS_PER_YEAR);

    vm.prank(_admin);
    rewards.setEmissionRate(INITIAL_RATE_BPS);

    uint256 accrued = rewards.totalAccruedNotPaid();
    assertGt(accrued, 0);
    uint256 targetBalance = accrued - 1;
    uint256 liveBalance = token.balanceOf(address(rewards));

    vm.prank(address(rewards));
    token.transfer(address(0xdead), liveBalance - targetBalance);

    vm.expectRevert(abi.encodeWithSelector(InsufficientRewardBalance.selector, targetBalance, accrued));
    _syncRewardBalance();
  }

  function test_syncRewardBalance_doesNotAccrueDirectTransferRetroactively() public {
    _credit(alice, INITIAL_POOL);
    skip(30 days);

    token.mint(address(rewards), INITIAL_POOL);
    skip(30 days);

    uint256 expectedBeforeSync = _expectedEarned(INITIAL_POOL, INITIAL_POOL, INITIAL_POOL, 60 days);
    _syncRewardBalance();

    assertApproxEqAbs(rewards.earned(alice), expectedBeforeSync, 1);

    skip(30 days);
    assertGt(rewards.earned(alice), expectedBeforeSync);
  }

  // -------------------------------------------------------------------------
  // currentRewardRateBps
  // -------------------------------------------------------------------------

  function test_rewardRate_zeroWhenNothingCommitted() public view {
    assertEq(rewards.currentRewardRateBps(), 0);
  }

  function test_rewardRate_returnsConfiguredRateAtEquilibrium() public {
    // pool == totalCommitted → reward rate equals emissionRateBps.
    _credit(alice, INITIAL_POOL);
    assertEq(rewards.currentRewardRateBps(), INITIAL_RATE_BPS);
  }

  function test_rewardRate_higherWhenPoolExceedsCommitted() public {
    _credit(alice, INITIAL_POOL / 4);
    assertEq(rewards.currentRewardRateBps(), INITIAL_RATE_BPS * 4);
  }

  function test_rewardRate_ignoresDirectTransferBeforeSync() public {
    _credit(alice, INITIAL_POOL);
    uint256 rateBefore = rewards.currentRewardRateBps();

    token.mint(address(rewards), INITIAL_POOL);

    assertEq(token.balanceOf(address(rewards)) - rewards.accountedRewardBalance(), INITIAL_POOL);
    assertEq(rewards.currentRewardRateBps(), rateBefore);
  }

  function test_rewardRate_lowerWhenCommittedExceedsPool() public {
    _credit(alice, INITIAL_POOL * 4);
    assertEq(rewards.currentRewardRateBps(), INITIAL_RATE_BPS / 4);
  }

  function test_rewardRate_accountsForPendingAccrual() public {
    _credit(alice, INITIAL_POOL);
    skip(SECONDS_PER_YEAR / 2);

    assertEq(rewards.currentRewardRateBps(), 1800);
  }

  function test_rewardRate_zeroWhenPendingAccrualExhaustsPool() public {
    _credit(alice, INITIAL_POOL);
    skip(SECONDS_PER_YEAR * 5);

    assertEq(rewards.currentRewardRateBps(), 0);
  }

  function test_rewardRate_zeroWhenAccruedDebtExhaustsPool() public {
    _credit(alice, INITIAL_POOL);
    skip(SECONDS_PER_YEAR * 5);

    vm.prank(_admin);
    rewards.setEmissionRate(INITIAL_RATE_BPS);

    assertEq(rewards.totalAccruedNotPaid(), INITIAL_POOL, "precondition: full pool accrued as debt");
    assertEq(rewards.currentRewardRateBps(), 0);
  }

  // -------------------------------------------------------------------------
  // Pause: accumulator continues
  // -------------------------------------------------------------------------

  function test_pause_accumulatorContinues() public {
    _credit(alice, 100e18);
    skip(SECONDS_PER_YEAR / 4);

    _pauseContract(ETHOS_REWARDS);
    skip(SECONDS_PER_YEAR / 4);
    _unpauseContract(ETHOS_REWARDS);

    uint256 expected = _expectedEarned(100e18, 100e18, INITIAL_POOL, SECONDS_PER_YEAR / 2);
    assertApproxEqAbs(rewards.earned(alice), expected, 1);
  }

  // -------------------------------------------------------------------------
  // UUPS upgrade
  // -------------------------------------------------------------------------

  function test_upgrade_revertsForNonOwner() public {
    address newImpl = address(new EthosRewards());
    vm.expectRevert(
      abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, alice, rewards.OWNER_ROLE())
    );
    vm.prank(alice);
    rewards.upgradeToAndCall(newImpl, "");
  }

  function test_upgrade_acceptedFromOwner() public {
    address newImpl = address(new EthosRewards());
    vm.prank(_owner);
    rewards.upgradeToAndCall(newImpl, "");
  }

  function test_upgrade_revertsOnZeroImpl() public {
    vm.expectRevert(SignatureControl.ZeroAddress.selector);
    vm.prank(_owner);
    rewards.upgradeToAndCall(address(0), "");
  }

  // -------------------------------------------------------------------------
  // Regression: cross-interval rounding DoS (claim() underflow)
  // -------------------------------------------------------------------------

  /// @notice Reproduces the exact scenario from the confirmed PoC:
  ///         a sole holder with a non-round committed balance accruing over
  ///         10 daily intervals triggers accumulated floor residual that,
  ///         before the fix, caused earned() > totalAccruedNotPaid and a
  ///         panic-0x11 underflow in claim(). After the fix the invariant
  ///         must hold and claim() must succeed.
  function test_claim_crossIntervalRounding_noUnderflow() public {
    // Exact PoC parameters.
    uint256 committedAmount = 24444572535038510415;
    _credit(alice, committedAmount);
    vm.prank(_admin);
    rewards.setEmissionRate(10000); // 100 %/yr — maximises per-interval residual

    // Ten accrual intervals with a rate-set each day; mirrors the PoC loop.
    for (uint256 i = 0; i < 10; i++) {
      skip(1 days);
      vm.prank(_admin);
      rewards.setEmissionRate(10000);
    }

    // The invariant the primary fix enforces: claimable never exceeds the
    // global counter.
    uint256 aliceEarned = rewards.earned(alice);
    uint256 accrued = rewards.totalAccruedNotPaid();
    assertLe(aliceEarned, accrued, "earned(alice) > totalAccruedNotPaid");

    // claim() must not revert; the full earned amount must be transferred.
    uint256 balanceBefore = token.balanceOf(alice);
    _claim(alice);
    assertEq(token.balanceOf(alice) - balanceBefore, aliceEarned, "transferred amount mismatch");
    assertEq(rewards.rewards(alice), 0, "settled balance not cleared");
  }
}
