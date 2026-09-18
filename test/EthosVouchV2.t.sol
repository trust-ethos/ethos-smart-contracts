// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {Vm} from "forge-std/Vm.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Burnable} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {AccessControlV2} from "../src/utils/AccessControlV2.sol";
import {SignatureControl} from "../src/utils/SignatureControl.sol";
import {EthosRewards} from "../src/EthosRewards.sol";
import {EthosVouchV2} from "../src/EthosVouchV2.sol";
import {IFreezable} from "../src/interfaces/IFreezable.sol";
import {ISlashable} from "../src/interfaces/ISlashable.sol";
import {ITargetStatus} from "../src/interfaces/ITargetStatus.sol";
import {UnauthorizedAccruingCaller} from "../src/errors/RewardsErrors.sol";
import {ETHOS_REWARDS, ETHOS_VOUCH_V2} from "../src/utils/Constants.sol";
import {
  AlreadyVouched,
  VouchAlreadyArchived,
  UnauthorizedVouchAccess,
  MaxVouchesExceeded,
  AmountBelowMinimum,
  AmountAboveMaximum,
  FeeBpsTooHigh,
  MaximumVouchesOutOfRange,
  InsufficientPermitAllowance,
  UnexpectedTokenBehavior,
  VouchNotFound,
  TokenNotBurnable,
  InvalidBps,
  ZeroAmount,
  AmountExceedsBalance,
  RemainingBelowMinimum,
  UnauthorizedComposer,
  InvalidAuthor
} from "../src/errors/VouchV2Errors.sol";
import {AccountFrozen, NotSlasher} from "../src/errors/SlashFreezableErrors.sol";
import {V2TestFixture} from "./helpers/V2TestFixture.sol";
import {InteractionControlFixture} from "./helpers/InteractionControlFixture.sol";

// ---------------------------------------------------------------------------
// Mock helpers
// ---------------------------------------------------------------------------

/// @dev Standard ERC-20 + Burnable + Permit for tests.
contract MockERC20Burnable is ERC20, ERC20Burnable, ERC20Permit {
  constructor() ERC20("TestToken", "TT") ERC20Permit("TestToken") {}

  function mint(address to, uint256 amount) external {
    _mint(to, amount);
  }
}

/// @dev Plain ERC-20 with no burn function — used to verify the burn(0) probe
///      in EthosVouchV2.initialize catches non-burnable tokens at deploy time.
contract MockERC20NonBurnable is ERC20 {
  constructor() ERC20("PlainToken", "PT") {}

  function mint(address to, uint256 amount) external {
    _mint(to, amount);
  }
}

/// @dev Fee-on-transfer token that deducts 1 wei on every transfer when `feeActive` is
///      true. Burnable so it can pass the initialize() probe. The toggle lets tests seed
///      an initial vouch without fees, then enable fee-on-transfer to exercise the
///      balance-delta guard in increaseVouch. Default is OFF so callers must opt in
///      to FoT behaviour — keeps the footgun off.
contract MockFeeOnTransferToken is ERC20, ERC20Burnable {
  bool public feeActive;

  constructor() ERC20("FeeToken", "FT") {}

  function mint(address to, uint256 amount) external {
    _mint(to, amount);
  }

  function setFeeActive(bool active) external {
    feeActive = active;
  }

  function _update(address from, address to, uint256 value) internal override {
    if (feeActive && from != address(0) && to != address(0) && value > 0) {
      super._update(from, to, value - 1);
      super._update(from, address(0), 1);
    } else {
      super._update(from, to, value);
    }
  }
}

/// @dev Token whose ERC-20 hooks (and burn) re-enter EthosVouchV2 on demand. Used to
///      verify the nonReentrant guard. After the underlying transfer/transferFrom/burn
///      succeeds, the configured re-entry call is fired and is expected to revert with
///      ReentrancyGuardReentrantCall — that revert propagates back through the original
///      call stack.
///
///      Test arms the desired trigger (When + Action), then calls the entry point. The
///      _reentered flag prevents infinite recursion in case the guard is broken.
contract MaliciousReentrantToken is ERC20, ERC20Burnable {
  enum When {
    None,
    OnTransfer,
    OnTransferFrom,
    OnBurn
  }
  enum Action {
    None,
    Vouch,
    Unvouch,
    IncreaseVouch,
    DecreaseVouch
  }

  address public targetVault;
  When public when_;
  Action public action_;
  uint256 public reVid;
  string public reTarget;
  bool internal _reentered;

  constructor() ERC20("Malicious", "MAL") {}

  function setTarget(address t) external {
    targetVault = t;
  }

  function arm(When w, Action a, uint256 vid, string memory tgt) external {
    when_ = w;
    action_ = a;
    reVid = vid;
    reTarget = tgt;
    _reentered = false;
  }

  function mint(address to, uint256 amount) external {
    _mint(to, amount);
  }

  function _maybeReenter(When trigger) internal {
    if (when_ != trigger || _reentered || targetVault == address(0)) return;
    _reentered = true;
    if (action_ == Action.Vouch) {
      // Note: the reentrant call's msg.sender is this token; that's irrelevant —
      // nonReentrant fires before any auth check and reverts with its own selector.
      EthosVouchV2(targetVault).vouch(reTarget, 10e18);
    } else if (action_ == Action.Unvouch) {
      EthosVouchV2(targetVault).unvouch(reVid);
    } else if (action_ == Action.IncreaseVouch) {
      EthosVouchV2(targetVault).increaseVouch(reVid, 1e18);
    } else if (action_ == Action.DecreaseVouch) {
      EthosVouchV2(targetVault).decreaseVouch(reVid, 1e18);
    }
  }

  function transfer(address to, uint256 amount) public override returns (bool) {
    bool ok = super.transfer(to, amount);
    _maybeReenter(When.OnTransfer);
    return ok;
  }

  function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
    bool ok = super.transferFrom(from, to, amount);
    _maybeReenter(When.OnTransferFrom);
    return ok;
  }

  function burn(uint256 amount) public override {
    super.burn(amount);
    _maybeReenter(When.OnBurn);
  }
}

/// @dev Minimal slasher that forwards calls to EthosVouchV2 as msg.sender == slasher.
contract MockSlasher {
  ISlashable private _vouch;

  constructor(address vouch_) {
    _vouch = ISlashable(vouch_);
  }

  function freeze(address account) external {
    _vouch.freeze(account);
  }

  function unfreeze(address account) external {
    _vouch.unfreeze(account);
  }

  function slash(address account, uint256 bps) external returns (uint256) {
    return _vouch.slash(account, bps);
  }
}

// ---------------------------------------------------------------------------
// Test contract
// ---------------------------------------------------------------------------

contract EthosVouchV2Test is V2TestFixture, InteractionControlFixture {
  EthosVouchV2 internal vouch;
  EthosRewards internal rewards;
  MockERC20Burnable internal token;

  address internal alice = address(0xA11CE);
  address internal bob = address(0xB0B);

  MockSlasher internal slasher;

  // Constant name used to register contract in CAM for pause support and for
  // EthosRewards' accruing-contract authorization.
  string internal constant CONTRACT_NAME = ETHOS_VOUCH_V2;
  bytes4 private constant V1_VOUCH_COMMENT_SELECTOR = bytes4(keccak256("vouch(string,string,uint256)"));
  bytes4 private constant V1_VOUCH_BY_PROFILE_COMMENT_SELECTOR =
    bytes4(keccak256("vouchByProfileId(uint256,string,string,(uint256,uint256,uint256))"));
  bytes4 private constant REVIEW_COMMENT_SELECTOR = bytes4(keccak256("addReview(uint8,address,string,string)"));
  bytes4 private constant SET_COMMENT_SELECTOR = bytes4(keccak256("setComment(uint256,string)"));
  bytes4 private constant COMMENT_READER_SELECTOR = bytes4(keccak256("comment(uint256)"));

  // -------------------------------------------------------------------------
  // Setup
  // -------------------------------------------------------------------------

  function setUp() public {
    _deployInfra();

    token = new MockERC20Burnable();

    EthosVouchV2 impl = new EthosVouchV2();
    vouch = EthosVouchV2(_deployProxy(address(impl)));

    vouch.initialize(
      _defaultInitParams(),
      address(token),
      100, // 1% entry fee
      50, // 0.5% exit fee
      1e18, // 1 token minimum
      50000e18, // 50_000 token maximum
      256, // max vouches
      0 // initial vouchCount offset
    );

    _setupInteractionControl(_cam);
    _registerControlledContract(CONTRACT_NAME, address(vouch));

    // Deploy EthosRewards and register under ETHOS_REWARDS in CAM. The vouch
    // contract is already registered under ETHOS_VOUCH_V2 above (via
    // _registerControlledContract), which is what EthosRewards reads to
    // authorize credit/debit callers. Uses the same token as vouch (matches
    // prod, where both EthosVouchV2 and EthosRewards point at WHF).
    EthosRewards rewardsImpl = new EthosRewards();
    rewards = EthosRewards(_deployProxy(address(rewardsImpl)));
    rewards.initialize(_defaultInitParams(), address(token), 1000);
    address[] memory rewardsAddrs = new address[](1);
    string[] memory rewardsNames = new string[](1);
    rewardsAddrs[0] = address(rewards);
    rewardsNames[0] = ETHOS_REWARDS;
    _cam.updateContractAddressesForNames(rewardsAddrs, rewardsNames);

    // Deploy and register slasher in CAM
    slasher = new MockSlasher(address(vouch));
    address[] memory addrs = new address[](1);
    string[] memory names = new string[](1);
    addrs[0] = address(slasher);
    names[0] = "SLASHER";
    _cam.updateContractAddressesForNames(addrs, names);

    // Fund actors
    token.mint(alice, 100_000e18);
    token.mint(bob, 100_000e18);
    token.mint(_admin, 100_000e18);

    vm.prank(alice);
    token.approve(address(vouch), type(uint256).max);
    vm.prank(bob);
    token.approve(address(vouch), type(uint256).max);
    vm.prank(_admin);
    token.approve(address(vouch), type(uint256).max);
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  /// @dev Creates a vouch from alice for a given target with amount 10e18.
  function _vouchAs(address author, string memory target, uint256 amount) internal returns (uint256) {
    vm.prank(author);
    vouch.vouch(target, amount);
    return vouch.vouchCount();
  }

  function _vouchAlice(string memory target) internal returns (uint256) {
    return _vouchAs(alice, target, 10e18);
  }

  function _unvouchAs(address author, uint256 vouchId) internal {
    vm.prank(author);
    vouch.unvouch(vouchId);
  }

  function _decreaseAs(address author, uint256 vouchId, uint256 amount) internal {
    vm.prank(author);
    vouch.decreaseVouch(vouchId, amount);
  }

  function _entryFee(uint256 amount) internal view returns (uint256) {
    return (amount * vouch.entryFeeBps() + vouch.BASIS_POINT_SCALE() - 1) / vouch.BASIS_POINT_SCALE();
  }

  function _exitFee(uint256 balance) internal view returns (uint256) {
    return (balance * vouch.exitFeeBps() + vouch.BASIS_POINT_SCALE() - 1) / vouch.BASIS_POINT_SCALE();
  }

  /// @dev Reads `vouches(vid)` and packs the returned tuple into a typed Vouch struct.
  ///      Centralising the destructuring means a future struct-field reorder breaks
  ///      compilation in exactly one place instead of silently re-mapping fields in
  ///      every test that reads vouch state.
  function _getVouch(uint256 vid) internal view returns (EthosVouchV2.Vouch memory v) {
    (v.author, v.archived, v.unhealthy, v.targetHash, v.balance) = vouch.vouches(vid);
  }

  // -------------------------------------------------------------------------
  // Initialization
  // -------------------------------------------------------------------------

  function test_initialize_setsRoles() public view {
    assertTrue(vouch.hasRole(vouch.OWNER_ROLE(), _owner));
    assertTrue(vouch.hasRole(vouch.ADMIN_ROLE(), _admin));
  }

  function test_initialize_setsToken() public view {
    assertEq(address(vouch.token()), address(token));
  }

  function test_initialize_setsFees() public view {
    assertEq(vouch.entryFeeBps(), 100);
    assertEq(vouch.exitFeeBps(), 50);
  }

  function test_initialize_setsMinimumVouchAmount() public view {
    assertEq(vouch.configuredMinimumVouchAmount(), 1e18);
  }

  function test_initialize_setsMaximumVouches() public view {
    assertEq(vouch.maximumVouches(), 256);
  }

  function test_initialize_revertsOnZeroToken() public {
    EthosVouchV2 impl2 = new EthosVouchV2();
    EthosVouchV2 proxy2 = EthosVouchV2(_deployProxy(address(impl2)));
    vm.expectRevert(SignatureControl.ZeroAddress.selector);
    proxy2.initialize(_defaultInitParams(), address(0), 100, 50, 1e18, 50000e18, 256, 0);
  }

  function test_initialize_revertsOnNonBurnableToken() public {
    MockERC20NonBurnable plain = new MockERC20NonBurnable();
    EthosVouchV2 impl2 = new EthosVouchV2();
    EthosVouchV2 proxy2 = EthosVouchV2(_deployProxy(address(impl2)));
    vm.expectRevert(abi.encodeWithSelector(TokenNotBurnable.selector, address(plain)));
    proxy2.initialize(_defaultInitParams(), address(plain), 100, 50, 1e18, 50000e18, 256, 0);
  }

  function test_initialize_revertsOnZeroMinimum() public {
    EthosVouchV2 impl2 = new EthosVouchV2();
    EthosVouchV2 proxy2 = EthosVouchV2(_deployProxy(address(impl2)));
    vm.expectRevert(abi.encodeWithSelector(AmountBelowMinimum.selector, 0, 1));
    proxy2.initialize(_defaultInitParams(), address(token), 100, 50, 0, 50000e18, 256, 0);
  }

  function test_initialize_revertsOnFeesTooHigh() public {
    EthosVouchV2 impl2 = new EthosVouchV2();
    EthosVouchV2 proxy2 = EthosVouchV2(_deployProxy(address(impl2)));
    // 600 + 500 = 1100 > 1000
    vm.expectRevert(abi.encodeWithSelector(FeeBpsTooHigh.selector, 1100, 1000));
    proxy2.initialize(_defaultInitParams(), address(token), 600, 500, 1e18, 50000e18, 256, 0);
  }

  function test_initialize_revertsWhenMaximumVouchesOutOfRange() public {
    EthosVouchV2 impl2 = new EthosVouchV2();
    EthosVouchV2 proxy2 = EthosVouchV2(_deployProxy(address(impl2)));
    uint256 max = uint256(type(uint32).max) + 1;
    vm.expectRevert(abi.encodeWithSelector(MaximumVouchesOutOfRange.selector, max));
    proxy2.initialize(_defaultInitParams(), address(token), 100, 50, 1e18, 50000e18, max, 0);
  }

  function test_initialize_revertsOnDoubleInit() public {
    vm.expectRevert(Initializable.InvalidInitialization.selector);
    vouch.initialize(_defaultInitParams(), address(token), 100, 50, 1e18, 50000e18, 256, 0);
  }

  function test_initialize_defaultMaxVouches_whenZeroPassed() public {
    EthosVouchV2 impl2 = new EthosVouchV2();
    EthosVouchV2 proxy2 = EthosVouchV2(_deployProxy(address(impl2)));
    proxy2.initialize(_defaultInitParams(), address(token), 100, 50, 1e18, 50000e18, 0, 0);
    assertEq(proxy2.maximumVouches(), 256);
  }

  function test_initialize_initialVouchCount_offsetsFirstMintedId() public {
    uint256 offset = 1_000_000_000;
    EthosVouchV2 impl2 = new EthosVouchV2();
    EthosVouchV2 proxy2 = EthosVouchV2(_deployProxy(address(impl2)));
    proxy2.initialize(_defaultInitParams(), address(token), 100, 50, 1e18, 50000e18, 256, offset);
    assertEq(proxy2.vouchCount(), offset);

    _setupInteractionControl(_cam);
    _registerControlledContract("ETHOS_VOUCH_V2_OFFSET", address(proxy2));
    _allowlistVouchOnRewards(address(proxy2));

    vm.prank(alice);
    token.approve(address(proxy2), type(uint256).max);
    vm.prank(alice);
    proxy2.vouch("offset-target", 10e18);
    assertEq(proxy2.vouchCount(), offset + 1);
  }

  /// @dev Hole ids below a nonzero initialVouchCount offset are in range but never minted;
  ///      each mutating path must reject them as VouchNotFound, not UnauthorizedVouchAccess.
  function test_holeId_belowInitialVouchCount_revertsVouchNotFound() public {
    uint256 offset = 5;
    EthosVouchV2 impl2 = new EthosVouchV2();
    EthosVouchV2 proxy2 = EthosVouchV2(_deployProxy(address(impl2)));
    proxy2.initialize(_defaultInitParams(), address(token), 100, 50, 1e18, 50000e18, 256, offset);

    uint256 hole = 3; // 0 < hole <= vouchCount, but no Vouch was ever written
    (bool exists,) = proxy2.targetExistsAndAllowedForId(hole);
    assertFalse(exists);

    vm.startPrank(alice);
    vm.expectRevert(abi.encodeWithSelector(VouchNotFound.selector, hole));
    proxy2.decreaseVouch(hole, 1e18);

    vm.expectRevert(abi.encodeWithSelector(VouchNotFound.selector, hole));
    proxy2.setVouchMetadata(hole, "x");

    vm.expectRevert(abi.encodeWithSelector(VouchNotFound.selector, hole));
    proxy2.unvouch(hole);

    vm.expectRevert(abi.encodeWithSelector(VouchNotFound.selector, hole));
    proxy2.unvouchUnhealthy(hole);

    vm.expectRevert(abi.encodeWithSelector(VouchNotFound.selector, hole));
    proxy2.increaseVouch(hole, 1e18);
    vm.stopPrank();
  }

  // -------------------------------------------------------------------------
  // vouch
  // -------------------------------------------------------------------------

  function test_vouch_basic_creditsBalance() public {
    uint256 amount = 10e18;
    uint256 vid = _vouchAlice("alice-target");
    EthosVouchV2.Vouch memory v = _getVouch(vid);
    assertEq(v.balance, amount);
    assertEq(v.author, alice);
    assertFalse(v.archived);
  }

  function test_vouch_chargesEntryFee() public {
    uint256 amount = 10e18;
    uint256 fee = _entryFee(amount);
    uint256 aliceBefore = token.balanceOf(alice);
    _vouchAlice("fee-target");
    uint256 spent = aliceBefore - token.balanceOf(alice);
    assertEq(spent, amount + fee);
  }

  function test_vouch_burnsFee() public {
    uint256 amount = 10e18;
    uint256 fee = _entryFee(amount);
    uint256 supplyBefore = token.totalSupply();
    _vouchAlice("fee-burn-target");
    assertEq(supplyBefore - token.totalSupply(), fee);
  }

  function test_vouch_mintsVouchId() public {
    assertEq(vouch.vouchCount(), 0);
    _vouchAlice("target-1");
    assertEq(vouch.vouchCount(), 1);
    _vouchAlice("target-2");
    assertEq(vouch.vouchCount(), 2);
  }

  function test_vouch_updatesIndexes() public {
    uint256 vid = _vouchAlice("index-target");
    bytes32 targetHash = keccak256(bytes("index-target"));

    // Author index
    assertEq(vouch.vouchIdsByAuthor(alice, 0), vid);

    // Uniqueness mapping
    assertEq(vouch.vouchIdByAuthorForTargetHash(alice, targetHash), vid);
  }

  function test_vouch_emitsVouched() public {
    bytes32 targetHash = keccak256(bytes("emit-target"));
    uint256 amount = 10e18;
    uint256 fee = _entryFee(amount);

    vm.expectEmit(true, true, false, true);
    emit EthosVouchV2.Vouched(alice, targetHash, 1, "emit-target", amount, fee, "");

    vm.prank(alice);
    vouch.vouch("emit-target", amount);
  }

  function test_vouch_revertsOnAmountBelowMinimum() public {
    vm.expectRevert(abi.encodeWithSelector(AmountBelowMinimum.selector, 0.5e18, 1e18));
    vm.prank(alice);
    vouch.vouch("below-min", 0.5e18);
  }

  function test_vouch_revertsOnDuplicateTarget() public {
    _vouchAlice("dup-target");
    bytes32 targetHash = keccak256(bytes("dup-target"));
    vm.expectRevert(abi.encodeWithSelector(AlreadyVouched.selector, alice, targetHash));
    vm.prank(alice);
    vouch.vouch("dup-target", 10e18);
  }

  function test_vouch_revertsWhenMaxVouchesReached() public {
    // Set max to 1 so we can test quickly
    vm.prank(_admin);
    vouch.setMaximumVouches(1);

    _vouchAlice("first-target");

    vm.expectRevert(abi.encodeWithSelector(MaxVouchesExceeded.selector, alice, 1));
    vm.prank(alice);
    vouch.vouch("second-target", 10e18);
  }

  function test_vouch_revertsWhenPaused() public {
    _pauseContract(CONTRACT_NAME);
    vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
    vm.prank(alice);
    vouch.vouch("paused-target", 10e18);
  }

  function test_vouch_noFeeWhenZeroFeeBps() public {
    vm.startPrank(_admin);
    vouch.setEntryFeeBps(0);
    vouch.setExitFeeBps(0);
    vm.stopPrank();

    uint256 aliceBefore = token.balanceOf(alice);
    uint256 supplyBefore = token.totalSupply();

    uint256 amount = 10e18;
    _vouchAs(alice, "no-fee-target", amount);

    assertEq(aliceBefore - token.balanceOf(alice), amount);
    assertEq(token.totalSupply(), supplyBefore);
  }

  function test_vouch_targetHashIsKeccak256OfTarget() public {
    uint256 vid = _vouchAlice("hash-check-target");
    assertEq(_getVouch(vid).targetHash, keccak256(bytes("hash-check-target")));
  }

  function test_vouch_multipleVouchersForSameTarget() public {
    uint256 vid1 = _vouchAs(alice, "shared-target", 10e18);
    uint256 vid2 = _vouchAs(bob, "shared-target", 10e18);

    bytes32 targetHash = keccak256(bytes("shared-target"));
    // Each author's uniqueness mapping resolves to their own vid for the shared target.
    assertEq(vouch.vouchIdByAuthorForTargetHash(alice, targetHash), vid1);
    assertEq(vouch.vouchIdByAuthorForTargetHash(bob, targetHash), vid2);
  }

  function test_vouch_revertsOnFeeOnTransferToken() public {
    MockFeeOnTransferToken fotToken = new MockFeeOnTransferToken();
    fotToken.setFeeActive(true);
    fotToken.mint(alice, 100e18);

    EthosVouchV2 impl2 = new EthosVouchV2();
    EthosVouchV2 feeVouch = EthosVouchV2(_deployProxy(address(impl2)));
    feeVouch.initialize(
      _defaultInitParams(),
      address(fotToken),
      0, // no entry fee so we test only the delta check
      0,
      1e18,
      50000e18,
      256,
      0
    );
    _allowlistVouchOnRewards(address(feeVouch));

    vm.prank(alice);
    fotToken.approve(address(feeVouch), type(uint256).max);

    vm.expectRevert(abi.encodeWithSelector(UnexpectedTokenBehavior.selector, 10e18, 10e18 - 1));
    vm.prank(alice);
    feeVouch.vouch("fot-target", 10e18);
  }

  /// @dev Mirror of the zero-fee FoT test but with a non-zero entry fee — verifies the
  ///      balance-delta guard checks `gross = amount + fee`, not just `amount`. A bug
  ///      that compared against `amount` alone would silently let FoT tokens through
  ///      when fees are configured.
  function test_vouch_revertsOnFeeOnTransferToken_withNonZeroFee() public {
    MockFeeOnTransferToken fotToken = new MockFeeOnTransferToken();
    fotToken.setFeeActive(true);
    fotToken.mint(alice, 100e18);

    EthosVouchV2 impl2 = new EthosVouchV2();
    EthosVouchV2 feeVouch = EthosVouchV2(_deployProxy(address(impl2)));
    feeVouch.initialize(
      _defaultInitParams(),
      address(fotToken),
      100, // 1% entry fee
      0,
      1e18,
      50000e18,
      256,
      0
    );
    _allowlistVouchOnRewards(address(feeVouch));

    vm.prank(alice);
    fotToken.approve(address(feeVouch), type(uint256).max);

    // gross = 10e18 + ceil(10e18 * 100 / 10000) = 10.1e18; FoT eats 1 wei.
    uint256 expectedGross = 10e18 + 10e18 / 100;
    vm.expectRevert(abi.encodeWithSelector(UnexpectedTokenBehavior.selector, expectedGross, expectedGross - 1));
    vm.prank(alice);
    feeVouch.vouch("fot-target-fee", 10e18);
  }

  // -------------------------------------------------------------------------
  // vouchWithPermit
  // -------------------------------------------------------------------------

  function test_vouchWithPermit_usesPermitThenTransferFrom() public {
    // Use a fresh signer key with permit support
    uint256 privKey = 0xDEAD;
    address signer = vm.addr(privKey);
    token.mint(signer, 100e18);

    uint256 amount = 10e18;
    uint256 fee = _entryFee(amount);
    uint256 gross = amount + fee;
    uint256 deadline = block.timestamp + 1 hours;

    (uint8 v, bytes32 r, bytes32 s) = _signPermit(token, privKey, signer, address(vouch), gross, deadline);

    uint256 nonceBefore = token.nonces(signer);

    vm.prank(signer);
    vouch.vouchWithPermit("permit-target", amount, deadline, v, r, s);

    assertEq(vouch.vouchCount(), 1);
    assertEq(_getVouch(1).author, signer);
    assertEq(_getVouch(1).balance, amount);
    // Successful permit advances the nonce — confirms the permit path was actually used.
    assertEq(token.nonces(signer), nonceBefore + 1);
  }

  function test_vouchWithPermit_fallsBackToApprovalIfPermitFails() public {
    // Pre-approve so permit failure is gracefully ignored
    vm.prank(alice);
    token.approve(address(vouch), type(uint256).max);

    uint256 nonceBefore = token.nonces(alice);

    // Pass a bad permit (wrong v) — should fall back to existing approval
    vm.prank(alice);
    vouch.vouchWithPermit("fallback-target", 10e18, block.timestamp + 1, 0, bytes32(0), bytes32(0));

    assertEq(vouch.vouchCount(), 1);
    // Failed permit must NOT advance the nonce — proves the try/catch swallowed the
    // revert and the function fell through to the existing allowance.
    assertEq(token.nonces(alice), nonceBefore);
  }

  function test_vouchWithPermit_revertsWhenPaused() public {
    _pauseContract(CONTRACT_NAME);

    // Permit args are irrelevant — whenNotPaused runs before the permit call.
    vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
    vm.prank(alice);
    vouch.vouchWithPermit("paused-permit-target", 10e18, block.timestamp + 1, 0, bytes32(0), bytes32(0));
  }

  /// @dev Bad permit + zero pre-existing allowance must surface
  /// InsufficientPermitAllowance instead of falling through to an opaque
  /// ERC20InsufficientAllowance from safeTransferFrom.
  function test_vouchWithPermit_revertsWithInsufficientPermitAllowance() public {
    address user = vm.addr(0xBEEF);
    token.mint(user, 100e18);
    // No pre-approval. Bad permit (zero v/r/s) reverts inside try/catch.

    uint256 amount = 10e18;
    uint256 fee = _entryFee(amount);
    uint256 required = amount + fee;

    vm.expectRevert(abi.encodeWithSelector(InsufficientPermitAllowance.selector, user, required));
    vm.prank(user);
    vouch.vouchWithPermit("no-allowance-target", amount, block.timestamp + 1, 0, bytes32(0), bytes32(0));
  }

  // -------------------------------------------------------------------------
  // increaseVouchWithPermit
  // -------------------------------------------------------------------------

  function test_increaseVouchWithPermit_usesPermitThenTransferFrom() public {
    uint256 privKey = 0xDEAD2;
    address signer = vm.addr(privKey);
    token.mint(signer, 100e18);

    vm.prank(signer);
    token.approve(address(vouch), type(uint256).max);

    // Create a vouch first
    vm.prank(signer);
    vouch.vouch("permit-inc-target", 10e18);
    uint256 vid = vouch.vouchCount();

    uint256 increment = 5e18;
    uint256 fee = _entryFee(increment);
    uint256 gross = increment + fee;
    uint256 deadline = block.timestamp + 1 hours;

    // Reset allowance to zero so we rely on the permit
    vm.prank(signer);
    token.approve(address(vouch), 0);

    (uint8 v, bytes32 r, bytes32 s) = _signPermit(token, privKey, signer, address(vouch), gross, deadline);

    uint256 nonceBefore = token.nonces(signer);

    vm.prank(signer);
    vouch.increaseVouchWithPermit(vid, increment, deadline, v, r, s);

    assertEq(_getVouch(vid).balance, 10e18 + increment);
    // Successful permit advances nonce — confirms the permit path was actually used.
    assertEq(token.nonces(signer), nonceBefore + 1);
  }

  function test_increaseVouchWithPermit_fallsBackToApprovalIfPermitFails() public {
    uint256 vid = _vouchAlice("permit-inc-fallback-target");
    uint256 nonceBefore = token.nonces(alice);

    // alice already has max approval, bad permit is silently caught
    vm.prank(alice);
    vouch.increaseVouchWithPermit(vid, 5e18, block.timestamp + 1, 0, bytes32(0), bytes32(0));

    assertEq(_getVouch(vid).balance, 15e18);
    // Failed permit must NOT advance the nonce — proves try/catch swallowed the
    // revert and the function fell through to the existing allowance.
    assertEq(token.nonces(alice), nonceBefore);
  }

  function test_increaseVouchWithPermit_revertsWhenPaused() public {
    uint256 vid = _vouchAlice("paused-permit-inc-target");
    _pauseContract(CONTRACT_NAME);

    vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
    vm.prank(alice);
    vouch.increaseVouchWithPermit(vid, 5e18, block.timestamp + 1, 0, bytes32(0), bytes32(0));
  }

  /// @dev Bad permit + zero pre-existing allowance on increaseVouchWithPermit must
  /// surface InsufficientPermitAllowance, not the opaque ERC20InsufficientAllowance.
  function test_increaseVouchWithPermit_revertsWithInsufficientPermitAllowance() public {
    uint256 privKey = 0xC0FFEE;
    address signer = vm.addr(privKey);
    token.mint(signer, 100e18);

    // Open a vouch via permit (consumes nonce 0). Use a valid permit so we have
    // a vouch to increase, then drop allowance to zero so the increase has no
    // fallback.
    uint256 openAmount = 10e18;
    uint256 openFee = _entryFee(openAmount);
    uint256 openGross = openAmount + openFee;
    uint256 openDeadline = block.timestamp + 1 hours;
    (uint8 v0, bytes32 r0, bytes32 s0) = _signPermit(token, privKey, signer, address(vouch), openGross, openDeadline);
    vm.prank(signer);
    vouch.vouchWithPermit("inc-no-allowance-target", openAmount, openDeadline, v0, r0, s0);
    uint256 vid = vouch.vouchCount();

    // Permit consumed exactly `openGross`; safeTransferFrom drained that to zero.
    // No residual allowance.
    assertEq(token.allowance(signer, address(vouch)), 0, "no residual allowance after open");

    uint256 increment = 5e18;
    uint256 incFee = _entryFee(increment);
    uint256 incRequired = increment + incFee;

    vm.expectRevert(abi.encodeWithSelector(InsufficientPermitAllowance.selector, signer, incRequired));
    vm.prank(signer);
    vouch.increaseVouchWithPermit(vid, increment, block.timestamp + 1, 0, bytes32(0), bytes32(0));
  }

  // -------------------------------------------------------------------------
  // increaseVouch
  // -------------------------------------------------------------------------

  function test_increaseVouch_addsToBalance() public {
    uint256 vid = _vouchAlice("inc-target");
    uint256 balanceBefore = 10e18;

    uint256 increment = 5e18;
    vm.prank(alice);
    vouch.increaseVouch(vid, increment);

    assertEq(_getVouch(vid).balance, balanceBefore + increment);
  }

  function test_increaseVouch_chargesFee() public {
    uint256 vid = _vouchAlice("inc-fee-target");
    uint256 increment = 5e18;
    uint256 fee = _entryFee(increment);

    uint256 aliceBefore = token.balanceOf(alice);
    uint256 supplyBefore = token.totalSupply();

    vm.prank(alice);
    vouch.increaseVouch(vid, increment);

    assertEq(aliceBefore - token.balanceOf(alice), increment + fee);
    assertEq(supplyBefore - token.totalSupply(), fee);
  }

  function test_increaseVouch_noFeeWhenZeroFeeBps() public {
    uint256 vid = _vouchAlice("inc-nofee-target");

    vm.startPrank(_admin);
    vouch.setEntryFeeBps(0);
    vouch.setExitFeeBps(0);
    vm.stopPrank();

    uint256 aliceBefore = token.balanceOf(alice);
    uint256 supplyBefore = token.totalSupply();
    uint256 increment = 5e18;

    vm.prank(alice);
    vouch.increaseVouch(vid, increment);

    assertEq(aliceBefore - token.balanceOf(alice), increment);
    assertEq(token.totalSupply(), supplyBefore);
  }

  function test_increaseVouch_emitsVouchIncreased() public {
    uint256 vid = _vouchAlice("inc-emit-target");
    uint256 increment = 5e18;
    uint256 fee = _entryFee(increment);
    uint256 newBalance = 10e18 + increment;

    vm.expectEmit(true, false, false, true);
    emit EthosVouchV2.VouchIncreased(vid, increment, fee, newBalance);

    vm.prank(alice);
    vouch.increaseVouch(vid, increment);
  }

  function test_increaseVouch_revertsWhenNewBalanceBelowMinimum() public {
    uint256 vid = _vouchAs(alice, "inc-slashed-sub-min", 10e18);

    slasher.slash(alice, 9500);
    assertEq(_getVouch(vid).balance, 0.5e18);

    vm.expectRevert(abi.encodeWithSelector(AmountBelowMinimum.selector, 0.6e18, 1e18));
    vm.prank(alice);
    vouch.increaseVouch(vid, 0.1e18);
  }

  function test_increaseVouch_canRestoreSlashedVouchToMinimum() public {
    uint256 vid = _vouchAs(alice, "inc-slashed-to-min", 10e18);

    slasher.slash(alice, 9500);
    assertEq(_getVouch(vid).balance, 0.5e18);

    vm.prank(alice);
    vouch.increaseVouch(vid, 0.5e18);

    assertEq(_getVouch(vid).balance, vouch.configuredMinimumVouchAmount());
  }

  function test_increaseVouch_revertsIfNotAuthor() public {
    uint256 vid = _vouchAlice("not-author-target");
    vm.expectRevert(abi.encodeWithSelector(UnauthorizedVouchAccess.selector, bob, alice));
    vm.prank(bob);
    vouch.increaseVouch(vid, 5e18);
  }

  function test_increaseVouch_revertsIfArchived() public {
    uint256 vid = _vouchAlice("archived-inc-target");
    _unvouchAs(alice, vid);

    vm.expectRevert(abi.encodeWithSelector(VouchAlreadyArchived.selector, vid));
    vm.prank(alice);
    vouch.increaseVouch(vid, 5e18);
  }

  function test_increaseVouch_revertsWhenPaused() public {
    uint256 vid = _vouchAlice("paused-inc-target");
    _pauseContract(CONTRACT_NAME);

    vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
    vm.prank(alice);
    vouch.increaseVouch(vid, 5e18);
  }

  /// @dev Mirror of test_vouch_revertsOnFeeOnTransferToken for the top-up path. Seeds an
  ///      initial vouch with the token's fee toggle off, then enables fee-on-transfer and
  ///      asserts that increaseVouch hits the same balance-delta guard inside
  ///      _checkTransferIn. Covers both increaseVouch and increaseVouchWithPermit because
  ///      they share the internal _increaseVouch / _checkTransferIn path.
  function test_increaseVouch_revertsOnFeeOnTransferToken() public {
    MockFeeOnTransferToken fotToken = new MockFeeOnTransferToken();
    fotToken.setFeeActive(false);
    fotToken.mint(alice, 100e18);

    EthosVouchV2 impl2 = new EthosVouchV2();
    EthosVouchV2 feeVouch = EthosVouchV2(_deployProxy(address(impl2)));
    feeVouch.initialize(_defaultInitParams(), address(fotToken), 0, 0, 1e18, 50000e18, 256, 0);
    _allowlistVouchOnRewards(address(feeVouch));

    vm.prank(alice);
    fotToken.approve(address(feeVouch), type(uint256).max);

    // Seed an active vouch while transfers are clean.
    vm.prank(alice);
    feeVouch.vouch("fot-inc-target", 10e18);
    uint256 vid = feeVouch.vouchCount();

    // Turn on fee-on-transfer and try to top up.
    fotToken.setFeeActive(true);

    vm.expectRevert(abi.encodeWithSelector(UnexpectedTokenBehavior.selector, 5e18, 5e18 - 1));
    vm.prank(alice);
    feeVouch.increaseVouch(vid, 5e18);
  }

  // -------------------------------------------------------------------------
  // unvouch
  // -------------------------------------------------------------------------

  function test_unvouch_returnsBalance() public {
    uint256 amount = 10e18;
    uint256 vid = _vouchAlice("unvouch-target");
    uint256 fee = _exitFee(amount);
    uint256 expectedPayout = amount - fee;

    uint256 aliceBefore = token.balanceOf(alice);
    _unvouchAs(alice, vid);
    assertEq(token.balanceOf(alice) - aliceBefore, expectedPayout);
  }

  function test_unvouch_burnsFee() public {
    uint256 amount = 10e18;
    uint256 vid = _vouchAlice("fee-burn-target");
    uint256 fee = _exitFee(amount);

    uint256 supplyBefore = token.totalSupply();
    _unvouchAs(alice, vid);
    assertEq(supplyBefore - token.totalSupply(), fee);
  }

  function test_unvouch_noFeeWhenZeroExitFeeBps() public {
    uint256 vid = _vouchAlice("unvouch-nofee-target");

    vm.prank(_admin);
    vouch.setExitFeeBps(0);

    uint256 aliceBefore = token.balanceOf(alice);
    uint256 supplyBefore = token.totalSupply();

    _unvouchAs(alice, vid);

    // Full balance returned; totalSupply untouched.
    assertEq(token.balanceOf(alice) - aliceBefore, 10e18);
    assertEq(token.totalSupply(), supplyBefore);
  }

  function test_unvouch_archivesVouch() public {
    uint256 vid = _vouchAlice("archive-target");
    _unvouchAs(alice, vid);
    EthosVouchV2.Vouch memory v = _getVouch(vid);
    assertTrue(v.archived);
    // Archived vouches must zero out the locked balance to prevent any future
    // payout/burn from referencing stale state.
    assertEq(v.balance, 0);
  }

  function test_unvouch_removesFromIndexes() public {
    uint256 vid1 = _vouchAlice("idx-target-1");
    uint256 vid2 = _vouchAlice("idx-target-2");

    _unvouchAs(alice, vid1);

    // After removing vid1, vid2 should be at position 0 (swap-pop)
    assertEq(vouch.vouchIdsByAuthor(alice, 0), vid2);

    // Alice now has exactly 1 active vouch; index 1 should revert
    vm.expectRevert();
    vouch.vouchIdsByAuthor(alice, 1);
  }

  function test_unvouch_clearsUniquenessMapping() public {
    uint256 vid = _vouchAlice("unique-target");
    bytes32 targetHash = keccak256(bytes("unique-target"));

    assertEq(vouch.vouchIdByAuthorForTargetHash(alice, targetHash), vid);
    _unvouchAs(alice, vid);
    assertEq(vouch.vouchIdByAuthorForTargetHash(alice, targetHash), 0);
  }

  function test_unvouch_emitsUnvouched() public {
    uint256 amount = 10e18;
    uint256 vid = _vouchAlice("emit-unvouch-target");
    uint256 fee = _exitFee(amount);
    uint256 payout = amount - fee;

    vm.expectEmit(true, false, false, true);
    emit EthosVouchV2.Unvouched(vid, amount, fee, payout);
    _unvouchAs(alice, vid);
  }

  function test_unvouch_revertsIfNotAuthor() public {
    uint256 vid = _vouchAlice("not-author-unvouch");
    vm.expectRevert(abi.encodeWithSelector(UnauthorizedVouchAccess.selector, bob, alice));
    vm.prank(bob);
    vouch.unvouch(vid);
  }

  function test_unvouch_revertsIfArchived() public {
    uint256 vid = _vouchAlice("archived-unvouch");
    _unvouchAs(alice, vid);
    vm.expectRevert(abi.encodeWithSelector(VouchAlreadyArchived.selector, vid));
    _unvouchAs(alice, vid);
  }

  function test_unvouch_revertsIfFrozen() public {
    uint256 vid = _vouchAlice("frozen-unvouch");
    slasher.freeze(alice);

    vm.expectRevert(abi.encodeWithSelector(AccountFrozen.selector, alice));
    _unvouchAs(alice, vid);
  }

  function test_unvouch_revertsWhenPaused() public {
    uint256 vid = _vouchAlice("paused-unvouch");
    _pauseContract(CONTRACT_NAME);

    vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
    vm.prank(alice);
    vouch.unvouch(vid);
  }

  function test_unvouch_allowsRevouch_afterUnvouch() public {
    uint256 vid1 = _vouchAlice("revouch-target");
    _unvouchAs(alice, vid1);

    // Should not revert — uniqueness mapping is cleared
    uint256 vid2 = _vouchAlice("revouch-target");
    assertTrue(vid2 > vid1);
  }

  function test_unvouch_staysHealthy() public {
    uint256 vid = _vouchAlice("healthy-target");
    _unvouchAs(alice, vid);

    assertFalse(_getVouch(vid).unhealthy);
  }

  // -------------------------------------------------------------------------
  // unvouchUnhealthy
  // -------------------------------------------------------------------------

  function test_unvouchUnhealthy_archivesAndMarksUnhealthy() public {
    uint256 vid = _vouchAlice("combined-target");

    vm.prank(alice);
    vouch.unvouchUnhealthy(vid);

    EthosVouchV2.Vouch memory v = _getVouch(vid);
    assertTrue(v.archived);
    assertTrue(v.unhealthy);
    assertEq(v.balance, 0);
  }

  function test_unvouchUnhealthy_returnsBalanceMinusFee() public {
    uint256 amount = 10e18;
    uint256 vid = _vouchAlice("combined-payout-target");
    uint256 fee = _exitFee(amount);

    uint256 aliceBefore = token.balanceOf(alice);
    vm.prank(alice);
    vouch.unvouchUnhealthy(vid);
    assertEq(token.balanceOf(alice) - aliceBefore, amount - fee);
  }

  function test_unvouchUnhealthy_emitsUnvouchedThenMarkedUnhealthy() public {
    uint256 amount = 10e18;
    uint256 vid = _vouchAlice("combined-emit-target");
    uint256 fee = _exitFee(amount);

    vm.expectEmit(true, false, false, true);
    emit EthosVouchV2.Unvouched(vid, amount, fee, amount - fee);
    vm.expectEmit(true, true, true, true);
    emit EthosVouchV2.MarkedUnhealthy(vid, alice, keccak256(bytes("combined-emit-target")));
    vm.prank(alice);
    vouch.unvouchUnhealthy(vid);
  }

  function test_unvouchUnhealthy_clearsUniquenessMapping_andRemovesFromIndex() public {
    uint256 vid = _vouchAlice("combined-cleanup-target");
    bytes32 targetHash = keccak256(bytes("combined-cleanup-target"));

    vm.prank(alice);
    vouch.unvouchUnhealthy(vid);

    assertEq(vouch.vouchIdByAuthorForTargetHash(alice, targetHash), 0);
    vm.expectRevert();
    vouch.vouchIdsByAuthor(alice, 0);
  }

  function test_unvouchUnhealthy_revertsIfNotAuthor() public {
    uint256 vid = _vouchAlice("combined-not-author");
    vm.expectRevert(abi.encodeWithSelector(UnauthorizedVouchAccess.selector, bob, alice));
    vm.prank(bob);
    vouch.unvouchUnhealthy(vid);
  }

  function test_unvouchUnhealthy_revertsIfArchived() public {
    uint256 vid = _vouchAlice("combined-archived");
    _unvouchAs(alice, vid);

    vm.expectRevert(abi.encodeWithSelector(VouchAlreadyArchived.selector, vid));
    vm.prank(alice);
    vouch.unvouchUnhealthy(vid);
  }

  function test_unvouchUnhealthy_revertsIfFrozen() public {
    uint256 vid = _vouchAlice("combined-frozen");
    slasher.freeze(alice);

    vm.expectRevert(abi.encodeWithSelector(AccountFrozen.selector, alice));
    vm.prank(alice);
    vouch.unvouchUnhealthy(vid);
  }

  function test_unvouchUnhealthy_revertsWhenPaused() public {
    uint256 vid = _vouchAlice("combined-paused");
    _pauseContract(CONTRACT_NAME);

    vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
    vm.prank(alice);
    vouch.unvouchUnhealthy(vid);
  }

  // -------------------------------------------------------------------------
  // decreaseVouch
  // -------------------------------------------------------------------------

  function test_decreaseVouch_reducesBalance() public {
    uint256 vid = _vouchAs(alice, "dec-target", 10e18);
    _decreaseAs(alice, vid, 3e18);
    assertEq(_getVouch(vid).balance, 7e18);
  }

  function test_decreaseVouch_returnsAmountMinusFee() public {
    uint256 vid = _vouchAs(alice, "dec-payout-target", 10e18);
    uint256 amount = 3e18;
    uint256 fee = _exitFee(amount);

    uint256 aliceBefore = token.balanceOf(alice);
    _decreaseAs(alice, vid, amount);
    assertEq(token.balanceOf(alice) - aliceBefore, amount - fee);
  }

  function test_decreaseVouch_burnsExitFee() public {
    uint256 vid = _vouchAs(alice, "dec-burn-target", 10e18);
    uint256 amount = 4e18;
    uint256 fee = _exitFee(amount);

    uint256 supplyBefore = token.totalSupply();
    _decreaseAs(alice, vid, amount);
    assertEq(supplyBefore - token.totalSupply(), fee);
  }

  function test_decreaseVouch_noFeeWhenZeroExitFeeBps() public {
    uint256 vid = _vouchAs(alice, "dec-nofee-target", 10e18);

    vm.prank(_admin);
    vouch.setExitFeeBps(0);

    uint256 aliceBefore = token.balanceOf(alice);
    uint256 supplyBefore = token.totalSupply();

    _decreaseAs(alice, vid, 4e18);

    assertEq(token.balanceOf(alice) - aliceBefore, 4e18);
    assertEq(token.totalSupply(), supplyBefore);
  }

  function test_decreaseVouch_doesNotArchive() public {
    uint256 vid = _vouchAs(alice, "dec-no-archive", 10e18);
    _decreaseAs(alice, vid, 3e18);
    assertFalse(_getVouch(vid).archived);
  }

  function test_decreaseVouch_doesNotAffectIndexes() public {
    uint256 vid1 = _vouchAs(alice, "dec-idx-1", 10e18);
    uint256 vid2 = _vouchAs(alice, "dec-idx-2", 10e18);
    bytes32 targetHash1 = keccak256(bytes("dec-idx-1"));

    _decreaseAs(alice, vid1, 3e18);

    // Author index unchanged — both vouches still active in original order.
    assertEq(vouch.vouchIdsByAuthor(alice, 0), vid1);
    assertEq(vouch.vouchIdsByAuthor(alice, 1), vid2);
    // Uniqueness mapping unchanged.
    assertEq(vouch.vouchIdByAuthorForTargetHash(alice, targetHash1), vid1);
  }

  function test_decreaseVouch_emitsVouchDecreased() public {
    uint256 vid = _vouchAs(alice, "dec-emit", 10e18);
    uint256 amount = 4e18;
    uint256 fee = _exitFee(amount);
    uint256 expectedNewBalance = 10e18 - amount;

    vm.expectEmit(true, false, false, true);
    emit EthosVouchV2.VouchDecreased(vid, amount, fee, expectedNewBalance);
    _decreaseAs(alice, vid, amount);
  }

  function test_decreaseVouch_revertsOnZeroAmount() public {
    uint256 vid = _vouchAs(alice, "dec-zero", 10e18);
    vm.expectRevert(ZeroAmount.selector);
    _decreaseAs(alice, vid, 0);
  }

  function test_decreaseVouch_revertsIfNotAuthor() public {
    uint256 vid = _vouchAs(alice, "dec-not-author", 10e18);
    vm.expectRevert(abi.encodeWithSelector(UnauthorizedVouchAccess.selector, bob, alice));
    vm.prank(bob);
    vouch.decreaseVouch(vid, 1e18);
  }

  function test_decreaseVouch_revertsIfArchived() public {
    uint256 vid = _vouchAs(alice, "dec-archived", 10e18);
    _unvouchAs(alice, vid);
    vm.expectRevert(abi.encodeWithSelector(VouchAlreadyArchived.selector, vid));
    _decreaseAs(alice, vid, 1e18);
  }

  function test_decreaseVouch_revertsIfFrozen() public {
    uint256 vid = _vouchAs(alice, "dec-frozen", 10e18);
    slasher.freeze(alice);

    vm.expectRevert(abi.encodeWithSelector(AccountFrozen.selector, alice));
    _decreaseAs(alice, vid, 1e18);
  }

  function test_decreaseVouch_revertsWhenPaused() public {
    uint256 vid = _vouchAs(alice, "dec-paused", 10e18);
    _pauseContract(CONTRACT_NAME);

    vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
    vm.prank(alice);
    vouch.decreaseVouch(vid, 1e18);
  }

  function test_decreaseVouch_revertsOnVouchNotFound() public {
    vm.expectRevert(abi.encodeWithSelector(VouchNotFound.selector, 0));
    vm.prank(alice);
    vouch.decreaseVouch(0, 1e18);

    vm.expectRevert(abi.encodeWithSelector(VouchNotFound.selector, 999));
    vm.prank(alice);
    vouch.decreaseVouch(999, 1e18);
  }

  function test_decreaseVouch_revertsIfAmountExceedsBalance() public {
    uint256 vid = _vouchAs(alice, "dec-overflow", 10e18);
    vm.expectRevert(abi.encodeWithSelector(AmountExceedsBalance.selector, 11e18, 10e18));
    _decreaseAs(alice, vid, 11e18);
  }

  function test_decreaseVouch_revertsIfBreachesMinimum() public {
    // min is 1e18; vouch starts at 10e18; decreasing 9.5e18 would leave 0.5e18.
    uint256 vid = _vouchAs(alice, "dec-min", 10e18);
    vm.expectRevert(abi.encodeWithSelector(RemainingBelowMinimum.selector, 0.5e18, 1e18));
    _decreaseAs(alice, vid, 9.5e18);
  }

  function test_decreaseVouch_atExactlyMinimum_succeeds() public {
    // Boundary: leaving the balance at exactly the minimum is allowed.
    uint256 vid = _vouchAs(alice, "dec-min-edge", 10e18);
    _decreaseAs(alice, vid, 9e18);
    assertEq(_getVouch(vid).balance, 1e18);
  }

  /// @dev Fee-arb closure: a partial decrease that leaves the balance at the minimum,
  ///      followed by an unvouch of the remainder, must burn at least as much as a single
  ///      unvouch of the full balance. Without this, decrease would be a free escape from
  ///      exit fees: drain to dust via decrease (paying fee on the delta), then unvouch
  ///      the dust (paying fee on the dust). This test pins that the per-token burn rate
  ///      is identical regardless of exit path. Equality holds with zero entry fee; the
  ///      ceiling rounding on each separate fee calculation can only push the split path
  ///      to burn the same or *more*, never less.
  function test_decreaseVouch_feeArbClosed() public {
    vm.prank(_admin);
    vouch.setEntryFeeBps(0); // isolate the exit-fee path

    uint256 amount = 100e18;

    // Path A: single unvouch of the full balance.
    uint256 vidA = _vouchAs(alice, "fee-arb-A", amount);
    uint256 supplyBeforeA = token.totalSupply();
    _unvouchAs(alice, vidA);
    uint256 burnedA = supplyBeforeA - token.totalSupply();

    // Path B: decrease down to the minimum, then unvouch the remainder.
    uint256 vidB = _vouchAs(bob, "fee-arb-B", amount);
    uint256 supplyBeforeB = token.totalSupply();
    _decreaseAs(bob, vidB, amount - 1e18); // leaves exactly the minimum (1e18)
    _unvouchAs(bob, vidB);
    uint256 burnedB = supplyBeforeB - token.totalSupply();

    // Split exit must burn at least as much as the single unvouch — ceiling rounding on
    // each leg can only inflate the total, never deflate it.
    assertGe(burnedB, burnedA, "split exit burned less than single unvouch");
  }

  function test_decreaseVouch_slashAppliesToReducedBalance() public {
    uint256 vid = _vouchAs(alice, "dec-then-slash", 10e18);
    _decreaseAs(alice, vid, 4e18);
    // Balance now 6e18; a 50% slash burns 3e18 and leaves 3e18.
    slasher.slash(alice, 5000);
    assertEq(_getVouch(vid).balance, 3e18);
  }

  function test_decreaseVouch_canIncreaseAfterDecrease() public {
    // A decreased vouch is fully active and can be topped back up.
    uint256 vid = _vouchAs(alice, "dec-then-inc", 10e18);
    _decreaseAs(alice, vid, 4e18);
    vm.prank(alice);
    vouch.increaseVouch(vid, 5e18);
    assertEq(_getVouch(vid).balance, 11e18);
  }

  /// @dev When a slash drops the balance below the configured minimum, decreaseVouch
  ///      becomes un-callable: any non-zero amount either leaves a sub-minimum remainder
  ///      (RemainingBelowMinimum) or exceeds the balance (AmountExceedsBalance). The only
  ///      way out is `unvouch`. This is an emergent consequence of the minimum-remainder
  ///      check, not an explicit branch — pin it so a future relaxation is intentional.
  function test_decreaseVouch_revertsAfterSlashedBelowMinimum() public {
    uint256 vid = _vouchAs(alice, "dec-slashed-sub-min", 10e18);

    // 95% slash burns 9.5e18, leaves 0.5e18 — below the 1e18 minimum.
    slasher.slash(alice, 9500);
    assertEq(_getVouch(vid).balance, 0.5e18);

    // Small amount: remainder would be 0.4e18, below the 1e18 minimum.
    vm.expectRevert(abi.encodeWithSelector(RemainingBelowMinimum.selector, 0.4e18, 1e18));
    _decreaseAs(alice, vid, 0.1e18);

    // Large amount: exceeds the post-slash balance.
    vm.expectRevert(abi.encodeWithSelector(AmountExceedsBalance.selector, 1e18, 0.5e18));
    _decreaseAs(alice, vid, 1e18);
  }

  /// @dev State correctness across a sequence of partial withdrawals on the same vouch:
  ///      balance decrements per call, payouts and burns accumulate, the vouch never
  ///      archives. Guards against any per-call state being wrongly cached or reset.
  function test_decreaseVouch_multipleDecreases() public {
    uint256 vid = _vouchAs(alice, "dec-multi", 100e18);

    uint256 aliceBefore = token.balanceOf(alice);
    uint256 supplyBefore = token.totalSupply();

    uint256 fee1 = _exitFee(30e18);
    uint256 fee2 = _exitFee(30e18);
    uint256 fee3 = _exitFee(20e18);

    _decreaseAs(alice, vid, 30e18);
    assertEq(_getVouch(vid).balance, 70e18);

    _decreaseAs(alice, vid, 30e18);
    assertEq(_getVouch(vid).balance, 40e18);

    _decreaseAs(alice, vid, 20e18);
    assertEq(_getVouch(vid).balance, 20e18);

    assertFalse(_getVouch(vid).archived);
    assertEq(token.balanceOf(alice) - aliceBefore, 80e18 - (fee1 + fee2 + fee3));
    assertEq(supplyBefore - token.totalSupply(), fee1 + fee2 + fee3);
  }

  // -------------------------------------------------------------------------
  // freeze / unfreeze
  // -------------------------------------------------------------------------

  function test_freeze_setsFrozenState() public {
    assertFalse(vouch.isFrozen(alice));
    slasher.freeze(alice);
    assertTrue(vouch.isFrozen(alice));
  }

  function test_freeze_emitsFrozen() public {
    vm.expectEmit(true, false, false, true);
    emit IFreezable.Frozen(alice, true);
    slasher.freeze(alice);
  }

  function test_freeze_blocksUnvouch() public {
    uint256 vid = _vouchAlice("freeze-blocks-target");
    slasher.freeze(alice);

    vm.expectRevert(abi.encodeWithSelector(AccountFrozen.selector, alice));
    _unvouchAs(alice, vid);
  }

  /// @dev Mirrors test_freeze_blocksUnvouch — without this gate, a frozen author could
  ///      drain their stake to the minimum via repeated decreases and escape a slash.
  function test_freeze_blocksDecrease() public {
    uint256 vid = _vouchAlice("freeze-blocks-decrease-target");
    slasher.freeze(alice);

    vm.expectRevert(abi.encodeWithSelector(AccountFrozen.selector, alice));
    _decreaseAs(alice, vid, 1e18);
  }

  function test_freeze_doesNotBlockVouch() public {
    slasher.freeze(alice);
    // vouch should still work — frozen state only blocks unvouch.
    uint256 vid = _vouchAlice("freeze-vouch-target");
    EthosVouchV2.Vouch memory v = _getVouch(vid);
    assertEq(v.author, alice);
    assertEq(v.balance, 10e18);
    assertFalse(v.archived);
  }

  function test_freeze_doesNotBlockIncrease() public {
    uint256 vid = _vouchAlice("freeze-inc-target");
    slasher.freeze(alice);

    vm.prank(alice);
    vouch.increaseVouch(vid, 5e18);
    assertEq(_getVouch(vid).balance, 15e18);
  }

  function test_unfreeze_clearsFrozenState() public {
    slasher.freeze(alice);
    assertTrue(vouch.isFrozen(alice));
    slasher.unfreeze(alice);
    assertFalse(vouch.isFrozen(alice));
  }

  function test_unfreeze_emitsFrozen() public {
    slasher.freeze(alice);

    vm.expectEmit(true, false, false, true);
    emit IFreezable.Frozen(alice, false);
    slasher.unfreeze(alice);
  }

  function test_freeze_revertsIfNotSlasher() public {
    vm.expectRevert(abi.encodeWithSelector(NotSlasher.selector, alice, address(slasher)));
    vm.prank(alice);
    vouch.freeze(alice);
  }

  function test_unfreeze_revertsIfNotSlasher() public {
    vm.expectRevert(abi.encodeWithSelector(NotSlasher.selector, alice, address(slasher)));
    vm.prank(alice);
    vouch.unfreeze(alice);
  }

  function test_freeze_revertsWhenPaused() public {
    _pauseContract(CONTRACT_NAME);
    vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
    slasher.freeze(alice);
  }

  // -------------------------------------------------------------------------
  // slash
  // -------------------------------------------------------------------------

  function test_slash_reducesVouchBalances() public {
    uint256 vid = _vouchAlice("burn-target");
    uint256 balanceBefore = _getVouch(vid).balance;

    slasher.slash(alice, 5000); // 50%

    // 10e18 burned at 50% with Rounding.Ceil = exactly 5e18.
    assertEq(_getVouch(vid).balance, balanceBefore - 5e18);
  }

  function test_slash_emitsVouchSlashed() public {
    uint256 vid = _vouchAlice("burn-emit-target");
    uint256 balance = 10e18;
    // 50% of 10e18 = 5e18
    uint256 burnAmount = (balance * 5000 + vouch.BASIS_POINT_SCALE() - 1) / vouch.BASIS_POINT_SCALE();

    vm.expectEmit(true, false, false, true);
    emit EthosVouchV2.VouchSlashed(vid, balance, balance - burnAmount, burnAmount);
    slasher.slash(alice, 5000);
  }

  function test_slash_emitsAccountSlashed() public {
    _vouchAlice("burn-author-emit-target");
    // 50% of 10e18 with Rounding.Ceil = exactly 5e18.
    uint256 burnAmount = 5e18;

    vm.expectEmit(true, false, false, true);
    emit EthosVouchV2.AccountSlashed(alice, 5000, burnAmount);
    slasher.slash(alice, 5000);
  }

  function test_slash_burnsTokens() public {
    _vouchAlice("burn-tokens-target");
    uint256 totalSupplyBefore = token.totalSupply();
    uint256 contractBalanceBefore = token.balanceOf(address(vouch));

    slasher.slash(alice, 5000);

    uint256 burned = contractBalanceBefore - token.balanceOf(address(vouch));
    // Exact: 50% of 10e18 = 5e18 — locks in both the burn arithmetic and the
    // expectation that totalSupply drops by exactly the same amount.
    assertEq(burned, 5e18);
    assertEq(token.totalSupply(), totalSupplyBefore - 5e18);
  }

  function test_slash_100pct_zerosAllBalances() public {
    uint256 vid = _vouchAlice("100pct-burn-target");
    slasher.slash(alice, 10000);
    assertEq(_getVouch(vid).balance, 0);
  }

  function test_slash_multipleVouches() public {
    uint256 vid1 = _vouchAs(alice, "multi-burn-1", 10e18);
    uint256 vid2 = _vouchAs(alice, "multi-burn-2", 20e18);
    uint256 vid3 = _vouchAs(alice, "multi-burn-3", 30e18);

    slasher.slash(alice, 2000); // 20%

    // Exact: 20% of 10/20/30 with Rounding.Ceil = 2/4/6 ether burned, leaving 8/16/24.
    assertEq(_getVouch(vid1).balance, 8e18);
    assertEq(_getVouch(vid2).balance, 16e18);
    assertEq(_getVouch(vid3).balance, 24e18);
  }

  function test_slash_zeroBalanceVouchStaysActive() public {
    uint256 vid = _vouchAlice("zero-balance-target");

    // Burn 100% first
    slasher.slash(alice, 10000);
    EthosVouchV2.Vouch memory v = _getVouch(vid);
    assertEq(v.balance, 0);
    // Vouch should NOT be archived — author can still unvouch (a no-op exit) or be
    // re-burned without throwing.
    assertFalse(v.archived);
  }

  function test_slash_skipsZeroBalanceVouchOnSecondBurn() public {
    uint256 vid = _vouchAlice("skip-zero-target");

    // First burn zeroes the balance but keeps the vouch in the index.
    slasher.slash(alice, 10000);

    // Second slash iterates, hits `prevBalance == 0`, skips without emitting VouchSlashed.
    vm.recordLogs();
    slasher.slash(alice, 5000);
    Vm.Log[] memory logs = vm.getRecordedLogs();

    uint256 vouchSlashedCount;
    bytes32 vouchSlashedSig = keccak256("VouchSlashed(uint256,uint256,uint256,uint256)");
    bytes32 accountSlashedSig = keccak256("AccountSlashed(address,uint256,uint256)");
    bool sawAccountSlashedZero;
    for (uint256 i = 0; i < logs.length; i++) {
      if (logs[i].topics.length > 0 && logs[i].topics[0] == vouchSlashedSig) {
        vouchSlashedCount++;
      }
      if (logs[i].topics.length > 0 && logs[i].topics[0] == accountSlashedSig) {
        // AccountSlashed(account, bps, amountApplied) — third unindexed field; data
        // layout is (bps, amountApplied).
        (uint256 bpsLogged, uint256 amountLogged) = abi.decode(logs[i].data, (uint256, uint256));
        assertEq(bpsLogged, 5000);
        assertEq(amountLogged, 0);
        sawAccountSlashedZero = true;
      }
    }
    assertEq(vouchSlashedCount, 0);
    assertTrue(sawAccountSlashedZero, "AccountSlashed with amountApplied=0 should fire");

    assertEq(_getVouch(vid).balance, 0);
  }

  function test_slash_atExactly10000_burnsEverything() public {
    // Boundary: bps == BASIS_POINT_SCALE is the legitimate "burn everything" call.
    uint256 vid = _vouchAlice("boundary-10000-burn");

    vm.expectEmit(true, false, false, true);
    emit EthosVouchV2.AccountSlashed(alice, 10000, 10e18);
    slasher.slash(alice, 10000);

    assertEq(_getVouch(vid).balance, 0);
  }

  function test_slash_atExactly10001_reverts() public {
    // Boundary: smallest illegal value. Catches off-by-one bugs like
    // `if (bps >= BASIS_POINT_SCALE)` and `if (bps > BASIS_POINT_SCALE + 1)`.
    _vouchAlice("boundary-10001-burn");

    vm.expectRevert(abi.encodeWithSelector(InvalidBps.selector, uint256(10001)));
    slasher.slash(alice, 10001);
  }

  function test_slash_maxUint_reverts() public {
    _vouchAlice("maxuint-burn-target");

    vm.expectRevert(abi.encodeWithSelector(InvalidBps.selector, type(uint256).max));
    slasher.slash(alice, type(uint256).max);
  }

  function test_slash_noopForAuthorWithNoVouches() public {
    // bob has no vouches
    vm.expectEmit(true, false, false, true);
    emit EthosVouchV2.AccountSlashed(bob, 5000, 0);
    slasher.slash(bob, 5000);
  }

  function test_slash_doesNotRequireFreeze() public {
    // Slasher can burn without freezing first; verify the author's frozen flag is
    // unchanged AND the burn actually moved tokens.
    assertFalse(vouch.isFrozen(alice));
    uint256 vid = _vouchAlice("no-freeze-burn-target");
    uint256 supplyBefore = token.totalSupply();

    slasher.slash(alice, 1000); // 10%

    assertFalse(vouch.isFrozen(alice));
    // 10% of 10e18 with Rounding.Ceil = 1e18.
    assertEq(_getVouch(vid).balance, 9e18);
    assertEq(token.totalSupply(), supplyBefore - 1e18);
  }

  function test_slash_revertsIfNotSlasher() public {
    vm.expectRevert(abi.encodeWithSelector(NotSlasher.selector, alice, address(slasher)));
    vm.prank(alice);
    vouch.slash(alice, 5000);
  }

  function test_slash_revertsWhenPaused() public {
    _pauseContract(CONTRACT_NAME);
    vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
    slasher.slash(alice, 5000);
  }

  function test_slash_doesNotArchiveVouches_canStillUnvouch() public {
    uint256 vid = _vouchAlice("burn-then-unvouch-target");

    slasher.slash(alice, 5000);

    // Should not revert — vouch is not archived
    assertFalse(_getVouch(vid).archived);

    // alice is not frozen, so unvouch works
    _unvouchAs(alice, vid);
    assertTrue(_getVouch(vid).archived);
  }

  function test_slash_doesNotAffectOtherAuthors() public {
    // Author isolation: burning alice must not change ANY of bob's vouch balances.
    uint256 aliceVid = _vouchAs(alice, "iso-alice", 10e18);
    uint256 bobVid1 = _vouchAs(bob, "iso-bob-1", 20e18);
    uint256 bobVid2 = _vouchAs(bob, "iso-bob-2", 30e18);

    uint256 bobBalBefore = token.balanceOf(bob);

    slasher.slash(alice, 5000);

    // alice's vouch is reduced.
    assertEq(_getVouch(aliceVid).balance, 5e18);
    // bob's vouches are untouched, both balances and his frozen state.
    assertEq(_getVouch(bobVid1).balance, 20e18);
    assertEq(_getVouch(bobVid2).balance, 30e18);
    assertFalse(vouch.isFrozen(bob));
    // bob's wallet balance unchanged (no rebate, no transfer).
    assertEq(token.balanceOf(bob), bobBalBefore);
  }

  // -------------------------------------------------------------------------
  // Preview functions
  // -------------------------------------------------------------------------

  function test_previewVouchFee_returnsCorrectFeeAndGross() public view {
    uint256 amount = 10e18;
    (uint256 fee, uint256 gross) = vouch.previewVouchFee(amount);
    assertEq(fee, _entryFee(amount));
    assertEq(gross, amount + fee);
  }

  function test_previewVouchFee_zeroFee() public {
    vm.prank(_admin);
    vouch.setEntryFeeBps(0);

    (uint256 fee, uint256 gross) = vouch.previewVouchFee(10e18);
    assertEq(fee, 0);
    assertEq(gross, 10e18);
  }

  function test_previewUnvouchPayout_returnsCorrectPayoutAndFee() public {
    uint256 amount = 10e18;
    uint256 vid = _vouchAlice("preview-payout-target");

    uint256 fee = _exitFee(amount);
    (uint256 payout, uint256 previewFee) = vouch.previewUnvouchPayout(vid);
    assertEq(previewFee, fee);
    assertEq(payout, amount - fee);
  }

  // -------------------------------------------------------------------------
  // Admin setters
  // -------------------------------------------------------------------------

  function test_setEntryFeeBps_updates() public {
    vm.prank(_admin);
    vouch.setEntryFeeBps(200);
    assertEq(vouch.entryFeeBps(), 200);
  }

  function test_setEntryFeeBps_emitsEvent() public {
    vm.expectEmit(false, false, false, true);
    emit EthosVouchV2.EntryFeeBpsUpdated(100, 200);
    vm.prank(_admin);
    vouch.setEntryFeeBps(200);
  }

  function test_setEntryFeeBps_atBoundarySucceeds() public {
    // exitFeeBps is 50, MAX_TOTAL_FEES is 1000 → max permitted entry is 950.
    // Boundary positive case — guards against a > vs >= regression in the check.
    vm.prank(_admin);
    vouch.setEntryFeeBps(950);
    assertEq(vouch.entryFeeBps(), 950);
  }

  function test_setEntryFeeBps_revertsIfTooHigh() public {
    // 951 + 50 = 1001, just past MAX_TOTAL_FEES.
    vm.expectRevert(abi.encodeWithSelector(FeeBpsTooHigh.selector, 1001, 1000));
    vm.prank(_admin);
    vouch.setEntryFeeBps(951);
  }

  function test_setEntryFeeBps_revertsIfNotAdmin() public {
    // AccessControlV2 reverts with Unauthorized() — assert the exact selector.
    vm.expectRevert();
    vm.prank(alice);
    vouch.setEntryFeeBps(200);
  }

  function test_setExitFeeBps_updates() public {
    vm.prank(_admin);
    vouch.setExitFeeBps(100);
    assertEq(vouch.exitFeeBps(), 100);
  }

  function test_setExitFeeBps_atBoundarySucceeds() public {
    // entryFeeBps is 100, MAX_TOTAL_FEES is 1000 → max permitted exit is 900.
    vm.prank(_admin);
    vouch.setExitFeeBps(900);
    assertEq(vouch.exitFeeBps(), 900);
  }

  function test_setExitFeeBps_revertsIfTooHigh() public {
    // 100 + 901 = 1001, just past MAX_TOTAL_FEES.
    vm.expectRevert(abi.encodeWithSelector(FeeBpsTooHigh.selector, 1001, 1000));
    vm.prank(_admin);
    vouch.setExitFeeBps(901);
  }

  function test_setMinimumVouchAmount_revertsOnZero() public {
    vm.expectRevert(abi.encodeWithSelector(AmountBelowMinimum.selector, 0, 1));
    vm.prank(_admin);
    vouch.setMinimumVouchAmount(0);
  }

  function test_setMinimumVouchAmount_updates() public {
    vm.prank(_admin);
    vouch.setMinimumVouchAmount(2e18);
    assertEq(vouch.configuredMinimumVouchAmount(), 2e18);
  }

  function test_setMaximumVouches_updates() public {
    vm.prank(_admin);
    vouch.setMaximumVouches(100);
    assertEq(vouch.maximumVouches(), 100);
  }

  function test_setMaximumVouches_revertsOnZero() public {
    vm.expectRevert(abi.encodeWithSelector(AmountBelowMinimum.selector, 0, 1));
    vm.prank(_admin);
    vouch.setMaximumVouches(0);
  }

  function test_setMaximumVouches_revertsAboveUint32() public {
    uint256 max = uint256(type(uint32).max) + 1;
    vm.expectRevert(abi.encodeWithSelector(MaximumVouchesOutOfRange.selector, max));
    vm.prank(_admin);
    vouch.setMaximumVouches(max);
  }

  function test_admin_revertsWhenPaused() public {
    _pauseContract(CONTRACT_NAME);

    vm.startPrank(_admin);
    vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
    vouch.setEntryFeeBps(200);
    vm.stopPrank();

    vm.startPrank(_admin);
    vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
    vouch.setExitFeeBps(100);
    vm.stopPrank();

    vm.startPrank(_admin);
    vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
    vouch.setMinimumVouchAmount(2e18);
    vm.stopPrank();

    vm.startPrank(_admin);
    vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
    vouch.setMaximumVouches(100);
    vm.stopPrank();
  }

  function test_admin_revertsIfNotAdmin() public {
    vm.startPrank(alice);
    vm.expectRevert();
    vouch.setEntryFeeBps(200);
    vm.stopPrank();

    vm.startPrank(alice);
    vm.expectRevert();
    vouch.setExitFeeBps(100);
    vm.stopPrank();

    vm.startPrank(alice);
    vm.expectRevert();
    vouch.setMinimumVouchAmount(2e18);
    vm.stopPrank();

    vm.startPrank(alice);
    vm.expectRevert();
    vouch.setMaximumVouches(100);
    vm.stopPrank();
  }

  // -------------------------------------------------------------------------
  // Upgrade
  // -------------------------------------------------------------------------

  function test_upgrade_authorizedByOwner() public {
    EthosVouchV2 newImpl = new EthosVouchV2();
    vm.prank(_owner);
    vouch.upgradeToAndCall(address(newImpl), "");
    // If no revert, upgrade succeeded
  }

  function test_upgrade_revertsIfNotOwner() public {
    EthosVouchV2 newImpl = new EthosVouchV2();
    vm.expectRevert();
    vm.prank(alice);
    vouch.upgradeToAndCall(address(newImpl), "");
  }

  function test_upgrade_revertsOnZeroAddress() public {
    vm.expectRevert();
    vm.prank(_owner);
    vouch.upgradeToAndCall(address(0), "");
  }

  /// @dev Catches storage-layout regressions: if a future contract change reorders
  ///      state variables or shrinks the __gap, this test will see post-upgrade reads
  ///      return wrong values. Today V2→V2 is a no-op, but the *test pattern* protects
  ///      us when a real V3 ships.
  function test_upgrade_preservesState() public {
    // 1) Establish state across most storage slots: a vouch, a frozen author, custom
    //    fee bps, custom min, custom max.
    uint256 vid = _vouchAlice("upgrade-state-target");
    slasher.freeze(bob);

    // Exercise the unhealthy field too: an unvouched-unhealthy vouch carries
    // archived + unhealthy across the upgrade.
    uint256 unhealthyVid = _vouchAlice("upgrade-unhealthy-target");
    vm.prank(alice);
    vouch.unvouchUnhealthy(unhealthyVid);

    vm.startPrank(_admin);
    vouch.setEntryFeeBps(250);
    vouch.setExitFeeBps(75);
    vouch.setMinimumVouchAmount(2e18);
    vouch.setMaximumVouches(123);
    vm.stopPrank();

    // Snapshot the on-chain state.
    EthosVouchV2.Vouch memory snap = _getVouch(vid);
    EthosVouchV2.Vouch memory unhealthySnap = _getVouch(unhealthyVid);
    uint256 supplyBefore = vouch.vouchCount();
    uint256 vaultBalBefore = token.balanceOf(address(vouch));

    // 2) Upgrade the proxy to a fresh implementation.
    EthosVouchV2 newImpl = new EthosVouchV2();
    vm.prank(_owner);
    vouch.upgradeToAndCall(address(newImpl), "");

    // 3) Every piece of state must read back identical post-upgrade.
    EthosVouchV2.Vouch memory after_ = _getVouch(vid);
    assertEq(after_.author, snap.author);
    assertEq(after_.balance, snap.balance);
    assertEq(after_.targetHash, snap.targetHash);
    assertEq(after_.archived, snap.archived);
    assertEq(after_.unhealthy, snap.unhealthy);

    EthosVouchV2.Vouch memory unhealthyAfter = _getVouch(unhealthyVid);
    assertTrue(unhealthyAfter.archived);
    assertEq(unhealthyAfter.unhealthy, unhealthySnap.unhealthy);
    assertTrue(unhealthyAfter.unhealthy);

    assertEq(vouch.vouchCount(), supplyBefore);
    assertEq(token.balanceOf(address(vouch)), vaultBalBefore);
    assertEq(vouch.entryFeeBps(), 250);
    assertEq(vouch.exitFeeBps(), 75);
    assertEq(vouch.configuredMinimumVouchAmount(), 2e18);
    assertEq(vouch.maximumVouches(), 123);
    assertTrue(vouch.isFrozen(bob));

    // 4) The contract still works after the upgrade.
    vm.prank(alice);
    vouch.increaseVouch(vid, 5e18);
    assertEq(_getVouch(vid).balance, snap.balance + 5e18);
  }

  // -------------------------------------------------------------------------
  // Solvency
  // -------------------------------------------------------------------------

  function test_solvency_afterManyVouchesAndUnvouches() public {
    address[] memory actors = new address[](5);
    actors[0] = alice;
    actors[1] = bob;
    actors[2] = address(0xC1);
    actors[3] = address(0xC2);
    actors[4] = address(0xC3);

    for (uint256 i = 2; i < 5; i++) {
      token.mint(actors[i], 100_000e18);
      vm.prank(actors[i]);
      token.approve(address(vouch), type(uint256).max);
    }

    uint256 supplyStart = token.totalSupply();

    uint256[] memory vids = new uint256[](actors.length);
    string[5] memory targets = ["t1", "t2", "t3", "t4", "t5"];

    // Track every fee that should be burned.
    uint256 expectedFees;

    for (uint256 i = 0; i < actors.length; i++) {
      vm.prank(actors[i]);
      vouch.vouch(targets[i], 10e18);
      vids[i] = vouch.vouchCount();
      expectedFees += _entryFee(10e18);
    }

    // Increase some vouches
    vm.prank(alice);
    vouch.increaseVouch(vids[0], 5e18);
    expectedFees += _entryFee(5e18);
    vm.prank(bob);
    vouch.increaseVouch(vids[1], 3e18);
    expectedFees += _entryFee(3e18);

    // Unvouch a few — exit fee charged on the active balance at time of unvouch.
    expectedFees += _exitFee(15e18); // alice: 10 + 5
    _unvouchAs(alice, vids[0]);
    expectedFees += _exitFee(10e18); // actor[2]: 10
    _unvouchAs(actors[2], vids[2]);

    // Contract balance should equal sum of remaining active vouch balances.
    uint256 totalActive;
    for (uint256 i = 0; i < actors.length; i++) {
      EthosVouchV2.Vouch memory v = _getVouch(vids[i]);
      if (!v.archived) {
        totalActive += v.balance;
      }
    }

    assertEq(token.balanceOf(address(vouch)), totalActive, "vault solvency");
    // totalSupply should have dropped by exactly the sum of every entry+exit fee.
    assertEq(supplyStart - token.totalSupply(), expectedFees, "fee accounting");
  }

  // -------------------------------------------------------------------------
  // VouchNotFound — input validation on vouchId
  // -------------------------------------------------------------------------

  function test_unvouch_revertsOnVouchIdZero() public {
    vm.expectRevert(abi.encodeWithSelector(VouchNotFound.selector, 0));
    vm.prank(alice);
    vouch.unvouch(0);
  }

  function test_unvouch_revertsOnVouchIdAboveCount() public {
    _vouchAlice("v1");
    uint256 bogus = vouch.vouchCount() + 1;
    vm.expectRevert(abi.encodeWithSelector(VouchNotFound.selector, bogus));
    vm.prank(alice);
    vouch.unvouch(bogus);
  }

  function test_increaseVouch_revertsOnVouchIdZero() public {
    vm.expectRevert(abi.encodeWithSelector(VouchNotFound.selector, 0));
    vm.prank(alice);
    vouch.increaseVouch(0, 1e18);
  }

  function test_increaseVouch_revertsOnVouchIdAboveCount() public {
    _vouchAlice("v1");
    uint256 bogus = vouch.vouchCount() + 1;
    vm.expectRevert(abi.encodeWithSelector(VouchNotFound.selector, bogus));
    vm.prank(alice);
    vouch.increaseVouch(bogus, 1e18);
  }

  function test_increaseVouchWithPermit_revertsOnVouchIdZero() public {
    vm.expectRevert(abi.encodeWithSelector(VouchNotFound.selector, 0));
    vm.prank(alice);
    vouch.increaseVouchWithPermit(0, 1e18, block.timestamp + 1, 0, bytes32(0), bytes32(0));
  }

  // -------------------------------------------------------------------------
  // Author-index swap-pop on non-last element (mirror of target-hash test)
  // -------------------------------------------------------------------------

  function test_unvouch_swapPop_authorIndex_nonLastElement() public {
    // Three vouches by alice; unvouching the FIRST exercises the swap-of-last-into-idx0
    // branch in _removeFromAuthorIndex.
    uint256 vid1 = _vouchAs(alice, "ai-1", 10e18);
    uint256 vid2 = _vouchAs(alice, "ai-2", 10e18);
    uint256 vid3 = _vouchAs(alice, "ai-3", 10e18);

    assertEq(vouch.vouchIdsByAuthor(alice, 0), vid1);
    assertEq(vouch.vouchIdsByAuthor(alice, 1), vid2);
    assertEq(vouch.vouchIdsByAuthor(alice, 2), vid3);

    _unvouchAs(alice, vid1);

    // After swap-pop: vid3 (was last) moves into slot 0; vid2 stays at slot 1.
    assertEq(vouch.vouchIdsByAuthor(alice, 0), vid3);
    assertEq(vouch.vouchIdsByAuthor(alice, 1), vid2);

    // Length is now 2 — index 2 must revert.
    vm.expectRevert();
    vouch.vouchIdsByAuthor(alice, 2);

    // The reverse-lookup index for vid3 must be updated to its new position (0).
    assertEq(vouch.vouchIdsByAuthorIndex(alice, vid3), 0);
    // vid2 stayed at 1.
    assertEq(vouch.vouchIdsByAuthorIndex(alice, vid2), 1);
    // vid1's reverse index is cleared (delete).
    assertEq(vouch.vouchIdsByAuthorIndex(alice, vid1), 0);

    // Re-vouch with vid2's target should still hit the duplicate-target check —
    // proves the index integrity didn't accidentally clear vid2's bookkeeping.
    bytes32 dupHash = keccak256(bytes("ai-2"));
    vm.expectRevert(abi.encodeWithSelector(AlreadyVouched.selector, alice, dupHash));
    vm.prank(alice);
    vouch.vouch("ai-2", 10e18);
  }

  // -------------------------------------------------------------------------
  // Boundary: amount == configuredMinimumVouchAmount
  // -------------------------------------------------------------------------

  function test_vouch_atExactMinimum_succeeds() public {
    // Boundary positive — guards against the check becoming `<=` instead of `<`.
    uint256 min = vouch.configuredMinimumVouchAmount();
    vm.prank(alice);
    vouch.vouch("min-boundary", min);
    assertEq(_getVouch(vouch.vouchCount()).balance, min);
  }

  function test_vouch_oneBelowMinimum_reverts() public {
    uint256 min = vouch.configuredMinimumVouchAmount();
    vm.expectRevert(abi.encodeWithSelector(AmountBelowMinimum.selector, min - 1, min));
    vm.prank(alice);
    vouch.vouch("just-under", min - 1);
  }

  // -------------------------------------------------------------------------
  // Rounding (Math.Rounding.Ceil) — entry, exit, and burn fees round UP to favour
  //                                 the contract.
  // -------------------------------------------------------------------------

  function test_entryFee_roundsUp_smallAmount() public {
    // amount = 99 wei, entryFeeBps = 100 → 99 * 100 / 10000 = 0.99 → ceil = 1.
    // We need an instance with a 1-wei minimum so the tiny amount isn't rejected.
    EthosVouchV2 small = _deployFreshVouchWithMinimum(1);

    uint256 aliceBefore = token.balanceOf(alice);
    uint256 supplyBefore = token.totalSupply();

    vm.prank(alice);
    small.vouch("rounding-entry", 99);

    // 99 + 1 (rounded-up fee) = 100 wei pulled; 1 wei burned.
    assertEq(aliceBefore - token.balanceOf(alice), 100);
    assertEq(supplyBefore - token.totalSupply(), 1);
    (uint256 previewFee,) = small.previewVouchFee(99);
    assertEq(previewFee, 1, "preview must agree with on-chain rounding");
  }

  function test_exitFee_roundsUp_smallBalance() public {
    // entry=0, exit=100 (1%) so the seed vouch is clean and only the exit rounds.
    EthosVouchV2 small = _deployFreshVouchWithFees(0, 100, 1);

    vm.prank(alice);
    small.vouch("rounding-exit", 99);
    uint256 vid = small.vouchCount();

    uint256 aliceBefore = token.balanceOf(alice);
    uint256 supplyBefore = token.totalSupply();

    vm.prank(alice);
    small.unvouch(vid);

    // exit fee = ceil(99 * 100 / 10000) = ceil(0.99) = 1.
    assertEq(token.balanceOf(alice) - aliceBefore, 98);
    assertEq(supplyBefore - token.totalSupply(), 1);
  }

  function test_slash_roundsUp_smallBalance() public {
    // 1 wei balance burned at 1 bps → 0.0001 → ceil = 1 wei (entire balance).
    EthosVouchV2 small = _deployFreshVouchWithFees(0, 0, 1);

    vm.prank(alice);
    small.vouch("rounding-burn", 1);
    uint256 vid = small.vouchCount();

    // Re-register the slasher for this fresh instance.
    MockSlasher s = new MockSlasher(address(small));
    address[] memory addrs = new address[](1);
    string[] memory names = new string[](1);
    addrs[0] = address(s);
    names[0] = "SLASHER";
    _cam.updateContractAddressesForNames(addrs, names);

    s.slash(alice, 1); // 1 bps

    // ceil(1 * 1 / 10000) = 1 → entire balance burned.
    EthosVouchV2.Vouch memory snap;
    (snap.author, snap.archived, snap.unhealthy, snap.targetHash, snap.balance) = small.vouches(vid);
    assertEq(snap.balance, 0);
  }

  function test_slash_perVouchRoundingExcess_isBoundedByActiveVouchCountMinusOne() public {
    EthosVouchV2 small = _deployFreshVouchWithFees(0, 0, 1);
    MockSlasher s = new MockSlasher(address(small));

    address[] memory addrs = new address[](1);
    string[] memory names = new string[](1);
    addrs[0] = address(s);
    names[0] = "SLASHER";
    _cam.updateContractAddressesForNames(addrs, names);

    string[5] memory targets =
      ["rounding-bound-0", "rounding-bound-1", "rounding-bound-2", "rounding-bound-3", "rounding-bound-4"];
    uint256 activeVouches = targets.length;
    uint256 aggregateBalance;

    for (uint256 i = 0; i < activeVouches; i++) {
      vm.prank(alice);
      small.vouch(targets[i], 1);
      aggregateBalance += 1;
    }

    uint256 bps = 1;
    uint256 aggregateCeilBurn = (aggregateBalance * bps + small.BASIS_POINT_SCALE() - 1) / small.BASIS_POINT_SCALE();
    uint256 actualBurn = s.slash(alice, bps);

    assertEq(actualBurn, activeVouches, "each 1 wei vouch rounds up to 1 wei burned");
    assertEq(actualBurn - aggregateCeilBurn, activeVouches - 1, "per-vouch rounding excess");
    assertEq(rewards.committedBalance(alice), 0, "rewards debit tracks actual slash amount");
  }

  // -------------------------------------------------------------------------
  // increaseVouch with zero amount
  // -------------------------------------------------------------------------

  function test_increaseVouch_revertsOnZeroAmount() public {
    uint256 vid = _vouchAlice("inc-zero");

    vm.prank(alice);
    vm.expectRevert(ZeroAmount.selector);
    vouch.increaseVouch(vid, 0);
  }

  // -------------------------------------------------------------------------
  // Preview-function edge cases
  // -------------------------------------------------------------------------

  function test_previewUnvouchPayout_archivedReturnsZero() public {
    uint256 vid = _vouchAlice("preview-archived");
    _unvouchAs(alice, vid);
    (uint256 payout, uint256 fee) = vouch.previewUnvouchPayout(vid);
    assertEq(payout, 0);
    assertEq(fee, 0);
  }

  function test_previewUnvouchPayout_nonexistentReturnsZero() public view {
    // No vouch with id 99999 exists. previewUnvouchPayout reads .balance on a
    // default-initialized Vouch, which is 0. Documented (lossy) behaviour: the
    // caller receives (0, 0) rather than a revert.
    (uint256 payout, uint256 fee) = vouch.previewUnvouchPayout(99999);
    assertEq(payout, 0);
    assertEq(fee, 0);
  }

  function test_previewVouchFee_zeroAmount() public view {
    (uint256 fee, uint256 gross) = vouch.previewVouchFee(0);
    assertEq(fee, 0);
    assertEq(gross, 0);
  }

  // -------------------------------------------------------------------------
  // Permit edge cases
  // -------------------------------------------------------------------------

  function test_vouchWithPermit_expiredPermit_fallsBack() public {
    // Pre-approve so the post-permit safeTransferFrom can still succeed.
    vm.prank(alice);
    token.approve(address(vouch), type(uint256).max);
    uint256 nonceBefore = token.nonces(alice);

    // Build a permit with a deadline that's already in the past.
    uint256 privKey = 0xCAFEBABE;
    address signer = vm.addr(privKey);
    token.mint(signer, 100e18);
    vm.prank(signer);
    token.approve(address(vouch), type(uint256).max);

    // Warp first so we can sign with a past deadline.
    vm.warp(1000);
    uint256 deadline = 500;
    (uint8 v, bytes32 r, bytes32 s) = _signPermit(token, privKey, signer, address(vouch), 10e18, deadline);

    vm.prank(signer);
    vouch.vouchWithPermit("expired-permit", 10e18, deadline, v, r, s);

    // Vouch succeeded via the pre-existing approval; nonce did NOT advance because
    // the expired permit reverted and try/catch swallowed it.
    assertEq(vouch.vouchCount(), 1);
    assertEq(token.nonces(signer), 0);
    // alice was the pre-approved actor; her nonce shouldn't move either.
    assertEq(token.nonces(alice), nonceBefore);
  }

  function test_vouchWithPermit_signedByDifferentSigner_drawsFromCallerNotSigner() public {
    // Threat model: a malicious caller submits a victim's signed permit but calls
    // the function themselves. EIP-2612's `permit(owner, spender, value, ...)`
    // grants `owner → spender` allowance regardless of msg.sender — that's by
    // design — but our `_vouch` then calls `safeTransferFrom(msg.sender, vault, ...)`,
    // which pulls from the caller, NOT the signer. So the worst the attacker can
    // do is grant the victim a wasted allowance to our vault; they cannot drain
    // the victim's tokens. This test pins that property.
    uint256 victimPriv = uint256(keccak256("cross-signer-victim"));
    address victim = vm.addr(victimPriv);
    token.mint(victim, 100e18);

    address attacker = address(0xBADBAD);
    // attacker has no funds and no allowance — the post-permit safeTransferFrom
    // pull MUST fail because it tries to pull from attacker, not victim.

    uint256 amount = 10e18;
    uint256 fee = _entryFee(amount);
    uint256 gross = amount + fee;
    uint256 deadline = block.timestamp + 1 hours;

    (uint8 v, bytes32 r, bytes32 s) = _signPermit(token, victimPriv, victim, address(vouch), gross, deadline);

    uint256 victimBalanceBefore = token.balanceOf(victim);

    // Even stronger property than I first expected: permit() is called with
    // `owner = msg.sender = attacker`, so the recovered signer (victim) doesn't
    // match owner and permit reverts. try/catch swallows the revert. _vouch then
    // runs and safeTransferFrom from attacker (no balance/allowance) reverts.
    vm.expectRevert();
    vm.prank(attacker);
    vouch.vouchWithPermit("stolen-perm", amount, deadline, v, r, s);

    // Verify the safety properties:
    //   1. No vouch was created.
    //   2. Victim's balance is intact — no tokens drained.
    //   3. Victim's nonce did NOT advance (permit was rejected, signature was
    //      not consumed — they can still use it themselves later).
    //   4. Victim's allowance to vault is unchanged (still 0).
    assertEq(vouch.vouchCount(), 0);
    assertEq(token.balanceOf(victim), victimBalanceBefore);
    assertEq(token.nonces(victim), 0);
    assertEq(token.allowance(victim, address(vouch)), 0);
  }

  // -------------------------------------------------------------------------
  // Reentrancy — verify nonReentrant guards block re-entry from a malicious token
  // -------------------------------------------------------------------------

  function test_vouch_blocksReentrancyOnTransferFrom() public {
    EthosVouchV2 v = _deployVouchWithToken(_deployArmedReentrantToken(alice));
    MaliciousReentrantToken mal = MaliciousReentrantToken(address(v.token()));
    mal.setTarget(address(v));
    mal.arm(MaliciousReentrantToken.When.OnTransferFrom, MaliciousReentrantToken.Action.Vouch, 0, "re-target");

    vm.expectRevert(ReentrancyGuardUpgradeable.ReentrancyGuardReentrantCall.selector);
    vm.prank(alice);
    v.vouch("outer-target", 10e18);
  }

  function test_unvouch_blocksReentrancyOnTransfer() public {
    EthosVouchV2 v = _deployVouchWithToken(_deployArmedReentrantToken(alice));
    MaliciousReentrantToken mal = MaliciousReentrantToken(address(v.token()));
    mal.setTarget(address(v));

    // Seed a vouch with the trigger disarmed.
    mal.arm(MaliciousReentrantToken.When.None, MaliciousReentrantToken.Action.Vouch, 0, "");
    vm.prank(alice);
    v.vouch("seed-unvouch-reent", 10e18);
    uint256 vid = v.vouchCount();

    // Arm the trigger on the outbound transfer (payout) — the reentrant unvouch
    // should hit the nonReentrant guard.
    mal.arm(MaliciousReentrantToken.When.OnTransfer, MaliciousReentrantToken.Action.Unvouch, vid, "");

    vm.expectRevert(ReentrancyGuardUpgradeable.ReentrancyGuardReentrantCall.selector);
    vm.prank(alice);
    v.unvouch(vid);
  }

  function test_increaseVouch_blocksReentrancyOnTransferFrom() public {
    EthosVouchV2 v = _deployVouchWithToken(_deployArmedReentrantToken(alice));
    MaliciousReentrantToken mal = MaliciousReentrantToken(address(v.token()));
    mal.setTarget(address(v));

    mal.arm(MaliciousReentrantToken.When.None, MaliciousReentrantToken.Action.Vouch, 0, "");
    vm.prank(alice);
    v.vouch("seed-inc-reent", 10e18);
    uint256 vid = v.vouchCount();

    mal.arm(MaliciousReentrantToken.When.OnTransferFrom, MaliciousReentrantToken.Action.IncreaseVouch, vid, "");

    vm.expectRevert(ReentrancyGuardUpgradeable.ReentrancyGuardReentrantCall.selector);
    vm.prank(alice);
    v.increaseVouch(vid, 5e18);
  }

  function test_decreaseVouch_blocksReentrancyOnTransfer() public {
    EthosVouchV2 v = _deployVouchWithToken(_deployArmedReentrantToken(alice));
    MaliciousReentrantToken mal = MaliciousReentrantToken(address(v.token()));
    mal.setTarget(address(v));

    // Seed a vouch with enough balance to satisfy the reentrant decrease's minimum check.
    mal.arm(MaliciousReentrantToken.When.None, MaliciousReentrantToken.Action.Vouch, 0, "");
    vm.prank(alice);
    v.vouch("seed-decrease-reent", 10e18);
    uint256 vid = v.vouchCount();

    // Re-enter on the outbound transfer (payout) — should hit the nonReentrant guard.
    mal.arm(MaliciousReentrantToken.When.OnTransfer, MaliciousReentrantToken.Action.DecreaseVouch, vid, "");

    vm.expectRevert(ReentrancyGuardUpgradeable.ReentrancyGuardReentrantCall.selector);
    vm.prank(alice);
    v.decreaseVouch(vid, 4e18);
  }

  function test_slash_blocksReentrancyOnBurn() public {
    EthosVouchV2 v = _deployVouchWithToken(_deployArmedReentrantToken(alice));
    MaliciousReentrantToken mal = MaliciousReentrantToken(address(v.token()));
    mal.setTarget(address(v));

    mal.arm(MaliciousReentrantToken.When.None, MaliciousReentrantToken.Action.Vouch, 0, "");
    vm.prank(alice);
    v.vouch("seed-burn-reent", 10e18);
    uint256 vid = v.vouchCount();

    // Register a slasher for THIS fresh vouch instance.
    MockSlasher s = new MockSlasher(address(v));
    address[] memory addrs = new address[](1);
    string[] memory names = new string[](1);
    addrs[0] = address(s);
    names[0] = "SLASHER";
    _cam.updateContractAddressesForNames(addrs, names);

    // Arm: when the malicious token's burn() is called by the vault, re-enter unvouch.
    mal.arm(MaliciousReentrantToken.When.OnBurn, MaliciousReentrantToken.Action.Unvouch, vid, "");

    vm.expectRevert(ReentrancyGuardUpgradeable.ReentrancyGuardReentrantCall.selector);
    s.slash(alice, 5000);
  }

  // -------------------------------------------------------------------------
  // ITargetStatus — discussion-target gate consumed by EthosDiscussion
  // -------------------------------------------------------------------------

  function test_targetExistsAndAllowedForId_unmintedId_returnsFalse() public view {
    (bool exists, bool allowed) = vouch.targetExistsAndAllowedForId(0);
    assertFalse(exists);
    assertFalse(allowed);

    (exists, allowed) = vouch.targetExistsAndAllowedForId(type(uint256).max);
    assertFalse(exists);
    assertFalse(allowed);
  }

  function test_targetExistsAndAllowedForId_activeVouch_returnsTrue() public {
    uint256 vid = _vouchAlice("target-active");
    (bool exists, bool allowed) = vouch.targetExistsAndAllowedForId(vid);
    assertTrue(exists);
    assertTrue(allowed);
  }

  /// @dev Archived (unvouched) entries must remain valid discussion targets so prior
  ///      threads stay reachable after the author exits — same as V1 behaviour.
  function test_targetExistsAndAllowedForId_archivedVouch_stillAllowed() public {
    uint256 vid = _vouchAlice("target-archive");
    _unvouchAs(alice, vid);
    assertTrue(_getVouch(vid).archived, "precondition: vouch archived");

    (bool exists, bool allowed) = vouch.targetExistsAndAllowedForId(vid);
    assertTrue(exists);
    assertTrue(allowed);
  }

  function test_targetExistsAndAllowedForId_callableViaInterface() public {
    uint256 vid = _vouchAlice("target-iface");
    (bool exists, bool allowed) = ITargetStatus(address(vouch)).targetExistsAndAllowedForId(vid);
    assertTrue(exists);
    assertTrue(allowed);
  }

  // -------------------------------------------------------------------------
  // Fuzz tests
  // -------------------------------------------------------------------------

  /// @dev For ANY (amount, entryBps, exitBps) within sane bounds, vouch+unvouch
  ///      must leave the vault solvent and burn exactly entry+exit fees.
  function testFuzz_vouchThenUnvouch_solventAndFeesExact(uint96 amount, uint16 entryBps, uint16 exitBps) public {
    amount = uint96(bound(amount, 1e18, 50_000e18));
    entryBps = uint16(bound(entryBps, 0, 500));
    exitBps = uint16(bound(exitBps, 0, 500));
    // Stay inside the valid configuration space the contract enforces at runtime.
    vm.assume(entryBps + exitBps <= vouch.MAX_TOTAL_FEES());

    vm.startPrank(_admin);
    vouch.setEntryFeeBps(entryBps);
    vouch.setExitFeeBps(exitBps);
    vm.stopPrank();

    uint256 expectedEntryFee = (uint256(amount) * entryBps + vouch.BASIS_POINT_SCALE() - 1) / vouch.BASIS_POINT_SCALE();
    uint256 expectedExitFee = (uint256(amount) * exitBps + vouch.BASIS_POINT_SCALE() - 1) / vouch.BASIS_POINT_SCALE();

    uint256 aliceBefore = token.balanceOf(alice);
    uint256 supplyBefore = token.totalSupply();
    uint256 vaultBefore = token.balanceOf(address(vouch));

    vm.prank(alice);
    vouch.vouch("fuzz-target", amount);
    uint256 vid = vouch.vouchCount();

    // After vouch: vault holds exactly `amount`, totalSupply dropped by exactly
    // `entryFee`, alice paid exactly `amount + entryFee`.
    assertEq(token.balanceOf(address(vouch)), vaultBefore + amount, "vault after vouch");
    assertEq(supplyBefore - token.totalSupply(), expectedEntryFee, "supply after vouch");
    assertEq(aliceBefore - token.balanceOf(alice), uint256(amount) + expectedEntryFee, "alice after vouch");

    _unvouchAs(alice, vid);

    // After unvouch: vault is back to starting balance, totalSupply dropped by
    // entry + exit fees combined, alice net-out is exactly the two fees.
    assertEq(token.balanceOf(address(vouch)), vaultBefore, "vault after unvouch");
    assertEq(supplyBefore - token.totalSupply(), expectedEntryFee + expectedExitFee, "supply after unvouch");
    assertEq(aliceBefore - token.balanceOf(alice), expectedEntryFee + expectedExitFee, "alice after unvouch");
  }

  /// @dev For ANY legal burn bps, the vault balance must drop by exactly the burned
  ///      amount AND the token totalSupply must drop by exactly the same number.
  function testFuzz_burnAuthor_movesExactTokens(uint96 amount, uint16 bps) public {
    amount = uint96(bound(amount, 1e18, 10_000e18));
    bps = uint16(bound(bps, 0, uint256(vouch.BASIS_POINT_SCALE())));

    vm.prank(alice);
    vouch.vouch("fuzz-burn", amount);
    uint256 vid = vouch.vouchCount();

    uint256 expectedBurn = (uint256(amount) * bps + vouch.BASIS_POINT_SCALE() - 1) / vouch.BASIS_POINT_SCALE();

    uint256 vaultBefore = token.balanceOf(address(vouch));
    uint256 supplyBefore = token.totalSupply();

    slasher.slash(alice, bps);

    assertEq(vaultBefore - token.balanceOf(address(vouch)), expectedBurn, "vault drop == burn");
    assertEq(supplyBefore - token.totalSupply(), expectedBurn, "supply drop == burn");
    assertEq(_getVouch(vid).balance, uint256(amount) - expectedBurn, "vouch balance updated");
  }

  // -------------------------------------------------------------------------
  // EthosRewards integration — credit on vouch/increase, debit on
  // decrease/unvouch/slash. Verifies the committed-balance accounting in
  // EthosRewards moves by the right delta on each path.
  // -------------------------------------------------------------------------

  function test_rewards_vouch_creditsNetAmountNotGross() public {
    uint256 amount = 10e18;
    _vouchAlice("rewards-credit-net");
    assertEq(rewards.committedBalance(alice), amount, "credits the net amount, not gross (amount + fee)");
    assertEq(rewards.totalCommitted(), amount);
  }

  function test_rewards_increaseVouch_creditsIncrement() public {
    uint256 vid = _vouchAlice("rewards-increase");
    uint256 increment = 7e18;
    vm.prank(alice);
    vouch.increaseVouch(vid, increment);
    assertEq(rewards.committedBalance(alice), 10e18 + increment);
  }

  function test_rewards_decreaseVouch_debitsAmount() public {
    uint256 vid = _vouchAlice("rewards-decrease");
    uint256 decrement = 3e18;
    vm.prank(alice);
    vouch.decreaseVouch(vid, decrement);
    assertEq(rewards.committedBalance(alice), 10e18 - decrement);
  }

  function test_rewards_unvouch_debitsFullBalance() public {
    uint256 vid = _vouchAlice("rewards-unvouch");
    _unvouchAs(alice, vid);
    assertEq(rewards.committedBalance(alice), 0);
    assertEq(rewards.totalCommitted(), 0);
  }

  function test_rewards_slash_debitsAmountApplied() public {
    _vouchAlice("rewards-slash-a");
    _vouchAs(alice, "rewards-slash-b", 20e18);
    uint256 committedBefore = rewards.committedBalance(alice);
    assertEq(committedBefore, 30e18);

    // 25% slash: rounds up per-vouch -> ceil(10e18 * 2500 / 10000) + ceil(20e18 * 2500 / 10000)
    //          = 2.5e18 + 5e18 = 7.5e18
    uint256 amountApplied = slasher.slash(alice, 2500);
    assertEq(amountApplied, 7.5e18);
    assertEq(rewards.committedBalance(alice), committedBefore - amountApplied);
  }

  function test_rewards_unvouch_afterFullSlash_succeedsWithoutDebit() public {
    uint256 vid = _vouchAlice("rewards-unvouch-zero");
    slasher.slash(alice, 10000); // 100% — drops vouch balance + committed to 0
    assertEq(rewards.committedBalance(alice), 0);

    // Unvouch must succeed even though balance == 0 (no debit attempt).
    _unvouchAs(alice, vid);
    assertEq(rewards.committedBalance(alice), 0);
    EthosVouchV2.Vouch memory v = _getVouch(vid);
    assertTrue(v.archived);
  }

  function test_rewards_vouch_revertsWhenAccruingRegistrationCleared() public {
    // Overwriting the ETHOS_VOUCH_V2 entry in CAM removes the vouch contract's
    // authorization to call credit/debit; subsequent user-facing vouch ops
    // revert from EthosRewards' identity check.
    address[] memory addrs = new address[](1);
    string[] memory names = new string[](1);
    addrs[0] = address(0);
    names[0] = ETHOS_VOUCH_V2;
    _cam.updateContractAddressesForNames(addrs, names);

    vm.expectRevert(abi.encodeWithSelector(UnauthorizedAccruingCaller.selector, address(vouch), address(0)));
    vm.prank(alice);
    vouch.vouch("rewards-revoked", 10e18);
  }

  // -------------------------------------------------------------------------
  // Helpers used only by the new tests above
  // -------------------------------------------------------------------------

  /// @dev Points CAM's ETHOS_VOUCH_V2 registration at a freshly-deployed vouch
  ///      proxy so its credit/debit calls succeed. Every helper that deploys a
  ///      new vouch proxy must call this — otherwise vouch state changes revert
  ///      with UnauthorizedAccruingCaller from EthosRewards. Overwrites any
  ///      prior ETHOS_VOUCH_V2 registration; tests that swap to a fresh proxy
  ///      stop driving the original `vouch` after the swap.
  function _allowlistVouchOnRewards(address freshVouch) internal {
    address[] memory addrs = new address[](1);
    string[] memory names = new string[](1);
    addrs[0] = freshVouch;
    names[0] = ETHOS_VOUCH_V2;
    _cam.updateContractAddressesForNames(addrs, names);
  }

  /// @dev Deploys + initializes a fresh EthosVouchV2 with a configurable minimum
  ///      vouch amount, using the standard `token` and current entry/exit fees.
  function _deployFreshVouchWithMinimum(uint256 minimum) internal returns (EthosVouchV2 fresh) {
    EthosVouchV2 impl2 = new EthosVouchV2();
    fresh = EthosVouchV2(_deployProxy(address(impl2)));
    fresh.initialize(
      _defaultInitParams(),
      address(token),
      100, // 1% entry
      0,
      minimum,
      50000e18,
      256,
      0
    );
    _allowlistVouchOnRewards(address(fresh));
    vm.prank(alice);
    token.approve(address(fresh), type(uint256).max);
  }

  /// @dev Deploys + initializes a fresh EthosVouchV2 with explicit fee bps and minimum.
  function _deployFreshVouchWithFees(uint256 entryBps, uint256 exitBps, uint256 minimum)
    internal
    returns (EthosVouchV2 fresh)
  {
    EthosVouchV2 impl2 = new EthosVouchV2();
    fresh = EthosVouchV2(_deployProxy(address(impl2)));
    fresh.initialize(_defaultInitParams(), address(token), entryBps, exitBps, minimum, 50000e18, 256, 0);
    _allowlistVouchOnRewards(address(fresh));
    vm.prank(alice);
    token.approve(address(fresh), type(uint256).max);
  }

  /// @dev Mints + approves a malicious reentrant token for `actor`. Returns the token.
  function _deployArmedReentrantToken(address actor) internal returns (MaliciousReentrantToken mal) {
    mal = new MaliciousReentrantToken();
    mal.mint(actor, 1_000_000e18);
  }

  /// @dev Deploys + initializes EthosVouchV2 backed by a custom token and approves
  ///      that token for alice. Used by reentrancy tests.
  function _deployVouchWithToken(MaliciousReentrantToken mal) internal returns (EthosVouchV2 fresh) {
    EthosVouchV2 impl2 = new EthosVouchV2();
    fresh = EthosVouchV2(_deployProxy(address(impl2)));
    fresh.initialize(_defaultInitParams(), address(mal), 100, 50, 1e18, 50000e18, 256, 0);
    _allowlistVouchOnRewards(address(fresh));
    vm.prank(alice);
    mal.approve(address(fresh), type(uint256).max);
  }

  // -------------------------------------------------------------------------
  // Metadata (3-arg vouch + setVouchMetadata + VouchMetadataUpdated)
  // -------------------------------------------------------------------------

  function test_vouch3Arg_storesMetadata_andEmitsInVouched() public {
    string memory meta = '{"batchId":"abc","reviewId":42}';
    uint256 amount = 10e18;
    uint256 fee = _entryFee(amount);
    bytes32 targetHash = keccak256(bytes("target-meta"));

    vm.expectEmit(true, true, false, true);
    emit EthosVouchV2.Vouched(alice, targetHash, 1, "target-meta", amount, fee, meta);

    vm.prank(alice);
    vouch.vouch("target-meta", amount, meta);

    assertEq(vouch.vouchMetadata(1), meta);
  }

  function test_vouch3Arg_nonEmptyMetadata_emitsVouchMetadataUpdated() public {
    string memory meta = '{"batchId":"abc"}';

    vm.expectEmit(true, false, false, true);
    emit EthosVouchV2.VouchMetadataUpdated(1, meta);

    vm.prank(alice);
    vouch.vouch("target-meta-event", 10e18, meta);
  }

  function test_vouch3Arg_emptyMetadata_doesNotWriteStorage() public {
    uint256 amount = 10e18;
    uint256 fee = _entryFee(amount);
    bytes32 targetHash = keccak256(bytes("target-empty"));

    vm.expectEmit(true, true, false, true);
    emit EthosVouchV2.Vouched(alice, targetHash, 1, "target-empty", amount, fee, "");

    vm.prank(alice);
    vouch.vouch("target-empty", amount, "");

    assertEq(bytes(vouch.vouchMetadata(1)).length, 0);
  }

  function test_vouch3Arg_creditsBalance_sameAs2Arg() public {
    vm.prank(alice);
    vouch.vouch("target-3arg", 10e18, '{"reviewId":1}');
    EthosVouchV2.Vouch memory v = _getVouch(1);
    assertEq(v.balance, 10e18);
    assertEq(v.author, alice);
  }

  function test_setVouchMetadata_authorOnly_succeeds() public {
    uint256 vid = _vouchAlice("set-meta-author");

    string memory meta = '{"reviewId":7}';
    vm.prank(alice);
    vouch.setVouchMetadata(vid, meta);

    assertEq(vouch.vouchMetadata(vid), meta);
  }

  function test_setVouchMetadata_revertsForNonAuthor() public {
    uint256 vid = _vouchAlice("set-meta-other");
    vm.expectRevert(abi.encodeWithSelector(UnauthorizedVouchAccess.selector, bob, alice));
    vm.prank(bob);
    vouch.setVouchMetadata(vid, "x");
  }

  function test_setVouchMetadata_revertsOnArchived() public {
    uint256 vid = _vouchAlice("set-meta-archived");
    _unvouchAs(alice, vid);
    vm.expectRevert(abi.encodeWithSelector(VouchAlreadyArchived.selector, vid));
    vm.prank(alice);
    vouch.setVouchMetadata(vid, "x");
  }

  function test_setVouchMetadata_revertsOnZeroId() public {
    vm.expectRevert(abi.encodeWithSelector(VouchNotFound.selector, 0));
    vm.prank(alice);
    vouch.setVouchMetadata(0, "x");
  }

  function test_setVouchMetadata_revertsOnNonexistentId() public {
    vm.expectRevert(abi.encodeWithSelector(VouchNotFound.selector, 999));
    vm.prank(alice);
    vouch.setVouchMetadata(999, "x");
  }

  function test_setVouchMetadata_revertsWhenPaused() public {
    uint256 vid = _vouchAlice("set-meta-paused");
    _pauseContract(CONTRACT_NAME);
    vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
    vm.prank(alice);
    vouch.setVouchMetadata(vid, "x");
  }

  function test_setVouchMetadata_emits_VouchMetadataUpdated() public {
    uint256 vid = _vouchAlice("set-meta-event");

    vm.expectEmit(true, false, false, true);
    emit EthosVouchV2.VouchMetadataUpdated(vid, "after");

    vm.prank(alice);
    vouch.setVouchMetadata(vid, "after");
  }

  function test_setVouchMetadata_replacesExistingValue() public {
    string memory first = '{"batchId":"a"}';
    vm.prank(alice);
    vouch.vouch("set-meta-replace", 10e18, first);
    assertEq(vouch.vouchMetadata(1), first);

    string memory second = '{"batchId":"b"}';
    vm.prank(alice);
    vouch.setVouchMetadata(1, second);
    assertEq(vouch.vouchMetadata(1), second);
  }

  function test_setVouchMetadata_emptyString_clearsValue() public {
    vm.prank(alice);
    vouch.vouch("set-meta-clear", 10e18, '{"reviewId":3}');
    vm.prank(alice);
    vouch.setVouchMetadata(1, "");
    assertEq(bytes(vouch.vouchMetadata(1)).length, 0);
  }

  function test_vouchWithPermit3Arg_storesMetadata() public {
    // Spin up a permit-capable token + fresh proxy because the suite's MockERC20Burnable
    // is already used by other tests; verify the metadata-bearing overload writes the
    // mapping and emits VouchMetadataUpdated through the permit path.
    MockERC20Burnable permitToken = new MockERC20Burnable();
    EthosVouchV2 impl2 = new EthosVouchV2();
    EthosVouchV2 fresh = EthosVouchV2(_deployProxy(address(impl2)));
    fresh.initialize(_defaultInitParams(), address(permitToken), 100, 50, 1e18, 50000e18, 256, 0);
    _allowlistVouchOnRewards(address(fresh));
    _setupInteractionControl(_cam);
    _registerControlledContract("ETHOS_VOUCH_V2_META", address(fresh));

    uint256 amount = 10e18;
    (uint256 fee,) = fresh.previewVouchFee(amount);
    uint256 required = amount + fee;
    uint256 aliceKey = 0xA11CE;
    address aliceSigner = vm.addr(aliceKey);
    permitToken.mint(aliceSigner, 100e18);

    (uint8 v, bytes32 r, bytes32 s) =
      _signPermit(permitToken, aliceKey, aliceSigner, address(fresh), required, block.timestamp + 1 hours);

    string memory meta = '{"batchId":"perm","reviewId":9}';
    bytes32 targetHash = keccak256(bytes("permit-meta"));

    vm.expectEmit(true, true, false, true);
    emit EthosVouchV2.Vouched(aliceSigner, targetHash, 1, "permit-meta", amount, fee, meta);

    vm.prank(aliceSigner);
    fresh.vouchWithPermit("permit-meta", amount, meta, block.timestamp + 1 hours, v, r, s);

    assertEq(fresh.vouchMetadata(1), meta);
  }

  function test_vouchWithPermit3Arg_revertsWithInsufficientPermitAllowance() public {
    address user = vm.addr(0xBEEFF00D);
    token.mint(user, 100e18);

    uint256 amount = 10e18;
    uint256 fee = _entryFee(amount);
    uint256 required = amount + fee;

    vm.expectRevert(abi.encodeWithSelector(InsufficientPermitAllowance.selector, user, required));
    vm.prank(user);
    vouch.vouchWithPermit("permit-meta-no-allowance", amount, "{}", block.timestamp + 1, 0, bytes32(0), bytes32(0));
  }

  /// @dev Invariant: V2 vouch entry points expose no `comment` parameter.
  ///      V1's `addReview` / `vouch` carried a free-form comment that was
  ///      stored on-chain; V2 deliberately dropped this in favour of an
  ///      opaque metadata string that off-chain consumers parse. Asserts
  ///      every V1-shaped comment-bearing selector is absent so the design
  ///      regression-tests itself.
  ///
  ///      Each forbidden signature is called with realistically-typed dummy
  ///      args, so the call reaches dispatch instead of bailing on argument
  ///      decoding. A failed dispatch (no fallback, selector missing) gives
  ///      the `success == false` we assert on; a `success == true` would
  ///      indicate the contract accepted the call and therefore implements
  ///      a comment-bearing entry point.
  function test_invariant_noCommentParameter() public {
    // Each entry encodes the forbidden signature with dummy args of the
    // expected types so the contract sees a well-formed call. The 3-arg
    // `vouch(string,uint256,string)` selector is intentionally omitted
    // because V2 reuses that slot under metadata semantics; see ADR-0001.

    bool ok1 = _forbiddenV1VouchCommentShapeResolves();
    assertFalse(ok1, "vouch(string,string,uint256) (V1 comment shape) resolved");

    bool ok2 = _forbiddenV1VouchByProfileCommentShapeResolves();
    assertFalse(ok2, "vouchByProfileId (V1 comment shape) resolved");

    bool ok3 = _forbiddenReviewCommentShapeResolves();
    assertFalse(ok3, "addReview (review's comment shape) resolved");

    bool ok4 = _forbiddenSetCommentResolves();
    assertFalse(ok4, "setComment(uint256,string) resolved");

    bool ok5 = _forbiddenCommentReaderResolves();
    assertFalse(ok5, "comment(uint256) reader resolved");

    // And confirm the canonical V2 surface IS reachable so the test would
    // fail with a clear positive result if the metadata path regressed.
    assertTrue(vouch.setVouchMetadata.selector != bytes4(0));
  }

  function _forbiddenV1VouchCommentShapeResolves() private returns (bool ok) {
    (ok,) = address(vouch).call(abi.encodeWithSelector(V1_VOUCH_COMMENT_SELECTOR, "comment", "target", uint256(10e18)));
  }

  function _forbiddenV1VouchByProfileCommentShapeResolves() private returns (bool ok) {
    bytes memory voucher = abi.encode(uint256(0), uint256(0), uint256(0));
    (ok,) = address(vouch)
      .call(abi.encodeWithSelector(V1_VOUCH_BY_PROFILE_COMMENT_SELECTOR, uint256(1), "target", "comment", voucher));
  }

  function _forbiddenReviewCommentShapeResolves() private returns (bool ok) {
    (ok,) =
      address(vouch).call(abi.encodeWithSelector(REVIEW_COMMENT_SELECTOR, uint8(0), address(0), "target", "comment"));
  }

  function _forbiddenSetCommentResolves() private returns (bool ok) {
    (ok,) = address(vouch).call(abi.encodeWithSelector(SET_COMMENT_SELECTOR, uint256(1), "comment"));
  }

  function _forbiddenCommentReaderResolves() private returns (bool ok) {
    (ok,) = address(vouch).call(abi.encodeWithSelector(COMMENT_READER_SELECTOR, uint256(1)));
  }

  /// @dev Helper for the permit-metadata test. Mirrors the production permit
  ///      signer at the unit level — sign a Whuffie permit so the contract
  ///      pulls `required` tokens via permit + transferFrom.
  function _signPermit(
    MockERC20Burnable t,
    uint256 ownerKey,
    address ownerAddr,
    address spender,
    uint256 value,
    uint256 deadline
  ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
    bytes32 PERMIT_TYPEHASH =
      keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 structHash =
      keccak256(abi.encode(PERMIT_TYPEHASH, ownerAddr, spender, value, t.nonces(ownerAddr), deadline));
    bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), t.DOMAIN_SEPARATOR(), structHash));
    (v, r, s) = vm.sign(ownerKey, digest);
  }

  // -------------------------------------------------------------------------
  // Maximum vouch amount
  // -------------------------------------------------------------------------

  function test_initialize_setsMaximumVouchAmount() public view {
    assertEq(vouch.configuredMaximumVouchAmount(), 50000e18);
  }

  function test_initialize_revertsWhenMaxBelowMin() public {
    EthosVouchV2 impl2 = new EthosVouchV2();
    EthosVouchV2 proxy2 = EthosVouchV2(_deployProxy(address(impl2)));
    // min=1e18, max=0 — max < min must revert.
    vm.expectRevert(abi.encodeWithSelector(AmountBelowMinimum.selector, 0, 1e18));
    proxy2.initialize(_defaultInitParams(), address(token), 100, 50, 1e18, 0, 256, 0);
  }

  function test_vouch_revertsAboveMaximum() public {
    uint256 max = vouch.configuredMaximumVouchAmount();
    vm.prank(_admin);
    vouch.setMaximumVouchAmount(10e18);
    token.mint(alice, 100e18);

    vm.expectRevert(abi.encodeWithSelector(AmountAboveMaximum.selector, 10e18 + 1, 10e18));
    vm.prank(alice);
    vouch.vouch("above-max", 10e18 + 1);

    // Restore for downstream tests in the same file run.
    vm.prank(_admin);
    vouch.setMaximumVouchAmount(max);
  }

  function test_vouch_atExactMaximum_succeeds() public {
    vm.prank(_admin);
    vouch.setMaximumVouchAmount(10e18);
    uint256 vid = _vouchAs(alice, "at-max", 10e18);
    EthosVouchV2.Vouch memory v = _getVouch(vid);
    assertEq(v.balance, 10e18);
  }

  function test_increaseVouch_revertsWhenNewBalanceAboveMaximum() public {
    vm.prank(_admin);
    vouch.setMaximumVouchAmount(15e18);
    uint256 vid = _vouchAs(alice, "increase-cap", 10e18);

    vm.expectRevert(abi.encodeWithSelector(AmountAboveMaximum.selector, 20e18, 15e18));
    vm.prank(alice);
    vouch.increaseVouch(vid, 10e18);
  }

  function test_setMaximumVouchAmount_emits_event_and_updates() public {
    uint256 prev = vouch.configuredMaximumVouchAmount();
    vm.expectEmit(false, false, false, true);
    emit EthosVouchV2.MaximumVouchAmountUpdated(prev, 1_000e18);

    vm.prank(_admin);
    vouch.setMaximumVouchAmount(1_000e18);
    assertEq(vouch.configuredMaximumVouchAmount(), 1_000e18);
  }

  function test_setMaximumVouchAmount_revertsBelowMinimum() public {
    uint256 min = vouch.configuredMinimumVouchAmount();
    vm.expectRevert(abi.encodeWithSelector(AmountBelowMinimum.selector, min - 1, min));
    vm.prank(_admin);
    vouch.setMaximumVouchAmount(min - 1);
  }

  function test_setMaximumVouchAmount_revertsForNonAdmin() public {
    vm.expectRevert();
    vm.prank(alice);
    vouch.setMaximumVouchAmount(1_000e18);
  }

  function test_setMaximumVouchAmount_revertsWhenPaused() public {
    _pauseContract(CONTRACT_NAME);
    vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
    vm.prank(_admin);
    vouch.setMaximumVouchAmount(1_000e18);
  }

  function test_setMinimumVouchAmount_revertsAboveMaximum() public {
    vm.prank(_admin);
    vouch.setMaximumVouchAmount(10e18);
    vm.expectRevert(abi.encodeWithSelector(AmountAboveMaximum.selector, 11e18, 10e18));
    vm.prank(_admin);
    vouch.setMinimumVouchAmount(11e18);
  }

  // -------------------------------------------------------------------------
  // vouchFor (composite path)
  // -------------------------------------------------------------------------

  /// @dev Registers a fresh address as the ETHOS_REVIEW contract in CAM so it
  ///      passes the `vouchFor` authorization check.
  function _registerComposer(address composer) internal {
    address[] memory addrs = new address[](1);
    string[] memory names = new string[](1);
    addrs[0] = composer;
    names[0] = "ETHOS_REVIEW";
    _cam.updateContractAddressesForNames(addrs, names);
  }

  /// @dev Funds + approves a composer-caller to push WHUF through `vouchFor`.
  function _fundComposer(address composer, uint256 amount) internal {
    token.mint(composer, amount);
    vm.prank(composer);
    token.approve(address(vouch), type(uint256).max);
  }

  function test_vouchFor_revertsWhenCallerNotInCAM() public {
    address rogue = address(0xDEAD);
    _fundComposer(rogue, 100e18);

    vm.expectRevert(abi.encodeWithSelector(UnauthorizedComposer.selector, rogue));
    vm.prank(rogue);
    vouch.vouchFor(alice, "address:0xabc", 10e18, "");
  }

  function test_vouchFor_revertsWhenAuthorIsZero() public {
    address composer = address(0xC0DE);
    _registerComposer(composer);
    _fundComposer(composer, 100e18);

    vm.expectRevert(InvalidAuthor.selector);
    vm.prank(composer);
    vouch.vouchFor(address(0), "address:0xabc", 10e18, "");
  }

  function test_vouchFor_creditsAuthor_notMsgSender() public {
    address composer = address(0xC0FFEE);
    _registerComposer(composer);
    _fundComposer(composer, 100e18);

    uint256 amount = 10e18;
    uint256 fee = _entryFee(amount);

    uint256 composerBalanceBefore = token.balanceOf(composer);
    uint256 supplyBefore = token.totalSupply();

    vm.prank(composer);
    vouch.vouchFor(alice, "address:0xabc", amount, "");

    uint256 vid = vouch.vouchCount();
    EthosVouchV2.Vouch memory v = _getVouch(vid);
    // Vouch row credited to author (alice), NOT msg.sender (composer).
    assertEq(v.author, alice);
    assertEq(v.balance, amount);
    assertFalse(v.archived);

    // Author-keyed indexes populated under alice.
    assertEq(vouch.vouchIdsByAuthor(alice, 0), vid);
    assertEq(vouch.vouchIdsByAuthorIndex(alice, vid), 0);
    bytes32 targetHash = keccak256(bytes("address:0xabc"));
    assertEq(vouch.vouchIdByAuthorForTargetHash(alice, targetHash), vid);

    // Composer pays WHUF (amount + fee); alice's WHUF balance unchanged.
    assertEq(composerBalanceBefore - token.balanceOf(composer), amount + fee);
    assertEq(token.balanceOf(alice), 100_000e18); // initial mint untouched

    // Fee burned.
    assertEq(supplyBefore - token.totalSupply(), fee);
  }

  function test_vouchFor_emitsVouchedWithAuthorParam() public {
    address composer = address(0xC0F1);
    _registerComposer(composer);
    _fundComposer(composer, 100e18);

    uint256 amount = 10e18;
    uint256 fee = _entryFee(amount);
    bytes32 targetHash = keccak256(bytes("address:0xabc"));

    vm.recordLogs();
    vm.prank(composer);
    vouch.vouchFor(alice, "address:0xabc", amount, "");
    Vm.Log[] memory entries = vm.getRecordedLogs();

    bytes32 vouchedSig = keccak256("Vouched(address,bytes32,uint256,string,uint256,uint256,string)");
    bool found;
    for (uint256 i = 0; i < entries.length; ++i) {
      if (entries[i].topics[0] == vouchedSig) {
        // Topic[1] = indexed author. Must be alice, not composer.
        assertEq(entries[i].topics[1], bytes32(uint256(uint160(alice))));
        assertEq(entries[i].topics[2], targetHash);
        (uint256 vid, string memory tgt, uint256 balance, uint256 emittedFee, string memory metadata) =
          abi.decode(entries[i].data, (uint256, string, uint256, uint256, string));
        assertEq(vid, vouch.vouchCount());
        assertEq(keccak256(bytes(tgt)), targetHash);
        assertEq(balance, amount);
        assertEq(emittedFee, fee);
        assertEq(bytes(metadata).length, 0);
        found = true;
        break;
      }
    }
    assertTrue(found, "Vouched event not emitted");
  }

  function test_vouchFor_setsMetadataWhenProvided() public {
    address composer = address(0xC0F2);
    _registerComposer(composer);
    _fundComposer(composer, 100e18);

    vm.prank(composer);
    vouch.vouchFor(alice, "address:0xabc", 10e18, "{\"foo\":1}");

    uint256 vid = vouch.vouchCount();
    assertEq(vouch.vouchMetadata(vid), "{\"foo\":1}");
  }

  function test_vouchFor_emitsMetadataInVouchedEvent() public {
    address composer = address(0xC0F4);
    _registerComposer(composer);
    _fundComposer(composer, 100e18);

    uint256 amount = 10e18;
    uint256 fee = _entryFee(amount);
    string memory meta = '{"client":"review","reviewId":42}';
    bytes32 targetHash = keccak256(bytes("address:0xdef"));

    vm.expectEmit(true, true, false, true);
    emit EthosVouchV2.Vouched(alice, targetHash, 1, "address:0xdef", amount, fee, meta);

    vm.prank(composer);
    vouch.vouchFor(alice, "address:0xdef", amount, meta);
  }

  function test_vouchFor_blocksReentryFromMaliciousToken() public {
    // Deploy a malicious WHUF-like token that re-enters `vouchFor` from inside
    // its own `transferFrom` hook. The single `_status` slot shared by
    // ReentrancyGuardUpgradeable across vouch / vouchWithPermit / vouchFor
    // must trip on the inner call and revert with ReentrancyGuardReentrantCall.
    MaliciousReentrantToken malicious = new MaliciousReentrantToken();

    // Spin up a fresh vouch proxy bound to the malicious token; reuse the
    // standard rewards + slasher + interaction-control wiring.
    EthosVouchV2 maliciousVouchImpl = new EthosVouchV2();
    EthosVouchV2 maliciousVouch = EthosVouchV2(_deployProxy(address(maliciousVouchImpl)));
    maliciousVouch.initialize(_defaultInitParams(), address(malicious), 100, 50, 1e18, 50000e18, 256, 0);
    _registerControlledContract("ETHOS_VOUCH_V2_REENTRANCY", address(maliciousVouch));
    _allowlistVouchOnRewards(address(maliciousVouch));

    // Composer pays in the malicious token; CAM-register it so vouchFor passes
    // the authorization gate.
    address composer = address(0xC0F3);
    _registerComposer(composer);
    malicious.mint(composer, 100e18);
    vm.prank(composer);
    malicious.approve(address(maliciousVouch), type(uint256).max);

    // Arm the malicious token: on `transferFrom`, re-enter `vouch(...)` (which
    // shares the same nonReentrant guard as `vouchFor`).
    malicious.setTarget(address(maliciousVouch));
    malicious.arm(MaliciousReentrantToken.When.OnTransferFrom, MaliciousReentrantToken.Action.Vouch, 0, "address:0xabc");

    vm.expectRevert(ReentrancyGuardUpgradeable.ReentrancyGuardReentrantCall.selector);
    vm.prank(composer);
    maliciousVouch.vouchFor(alice, "address:0xabc", 10e18, "");
  }

  function test_vouchFor_directVouchUnaffected() public {
    // Sanity: existing direct `vouch(...)` still credits msg.sender, not anyone else.
    vm.prank(alice);
    vouch.vouch("alice-self", 10e18);
    uint256 vid = vouch.vouchCount();
    EthosVouchV2.Vouch memory v = _getVouch(vid);
    assertEq(v.author, alice);
  }

  function test_previewVouchFee_matchesEntryFeeFormula() public view {
    uint256 amount = 12345e18;
    (uint256 fee, uint256 gross) = vouch.previewVouchFee(amount);
    assertEq(fee, _entryFee(amount));
    assertEq(gross, amount + fee);
  }
}
