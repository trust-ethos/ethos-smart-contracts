// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {
  ERC20CappedUpgradeable
} from "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20CappedUpgradeable.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Vm} from "forge-std/Vm.sol";

import {EthosWhuffie} from "../src/EthosWhuffie.sol";
import {WhuffieLockList} from "../src/WhuffieLockList.sol";
import {
  ArrayLengthMismatch,
  TransfersAlreadyUnlocked,
  TransfersLocked,
  ZeroAddress
} from "../src/errors/WhuffieErrors.sol";
import {IWhuffieLockList} from "../src/interfaces/IWhuffieLockList.sol";
import {ETHOS_REVIEW, ETHOS_VOUCH_V2} from "../src/utils/Constants.sol";
import {InteractionControlFixture} from "./helpers/InteractionControlFixture.sol";
import {V2TestFixture} from "./helpers/V2TestFixture.sol";

contract EthosWhuffieTest is V2TestFixture, InteractionControlFixture {
  bytes32 internal constant PERMIT_TYPEHASH =
    keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
  uint256 internal constant PERMIT_USER_PRIVATE_KEY = 0xBEEFCAFE;

  EthosWhuffie public whuffie;

  address internal saleRecipient = makeAddr("saleRecipient");
  address internal treasury = makeAddr("treasury");
  address internal marketMaker = makeAddr("marketMaker");

  function setUp() public {
    _deployInfra();
    whuffie = EthosWhuffie(_deployProxy(address(_deployWhuffieImpl(_lockedAccounts()))));
    whuffie.initialize(_owner, address(_cam), _WHUFFIE_TOKEN_CAP);
  }

  function _lockedAccounts() internal view returns (address[] memory accounts) {
    accounts = new address[](1);
    accounts[0] = saleRecipient;
  }

  function _freshWhuffieProxy() internal returns (EthosWhuffie) {
    return EthosWhuffie(_deployProxy(address(_deployWhuffieImpl(_lockedAccounts()))));
  }

  function _mint(address recipient, uint256 amount) internal {
    vm.prank(_owner);
    whuffie.mint(recipient, amount);
  }

  function _unlock() internal {
    vm.prank(_owner);
    whuffie.unlockTransfers();
  }

  function _registerVouch(address vouch) internal {
    address[] memory addrs = new address[](1);
    string[] memory names = new string[](1);
    addrs[0] = vouch;
    names[0] = ETHOS_VOUCH_V2;
    _cam.updateContractAddressesForNames(addrs, names);
  }

  function _registerReview(address review) internal {
    address[] memory addrs = new address[](1);
    string[] memory names = new string[](1);
    addrs[0] = review;
    names[0] = ETHOS_REVIEW;
    _cam.updateContractAddressesForNames(addrs, names);
  }

  function _countTransfersUnlocked(Vm.Log[] memory logs) internal view returns (uint256 count) {
    for (uint256 i = 0; i < logs.length; i++) {
      if (logs[i].emitter == address(whuffie) && logs[i].topics[0] == EthosWhuffie.TransfersUnlocked.selector) {
        count++;
      }
    }
  }

  function _permitSigner() internal pure returns (address) {
    return vm.addr(PERMIT_USER_PRIVATE_KEY);
  }

  function _signPermit(address owner_, uint256 ownerPk, address spender, uint256 value, uint256 deadline)
    internal
    view
    returns (uint8 v, bytes32 r, bytes32 s)
  {
    bytes32 structHash =
      keccak256(abi.encode(PERMIT_TYPEHASH, owner_, spender, value, whuffie.nonces(owner_), deadline));
    bytes32 digest = MessageHashUtils.toTypedDataHash(whuffie.DOMAIN_SEPARATOR(), structHash);
    (v, r, s) = vm.sign(ownerPk, digest);
  }

  // --- Initialization ---

  function test_initialize_sets_token_metadata() public view {
    assertEq(whuffie.name(), _WHUFFIE_TOKEN_NAME);
    assertEq(whuffie.symbol(), _WHUFFIE_TOKEN_SYMBOL);
    assertEq(whuffie.decimals(), 18);
    assertEq(whuffie.cap(), _WHUFFIE_TOKEN_CAP);
  }

  function test_initialize_sets_owner() public view {
    assertEq(whuffie.owner(), _owner);
    assertEq(whuffie.VERSION(), 2);
  }

  function test_initialize_sets_contract_address_manager_and_starts_locked() public view {
    assertEq(address(whuffie.contractAddressManager()), address(_cam));
    assertFalse(whuffie.transfersUnlocked());
  }

  function test_initialize_sets_domain_separator() public view {
    assertTrue(whuffie.DOMAIN_SEPARATOR() != bytes32(0));
  }

  function test_initialize_reverts_on_double_init() public {
    vm.expectRevert(Initializable.InvalidInitialization.selector);
    whuffie.initialize(_owner, address(_cam), _WHUFFIE_TOKEN_CAP);
  }

  function test_initialize_reverts_on_zero_owner() public {
    EthosWhuffie w = _freshWhuffieProxy();
    vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableInvalidOwner.selector, address(0)));
    w.initialize(address(0), address(_cam), _WHUFFIE_TOKEN_CAP);
  }

  function test_initialize_reverts_on_zero_contract_address_manager() public {
    EthosWhuffie w = _freshWhuffieProxy();
    vm.expectRevert(ZeroAddress.selector);
    w.initialize(_owner, address(0), _WHUFFIE_TOKEN_CAP);
  }

  function test_initialize_reverts_on_zero_cap() public {
    EthosWhuffie w = _freshWhuffieProxy();
    vm.expectRevert(abi.encodeWithSelector(ERC20CappedUpgradeable.ERC20InvalidCap.selector, 0));
    w.initialize(_owner, address(_cam), 0);
  }

  function test_initialize_reverts_on_direct_impl_init() public {
    EthosWhuffie impl = _deployWhuffieImpl();
    vm.expectRevert();
    impl.initialize(_owner, address(_cam), _WHUFFIE_TOKEN_CAP);
  }

  // --- Minting ---

  function test_mint_mints_for_owner() public {
    _mint(_user, 500e18);
    assertEq(whuffie.balanceOf(_user), 500e18);
    assertEq(whuffie.totalSupply(), 500e18);
  }

  function test_mint_allows_zero_amount() public {
    _mint(_user, 0);
    assertEq(whuffie.balanceOf(_user), 0);
    assertEq(whuffie.totalSupply(), 0);
  }

  function test_mint_reverts_for_non_owner() public {
    vm.prank(_admin);
    vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, _admin));
    whuffie.mint(_user, 100e18);
  }

  function test_mint_reverts_above_cap() public {
    EthosWhuffie capped = _freshWhuffieProxy();
    capped.initialize(_owner, address(_cam), 100e18);

    vm.prank(_owner);
    capped.mint(_user, 100e18);

    vm.prank(_owner);
    vm.expectRevert(abi.encodeWithSelector(ERC20CappedUpgradeable.ERC20ExceededCap.selector, 101e18, 100e18));
    capped.mint(_user, 1e18);
  }

  function test_mintBatch_mints_to_multiple_recipients() public {
    address[] memory recipients = new address[](3);
    recipients[0] = _user;
    recipients[1] = _user2;
    recipients[2] = address(0xBA7C03);

    uint256[] memory amounts = new uint256[](3);
    amounts[0] = 100e18;
    amounts[1] = 200e18;
    amounts[2] = 0;

    vm.prank(_owner);
    whuffie.mintBatch(recipients, amounts);

    assertEq(whuffie.balanceOf(recipients[0]), 100e18);
    assertEq(whuffie.balanceOf(recipients[1]), 200e18);
    assertEq(whuffie.balanceOf(recipients[2]), 0);
  }

  function test_mintBatch_reverts_on_length_mismatch() public {
    address[] memory recipients = new address[](2);
    uint256[] memory amounts = new uint256[](1);

    vm.prank(_owner);
    vm.expectRevert(abi.encodeWithSelector(ArrayLengthMismatch.selector, 2, 1));
    whuffie.mintBatch(recipients, amounts);
  }

  function test_mintBatch_reverts_for_non_owner() public {
    address[] memory recipients = new address[](1);
    uint256[] memory amounts = new uint256[](1);
    recipients[0] = _user;
    amounts[0] = 100e18;

    vm.prank(_admin);
    vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, _admin));
    whuffie.mintBatch(recipients, amounts);
  }

  // --- Transfer lock, burn, and permit ---

  function test_transfer_reverts_while_locked() public {
    _mint(saleRecipient, 1000e18);

    vm.prank(saleRecipient);
    vm.expectRevert(abi.encodeWithSelector(TransfersLocked.selector, saleRecipient, _user2));
    whuffie.transfer(_user2, 100e18);
  }

  function test_transfer_succeeds_for_unlisted_sender_while_locked() public {
    _mint(_user, 1000e18);

    vm.prank(_user);
    whuffie.transfer(_user2, 100e18);

    assertEq(whuffie.balanceOf(_user2), 100e18);
  }

  function test_transfer_reverts_for_account_locked_after_construction() public {
    _mint(marketMaker, 1000e18);
    address[] memory accounts = new address[](1);
    accounts[0] = marketMaker;
    WhuffieLockList(address(whuffie.lockList())).lock(accounts);

    vm.prank(marketMaker);
    vm.expectRevert(abi.encodeWithSelector(TransfersLocked.selector, marketMaker, _user2));
    whuffie.transfer(_user2, 100e18);
  }

  function test_transferFrom_reverts_while_locked() public {
    _mint(saleRecipient, 1000e18);
    vm.prank(saleRecipient);
    whuffie.approve(marketMaker, 500e18);

    vm.prank(marketMaker);
    vm.expectRevert(abi.encodeWithSelector(TransfersLocked.selector, saleRecipient, marketMaker));
    whuffie.transferFrom(saleRecipient, marketMaker, 100e18);
  }

  function test_burn_succeeds_for_locked_holder_while_locked() public {
    _mint(saleRecipient, 1000e18);

    vm.prank(saleRecipient);
    whuffie.burn(400e18);

    assertEq(whuffie.balanceOf(saleRecipient), 600e18);
    assertEq(whuffie.totalSupply(), 600e18);
  }

  function test_transfer_succeeds_through_unknown_free_holders_while_locked() public {
    address unknown = makeAddr("unknown");
    address unknown2 = makeAddr("unknown2");
    _mint(treasury, 200_000e18);

    vm.prank(treasury);
    whuffie.transfer(marketMaker, 200_000e18);
    vm.prank(marketMaker);
    whuffie.transfer(unknown, 50_000e18);
    vm.prank(unknown);
    whuffie.transfer(unknown2, 20_000e18);

    assertEq(whuffie.balanceOf(marketMaker), 150_000e18);
    assertEq(whuffie.balanceOf(unknown), 30_000e18);
    assertEq(whuffie.balanceOf(unknown2), 20_000e18);
  }

  function test_transfer_to_locked_holder_succeeds_but_cannot_be_forwarded_while_locked() public {
    _mint(marketMaker, 1000e18);

    vm.prank(marketMaker);
    whuffie.transfer(saleRecipient, 400e18);
    assertEq(whuffie.balanceOf(saleRecipient), 400e18);

    vm.prank(saleRecipient);
    vm.expectRevert(abi.encodeWithSelector(TransfersLocked.selector, saleRecipient, marketMaker));
    whuffie.transfer(marketMaker, 400e18);
  }

  function test_approve_works_while_locked() public {
    _mint(saleRecipient, 1000e18);

    vm.prank(saleRecipient);
    whuffie.approve(_user2, 500e18);

    assertEq(whuffie.allowance(saleRecipient, _user2), 500e18);
  }

  function test_vouch_recipient_can_receive_while_locked() public {
    address vouchContract = address(0xFEED);
    _mint(saleRecipient, 1000e18);
    _registerVouch(vouchContract);

    vm.prank(saleRecipient);
    whuffie.transfer(vouchContract, 400e18);

    assertEq(whuffie.balanceOf(saleRecipient), 600e18);
    assertEq(whuffie.balanceOf(vouchContract), 400e18);
  }

  function test_vouch_sender_can_send_while_locked() public {
    address vouchContract = address(0xFEED);
    _mint(vouchContract, 1000e18);
    _registerVouch(vouchContract);

    vm.prank(vouchContract);
    whuffie.transfer(saleRecipient, 400e18);

    assertEq(whuffie.balanceOf(vouchContract), 600e18);
    assertEq(whuffie.balanceOf(saleRecipient), 400e18);
  }

  function test_unvouch_payout_stays_locked_for_locked_holder() public {
    address vouchContract = address(0xFEED);
    _mint(saleRecipient, 1000e18);
    _registerVouch(vouchContract);

    vm.prank(saleRecipient);
    whuffie.transfer(vouchContract, 400e18);
    vm.prank(vouchContract);
    whuffie.transfer(saleRecipient, 400e18);
    assertEq(whuffie.balanceOf(saleRecipient), 1000e18);

    vm.prank(saleRecipient);
    vm.expectRevert(abi.encodeWithSelector(TransfersLocked.selector, saleRecipient, _user2));
    whuffie.transfer(_user2, 400e18);
  }

  function test_review_can_pull_into_itself_while_locked() public {
    address reviewContract = address(0xB00C);
    _mint(saleRecipient, 1000e18);
    _registerReview(reviewContract);

    vm.prank(saleRecipient);
    whuffie.approve(reviewContract, 500e18);

    vm.prank(reviewContract);
    whuffie.transferFrom(saleRecipient, reviewContract, 400e18);

    assertEq(whuffie.balanceOf(saleRecipient), 600e18);
    assertEq(whuffie.balanceOf(reviewContract), 400e18);
  }

  function test_user_cannot_transfer_directly_to_review_while_locked() public {
    address reviewContract = address(0xB00C);
    _mint(saleRecipient, 1000e18);
    _registerReview(reviewContract);

    vm.prank(saleRecipient);
    vm.expectRevert(abi.encodeWithSelector(TransfersLocked.selector, saleRecipient, reviewContract));
    whuffie.transfer(reviewContract, 400e18);
  }

  function test_unregistered_vouch_blocks_locked_sender_while_locked() public {
    _mint(saleRecipient, 1000e18);

    vm.prank(saleRecipient);
    vm.expectRevert(abi.encodeWithSelector(TransfersLocked.selector, saleRecipient, _user2));
    whuffie.transfer(_user2, 100e18);
  }

  // --- Scheduled unlock ---

  function test_transfer_succeeds_at_UNLOCK_AT_and_reverts_one_second_before() public {
    _mint(saleRecipient, 1000e18);

    vm.warp(whuffie.UNLOCK_AT() - 1);
    vm.prank(saleRecipient);
    vm.expectRevert(abi.encodeWithSelector(TransfersLocked.selector, saleRecipient, _user2));
    whuffie.transfer(_user2, 100e18);

    vm.warp(whuffie.UNLOCK_AT());
    vm.prank(saleRecipient);
    whuffie.transfer(_user2, 100e18);
    assertEq(whuffie.balanceOf(_user2), 100e18);
  }

  function test_transfer_emits_TransfersUnlocked_at_UNLOCK_AT() public {
    _mint(saleRecipient, 1000e18);
    vm.warp(whuffie.UNLOCK_AT() + 1 days);

    vm.expectEmit(true, true, true, true, address(whuffie));
    emit EthosWhuffie.TransfersUnlocked(_owner, whuffie.UNLOCK_AT());
    vm.prank(saleRecipient);
    whuffie.transfer(_user2, 100e18);

    assertTrue(whuffie.transfersUnlocked());
  }

  function test_transfer_emits_TransfersUnlocked_once_after_UNLOCK_AT() public {
    _mint(saleRecipient, 1000e18);
    _mint(treasury, 1000e18);
    vm.warp(whuffie.UNLOCK_AT());
    vm.recordLogs();

    vm.prank(saleRecipient);
    whuffie.transfer(_user2, 100e18);
    vm.prank(saleRecipient);
    whuffie.transfer(_user2, 100e18);
    vm.prank(treasury);
    whuffie.transfer(_user2, 100e18);

    assertEq(_countTransfersUnlocked(vm.getRecordedLogs()), 1);
  }

  function test_transfer_emits_no_TransfersUnlocked_after_early_unlock() public {
    _mint(saleRecipient, 1000e18);
    _unlock();

    vm.prank(saleRecipient);
    whuffie.transfer(_user2, 100e18);

    vm.warp(whuffie.UNLOCK_AT() + 1);
    vm.recordLogs();
    vm.prank(saleRecipient);
    whuffie.transfer(_user2, 100e18);

    assertEq(_countTransfersUnlocked(vm.getRecordedLogs()), 0);
    assertEq(whuffie.balanceOf(_user2), 200e18);
  }

  function test_unlockTransfers_flips_flag_and_enables_transfers() public {
    _mint(saleRecipient, 1000e18);

    _unlock();

    assertTrue(whuffie.transfersUnlocked());
    vm.prank(saleRecipient);
    whuffie.transfer(_user2, 400e18);
    assertEq(whuffie.balanceOf(_user2), 400e18);
  }

  function test_unlockTransfers_emits_event() public {
    vm.expectEmit(true, true, true, true, address(whuffie));
    emit EthosWhuffie.TransfersUnlocked(_owner, block.timestamp);
    _unlock();
  }

  function test_unlockTransfers_reverts_after_auto_unlock() public {
    _mint(_user, 1000e18);
    vm.warp(whuffie.UNLOCK_AT() + 1);
    vm.prank(_user);
    whuffie.transfer(_user2, 100e18);

    vm.prank(_owner);
    vm.expectRevert(TransfersAlreadyUnlocked.selector);
    whuffie.unlockTransfers();
  }

  function test_unlockTransfers_reverts_for_non_owner() public {
    vm.prank(_admin);
    vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, _admin));
    whuffie.unlockTransfers();
  }

  function test_unlockTransfers_reverts_on_second_call() public {
    _unlock();

    vm.prank(_owner);
    vm.expectRevert(TransfersAlreadyUnlocked.selector);
    whuffie.unlockTransfers();
  }

  function test_burn_zero_is_noop() public {
    _mint(_user, 1000e18);

    vm.prank(_user);
    whuffie.burn(0);

    assertEq(whuffie.balanceOf(_user), 1000e18);
    assertEq(whuffie.totalSupply(), 1000e18);
  }

  function test_burnFrom_consumes_allowance_and_reduces_supply() public {
    _mint(_user, 1000e18);
    vm.prank(_user);
    whuffie.approve(_user2, 500e18);

    vm.prank(_user2);
    whuffie.burnFrom(_user, 300e18);

    assertEq(whuffie.balanceOf(_user), 700e18);
    assertEq(whuffie.totalSupply(), 700e18);
    assertEq(whuffie.allowance(_user, _user2), 200e18);
  }

  function test_burn_reverts_on_insufficient_balance() public {
    _mint(_user, 100e18);

    vm.prank(_user);
    vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InsufficientBalance.selector, _user, 100e18, 200e18));
    whuffie.burn(200e18);
  }

  function test_permit_sets_allowance() public {
    address owner_ = _permitSigner();
    uint256 deadline = block.timestamp + 1 hours;
    (uint8 v, bytes32 r, bytes32 s) = _signPermit(owner_, PERMIT_USER_PRIVATE_KEY, _user2, 500e18, deadline);

    whuffie.permit(owner_, _user2, 500e18, deadline, v, r, s);

    assertEq(whuffie.allowance(owner_, _user2), 500e18);
    assertEq(whuffie.nonces(owner_), 1);
  }

  // --- Pause ---

  function test_pause_blocks_balance_changes() public {
    _mint(_user, 1000e18);

    vm.prank(_owner);
    whuffie.pause();

    vm.prank(_user);
    vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
    whuffie.transfer(_user2, 100e18);

    vm.prank(_owner);
    vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
    whuffie.mint(_user2, 100e18);

    vm.prank(_user);
    vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
    whuffie.burn(100e18);
  }

  function test_unpause_restores_balance_changes() public {
    _mint(_user, 1000e18);
    _unlock();

    vm.prank(_owner);
    whuffie.pause();
    vm.prank(_owner);
    whuffie.unpause();

    vm.prank(_user);
    whuffie.transfer(_user2, 100e18);
    assertEq(whuffie.balanceOf(_user2), 100e18);
  }

  function test_pause_at_UNLOCK_AT_defers_auto_unlock_until_unpause() public {
    _mint(saleRecipient, 1000e18);
    vm.prank(_owner);
    whuffie.pause();
    vm.warp(whuffie.UNLOCK_AT());

    vm.prank(saleRecipient);
    vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
    whuffie.transfer(_user2, 100e18);
    assertFalse(whuffie.transfersUnlocked());

    vm.prank(_owner);
    whuffie.unpause();
    vm.recordLogs();
    vm.expectEmit(true, true, true, true, address(whuffie));
    emit EthosWhuffie.TransfersUnlocked(_owner, whuffie.UNLOCK_AT());
    vm.prank(saleRecipient);
    whuffie.transfer(_user2, 100e18);

    assertEq(_countTransfersUnlocked(vm.getRecordedLogs()), 1);
    assertEq(whuffie.balanceOf(_user2), 100e18);
  }

  function test_pause_reverts_for_non_owner() public {
    vm.prank(_admin);
    vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, _admin));
    whuffie.pause();
  }

  function test_interactionControlPauseAll_does_not_pause_whuf() public {
    _setupInteractionControl(_cam);
    _ic.pauseAll();

    _mint(_user, 1000e18);
    _unlock();
    vm.prank(_user);
    whuffie.transfer(_user2, 100e18);

    assertFalse(whuffie.paused());
    assertEq(whuffie.balanceOf(_user2), 100e18);
  }

  // --- Ownership and UUPS ---

  function test_ownership_transfer_round_trip() public {
    vm.prank(_owner);
    whuffie.transferOwnership(_user);

    vm.prank(_user);
    whuffie.acceptOwnership();

    assertEq(whuffie.owner(), _user);
  }

  function test_uups_upgrade_preserves_storage() public {
    _mint(_user, 500e18);
    uint256 balanceBefore = whuffie.balanceOf(_user);

    EthosWhuffie newImpl = _deployWhuffieImpl(_lockedAccounts());
    vm.prank(_owner);
    whuffie.upgradeToAndCall(address(newImpl), "");

    assertEq(whuffie.balanceOf(_user), balanceBefore);
    assertEq(whuffie.owner(), _owner);
    assertEq(whuffie.cap(), _WHUFFIE_TOKEN_CAP);
  }

  function test_constructor_binds_lock_list() public view {
    IWhuffieLockList list = whuffie.lockList();

    assertTrue(list.isLocked(saleRecipient));
    assertFalse(list.isLocked(treasury));
    assertFalse(list.isLocked(marketMaker));
  }

  function test_constructor_reverts_on_zero_lock_list() public {
    vm.expectRevert(ZeroAddress.selector);
    new EthosWhuffie(IWhuffieLockList(address(0)));
  }

  function test_uups_upgrade_activates_new_lock_list() public {
    _mint(saleRecipient, 1000e18);
    _mint(marketMaker, 1000e18);
    address[] memory locked = new address[](1);
    locked[0] = marketMaker;
    EthosWhuffie newImpl = _deployWhuffieImpl(locked);

    vm.prank(_owner);
    whuffie.upgradeToAndCall(address(newImpl), "");

    vm.prank(saleRecipient);
    whuffie.transfer(_user, 100e18);
    assertEq(whuffie.balanceOf(_user), 100e18);

    vm.prank(marketMaker);
    vm.expectRevert(abi.encodeWithSelector(TransfersLocked.selector, marketMaker, _user));
    whuffie.transfer(_user, 100e18);
  }

  function test_uups_upgrade_reverts_for_non_owner() public {
    EthosWhuffie newImpl = _deployWhuffieImpl();

    vm.prank(_admin);
    vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, _admin));
    whuffie.upgradeToAndCall(address(newImpl), "");
  }

  // --- Removed signer API ---

  function test_removed_signature_accessors_are_absent() public view {
    (bool expectedSignerExists,) = address(whuffie).staticcall(abi.encodeWithSignature("expectedSigner()"));
    (bool signatureVerifierExists,) = address(whuffie).staticcall(abi.encodeWithSignature("signatureVerifier()"));
    (bool signatureUsedExists,) =
      address(whuffie).staticcall(abi.encodeWithSignature("signatureUsed(bytes32)", bytes32(0)));

    assertFalse(expectedSignerExists);
    assertFalse(signatureVerifierExists);
    assertFalse(signatureUsedExists);
  }
}
