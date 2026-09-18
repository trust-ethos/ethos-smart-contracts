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

import {EthosWhuffie} from "../src/EthosWhuffie.sol";
import {
  ArrayLengthMismatch,
  TransfersAlreadyUnlocked,
  TransfersLocked,
  ZeroAddress
} from "../src/errors/WhuffieErrors.sol";
import {ETHOS_REVIEW, ETHOS_VOUCH_V2} from "../src/utils/Constants.sol";
import {InteractionControlFixture} from "./helpers/InteractionControlFixture.sol";
import {V2TestFixture} from "./helpers/V2TestFixture.sol";

contract EthosWhuffieTest is V2TestFixture, InteractionControlFixture {
  bytes32 internal constant PERMIT_TYPEHASH =
    keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
  uint256 internal constant PERMIT_USER_PRIVATE_KEY = 0xBEEFCAFE;

  EthosWhuffie public whuffie;

  function setUp() public {
    _deployInfra();
    whuffie = EthosWhuffie(_deployProxy(address(new EthosWhuffie())));
    whuffie.initialize(_owner, address(_cam), _WHUFFIE_TOKEN_CAP);
  }

  function _freshWhuffieProxy() internal returns (EthosWhuffie) {
    return EthosWhuffie(_deployProxy(address(new EthosWhuffie())));
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
    assertEq(whuffie.VERSION(), 1);
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
    EthosWhuffie impl = new EthosWhuffie();
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
    _mint(_user, 1000e18);

    vm.prank(_user);
    vm.expectRevert(abi.encodeWithSelector(TransfersLocked.selector, _user, _user2));
    whuffie.transfer(_user2, 100e18);
  }

  function test_transferFrom_reverts_while_locked() public {
    _mint(_user, 1000e18);
    vm.prank(_user);
    whuffie.approve(_user2, 500e18);

    vm.prank(_user2);
    vm.expectRevert(abi.encodeWithSelector(TransfersLocked.selector, _user, _user2));
    whuffie.transferFrom(_user, _user2, 100e18);
  }

  function test_approve_works_while_locked() public {
    _mint(_user, 1000e18);

    vm.prank(_user);
    whuffie.approve(_user2, 500e18);

    assertEq(whuffie.allowance(_user, _user2), 500e18);
  }

  function test_vouch_recipient_can_receive_while_locked() public {
    address vouchContract = address(0xFEED);
    _mint(_user, 1000e18);
    _registerVouch(vouchContract);

    vm.prank(_user);
    whuffie.transfer(vouchContract, 400e18);

    assertEq(whuffie.balanceOf(_user), 600e18);
    assertEq(whuffie.balanceOf(vouchContract), 400e18);
  }

  function test_vouch_sender_can_send_while_locked() public {
    address vouchContract = address(0xFEED);
    _mint(vouchContract, 1000e18);
    _registerVouch(vouchContract);

    vm.prank(vouchContract);
    whuffie.transfer(_user, 400e18);

    assertEq(whuffie.balanceOf(vouchContract), 600e18);
    assertEq(whuffie.balanceOf(_user), 400e18);
  }

  function test_review_can_pull_into_itself_while_locked() public {
    address reviewContract = address(0xB00C);
    _mint(_user, 1000e18);
    _registerReview(reviewContract);

    vm.prank(_user);
    whuffie.approve(reviewContract, 500e18);

    vm.prank(reviewContract);
    whuffie.transferFrom(_user, reviewContract, 400e18);

    assertEq(whuffie.balanceOf(_user), 600e18);
    assertEq(whuffie.balanceOf(reviewContract), 400e18);
  }

  function test_user_cannot_transfer_directly_to_review_while_locked() public {
    address reviewContract = address(0xB00C);
    _mint(_user, 1000e18);
    _registerReview(reviewContract);

    vm.prank(_user);
    vm.expectRevert(abi.encodeWithSelector(TransfersLocked.selector, _user, reviewContract));
    whuffie.transfer(reviewContract, 400e18);
  }

  function test_unregistered_vouch_blocks_all_transfers_while_locked() public {
    _mint(_user, 1000e18);

    vm.prank(_user);
    vm.expectRevert(abi.encodeWithSelector(TransfersLocked.selector, _user, _user2));
    whuffie.transfer(_user2, 100e18);
  }

  function test_unlockTransfers_flips_flag_and_enables_transfers() public {
    _mint(_user, 1000e18);

    _unlock();

    assertTrue(whuffie.transfersUnlocked());
    vm.prank(_user);
    whuffie.transfer(_user2, 400e18);
    assertEq(whuffie.balanceOf(_user2), 400e18);
  }

  function test_unlockTransfers_emits_event() public {
    vm.expectEmit(true, true, true, true, address(whuffie));
    emit EthosWhuffie.TransfersUnlocked(_owner, block.timestamp);
    _unlock();
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

    EthosWhuffie newImpl = new EthosWhuffie();
    vm.prank(_owner);
    whuffie.upgradeToAndCall(address(newImpl), "");

    assertEq(whuffie.balanceOf(_user), balanceBefore);
    assertEq(whuffie.owner(), _owner);
    assertEq(whuffie.cap(), _WHUFFIE_TOKEN_CAP);
  }

  function test_uups_upgrade_reverts_for_non_owner() public {
    EthosWhuffie newImpl = new EthosWhuffie();

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
