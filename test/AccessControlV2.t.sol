// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlV2} from "../src/utils/AccessControlV2.sol";
import {NotPendingOwner, RenounceNotAllowed} from "../src/errors/AccessControlV2Errors.sol";
import {SignatureControl} from "../src/utils/SignatureControl.sol";
import {ContractAddressManager} from "../src/utils/ContractAddressManager.sol";
import {V2TestFixture} from "./helpers/V2TestFixture.sol";

/// @dev Minimal concrete contract to test AccessControlV2 behind a UUPS proxy.
contract TestAccessControlV2 is AccessControlV2, UUPSUpgradeable {
  function initialize(AccessControlInitParams calldata p) external initializer {
    __accessControl_init(p);
    __UUPSUpgradeable_init();
  }

  function _authorizeUpgrade(address newImplementation)
    internal
    override
    onlyOwner
    onlyNonZeroAddress(newImplementation)
  {}
}

contract AccessControlV2Test is V2TestFixture {
  TestAccessControlV2 public ac;

  function setUp() public {
    _deployInfra();
    TestAccessControlV2 impl = new TestAccessControlV2();
    ac = TestAccessControlV2(_deployProxy(address(impl)));
    ac.initialize(_defaultInitParams());
  }

  // --- Initialization ---

  function test_initialize_sets_roles() public view {
    assertTrue(ac.hasRole(ac.OWNER_ROLE(), _owner));
    assertTrue(ac.hasRole(ac.ADMIN_ROLE(), _admin));
  }

  function test_initialize_reverts_on_zero_contractAddressManager() public {
    TestAccessControlV2 impl = new TestAccessControlV2();
    TestAccessControlV2 fresh = TestAccessControlV2(_deployProxy(address(impl)));
    AccessControlV2.AccessControlInitParams memory p = _defaultInitParams();
    p.contractAddressManager = address(0);
    vm.expectRevert();
    fresh.initialize(p);
  }

  function test_initialize_reverts_on_double_init() public {
    vm.expectRevert(Initializable.InvalidInitialization.selector);
    ac.initialize(_defaultInitParams());
  }

  // --- transferOwnership ---

  function test_transferOwnership_sets_pendingOwner() public {
    vm.prank(_owner);
    ac.transferOwnership(_user);

    assertEq(ac.pendingOwner(), _user);
    // Owner hasn't changed yet
    assertTrue(ac.hasRole(ac.OWNER_ROLE(), _owner));
    assertFalse(ac.hasRole(ac.OWNER_ROLE(), _user));
  }

  function test_transferOwnership_emits_event() public {
    vm.expectEmit(true, true, true, true);
    emit AccessControlV2.OwnershipTransferStarted(_owner, _user);

    vm.prank(_owner);
    ac.transferOwnership(_user);
  }

  function test_transferOwnership_reverts_for_non_owner() public {
    vm.prank(_admin);
    vm.expectRevert();
    ac.transferOwnership(_user);
  }

  function test_transferOwnership_to_zero_cancels_pending() public {
    vm.prank(_owner);
    ac.transferOwnership(_user);
    assertEq(ac.pendingOwner(), _user);

    vm.expectEmit(true, true, true, true);
    emit AccessControlV2.OwnershipTransferCancelled(_user);

    vm.prank(_owner);
    ac.transferOwnership(address(0));
    assertEq(ac.pendingOwner(), address(0));
  }

  function test_transferOwnership_overwrites_pending() public {
    vm.prank(_owner);
    ac.transferOwnership(_user);
    assertEq(ac.pendingOwner(), _user);

    vm.prank(_owner);
    ac.transferOwnership(_user2);
    assertEq(ac.pendingOwner(), _user2);
  }

  // --- acceptOwnership ---

  function test_acceptOwnership_completes_transfer() public {
    vm.prank(_owner);
    ac.transferOwnership(_user);

    vm.prank(_user);
    ac.acceptOwnership();

    assertTrue(ac.hasRole(ac.OWNER_ROLE(), _user));
    assertFalse(ac.hasRole(ac.OWNER_ROLE(), _owner));
    assertEq(ac.pendingOwner(), address(0));
  }

  function test_acceptOwnership_emits_OwnershipTransferred() public {
    vm.prank(_owner);
    ac.transferOwnership(_user);

    vm.expectEmit(true, true, true, true);
    emit AccessControlV2.OwnershipTransferred(_owner, _user);

    vm.prank(_user);
    ac.acceptOwnership();
  }

  function test_acceptOwnership_reverts_for_wrong_caller() public {
    vm.prank(_owner);
    ac.transferOwnership(_user);

    vm.prank(_user2);
    vm.expectRevert(abi.encodeWithSelector(NotPendingOwner.selector, _user2, _user));
    ac.acceptOwnership();
  }

  function test_acceptOwnership_reverts_when_no_pending_transfer() public {
    vm.prank(_user);
    vm.expectRevert(abi.encodeWithSelector(NotPendingOwner.selector, _user, address(0)));
    ac.acceptOwnership();
  }

  // --- No updateOwner ---

  function test_no_updateOwner_selector_reverts() public view {
    bytes4 selector = bytes4(keccak256("updateOwner(address)"));
    (bool success,) = address(ac).staticcall(abi.encodeWithSelector(selector, _user));
    assertFalse(success, "updateOwner selector should revert on V2");
  }

  // --- Admin management ---

  function test_addAdmin_works() public {
    vm.prank(_owner);
    ac.addAdmin(_user);
    assertTrue(ac.hasRole(ac.ADMIN_ROLE(), _user));
  }

  function test_removeAdmin_works() public {
    vm.prank(_owner);
    ac.removeAdmin(_admin);
    assertFalse(ac.hasRole(ac.ADMIN_ROLE(), _admin));
  }

  // --- transferOwnership to self ---

  function test_transferOwnership_to_self() public {
    vm.prank(_owner);
    ac.transferOwnership(_owner);
    assertEq(ac.pendingOwner(), _owner);

    vm.prank(_owner);
    ac.acceptOwnership();

    assertTrue(ac.hasRole(ac.OWNER_ROLE(), _owner));
    assertEq(ac.pendingOwner(), address(0));
  }

  // --- OwnershipTransferCancelled event on overwrite ---

  function test_transferOwnership_emits_cancellation_event() public {
    vm.prank(_owner);
    ac.transferOwnership(_user);

    vm.expectEmit(true, true, true, true);
    emit AccessControlV2.OwnershipTransferCancelled(_user);

    vm.prank(_owner);
    ac.transferOwnership(_user2);

    assertEq(ac.pendingOwner(), _user2);
  }

  // --- addAdmin zero-address guard ---

  function test_addAdmin_reverts_on_zero_address() public {
    vm.prank(_owner);
    vm.expectRevert(abi.encodeWithSelector(SignatureControl.ZeroAddress.selector));
    ac.addAdmin(address(0));
  }

  // --- removeAdmin zero-address guard ---

  function test_removeAdmin_reverts_on_zero_address() public {
    vm.prank(_owner);
    vm.expectRevert(abi.encodeWithSelector(SignatureControl.ZeroAddress.selector));
    ac.removeAdmin(address(0));
  }

  // --- updateContractAddressManager zero-address guard ---

  function test_updateContractAddressManager_reverts_on_zero_address() public {
    vm.prank(_owner);
    vm.expectRevert(abi.encodeWithSelector(SignatureControl.ZeroAddress.selector));
    ac.updateContractAddressManager(address(0));
  }

  // --- renounceRole disabled ---

  function test_renounceRole_reverts_for_owner() public {
    bytes32 ownerRole = ac.OWNER_ROLE();
    vm.prank(_owner);
    vm.expectRevert(abi.encodeWithSelector(RenounceNotAllowed.selector));
    ac.renounceRole(ownerRole, _owner);
  }

  function test_renounceRole_reverts_for_admin() public {
    bytes32 adminRole = ac.ADMIN_ROLE();
    vm.prank(_admin);
    vm.expectRevert(abi.encodeWithSelector(RenounceNotAllowed.selector));
    ac.renounceRole(adminRole, _admin);
  }

  // --- External grantRole/revokeRole blocked by unassigned DEFAULT_ADMIN_ROLE ---

  function test_external_grantRole_reverts_for_owner_role() public {
    bytes32 ownerRole = ac.OWNER_ROLE();
    vm.prank(_owner);
    vm.expectRevert();
    ac.grantRole(ownerRole, _user);
  }

  function test_external_grantRole_reverts_for_admin_role() public {
    bytes32 adminRole = ac.ADMIN_ROLE();
    vm.prank(_owner);
    vm.expectRevert();
    ac.grantRole(adminRole, _user);
  }

  function test_external_revokeRole_reverts_for_admin_role() public {
    bytes32 adminRole = ac.ADMIN_ROLE();
    vm.prank(_owner);
    vm.expectRevert();
    ac.revokeRole(adminRole, _admin);
  }

  // --- Owner-only infra functions reject admin ---

  function test_updateContractAddressManager_reverts_for_admin() public {
    vm.prank(_admin);
    vm.expectRevert();
    ac.updateContractAddressManager(address(0xDEAD));
  }

  function test_updateExpectedSigner_reverts_for_admin() public {
    vm.prank(_admin);
    vm.expectRevert();
    ac.updateExpectedSigner(address(0xDEAD));
  }

  function test_updateSignatureVerifier_reverts_for_admin() public {
    vm.prank(_admin);
    vm.expectRevert();
    ac.updateSignatureVerifier(address(0xDEAD));
  }

  // --- Owner-only infra functions succeed for owner ---

  function test_updateContractAddressManager_succeeds_for_owner() public {
    ContractAddressManager newCam = new ContractAddressManager();
    vm.prank(_owner);
    ac.updateContractAddressManager(address(newCam));
    assertEq(address(ac.contractAddressManager()), address(newCam));
  }

  function test_updateExpectedSigner_succeeds_for_owner() public {
    vm.prank(_owner);
    ac.updateExpectedSigner(_user);
    assertEq(ac.expectedSigner(), _user);
  }

  function test_updateSignatureVerifier_succeeds_for_owner() public {
    vm.prank(_owner);
    ac.updateSignatureVerifier(_user);
    assertEq(ac.signatureVerifier(), _user);
  }

  // --- Pause/unpause via InteractionControl ---

  function test_pause_reverts_for_non_interaction_control() public {
    vm.prank(_owner);
    vm.expectRevert();
    ac.pause();
  }

  function test_unpause_reverts_for_non_interaction_control() public {
    vm.prank(_owner);
    vm.expectRevert();
    ac.unpause();
  }
}
