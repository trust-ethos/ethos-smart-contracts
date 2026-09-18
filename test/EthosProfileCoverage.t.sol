// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Test} from "forge-std/Test.sol";

import {EthosProfile} from "../src/legacy/EthosProfile.sol";
import {
  AddressAuthorization,
  AddressCompromised,
  AddressNotInvited,
  InvalidIndex,
  InvalidSender,
  MaxAddressesReached,
  MaxInvitesReached,
  ProfileAccess,
  ProfileExistsForAddress,
  ProfileNotFound,
  ProfileNotFoundForAddress
} from "../src/legacy/errors/ProfileErrors.sol";
import {SignatureVerifier} from "../src/legacy/SignatureVerifier.sol";
import {ContractAddressManager} from "../src/utils/ContractAddressManager.sol";
import {ETHOS_ATTESTATION, ETHOS_PROFILE, ETHOS_REVIEW, ETHOS_VOUCH} from "../src/utils/Constants.sol";

contract MockLegacyVouchHook {
  bytes32 public lastAttestationHash;
  uint256 public lastProfileId;
  uint256 public callCount;

  function handleAttestationClaim(bytes32 attestationHash, uint256 profileId) external {
    lastAttestationHash = attestationHash;
    lastProfileId = profileId;
    callCount++;
  }
}

contract EthosProfileCoverageTest is Test {
  address internal owner = address(0x1001);
  address internal admin = address(0x1002);
  uint256 internal signerPrivateKey = 0xA11CE;
  address internal signer;
  address internal reviewCaller = address(0x2001);
  address internal attestationCaller = address(0x2002);

  ContractAddressManager internal cam;
  SignatureVerifier internal verifier;
  EthosProfile internal profile;
  MockLegacyVouchHook internal vouchHook;

  function setUp() public {
    vm.warp(100);
    signer = vm.addr(signerPrivateKey);
    cam = new ContractAddressManager();
    verifier = new SignatureVerifier();
    vouchHook = new MockLegacyVouchHook();

    profile = EthosProfile(address(new ERC1967Proxy(address(new EthosProfile()), "")));
    profile.initialize(owner, admin, signer, address(verifier), address(cam));

    address[] memory addrs = new address[](4);
    string[] memory names = new string[](4);
    addrs[0] = address(profile);
    addrs[1] = reviewCaller;
    addrs[2] = attestationCaller;
    addrs[3] = address(vouchHook);
    names[0] = ETHOS_PROFILE;
    names[1] = ETHOS_REVIEW;
    names[2] = ETHOS_ATTESTATION;
    names[3] = ETHOS_VOUCH;
    cam.updateContractAddressesForNames(addrs, names);
  }

  function test_inviteUninviteCreateProfileAndViews() public {
    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    address[] memory invitees = new address[](2);
    invitees[0] = alice;
    invitees[1] = bob;

    vm.prank(owner);
    profile.bulkInviteAddresses(invitees);

    address[] memory pending = profile.sentInvitationsForProfile(1);
    assertEq(pending.length, 2);
    assertEq(pending[0], alice);
    assertEq(pending[1], bob);
    assertEq(profile.sentAt(1, alice), block.timestamp);

    vm.prank(owner);
    profile.uninviteUser(alice);

    pending = profile.sentInvitationsForProfile(1);
    assertEq(pending.length, 1);
    assertEq(pending[0], bob);
    assertEq(profile.sentAt(1, alice), 0);

    vm.prank(bob);
    profile.createProfile(1);
    uint256 bobId = profile.verifiedProfileIdForAddress(bob);
    assertEq(bobId, 2);

    EthosProfile.Profile memory bobProfile = profile.getProfile(bobId);
    assertEq(bobProfile.profileId, bobId);
    assertEq(bobProfile.inviteInfo.invitedBy, 1);

    uint256[] memory accepted = profile.invitedIdsForProfile(1);
    assertEq(accepted.length, 1);
    assertEq(accepted[0], bobId);

    address[] memory addresses = profile.addressesForProfile(bobId);
    assertEq(addresses.length, 1);
    assertEq(addresses[0], bob);

    EthosProfile.InviteInfo memory ownerInvites = profile.inviteInfoForProfileId(1);
    assertEq(ownerInvites.available, 9);

    (bool exists, bool allowed) = profile.targetExistsAndAllowedForId(bobId);
    assertTrue(exists);
    assertTrue(allowed);
    assertTrue(profile.addressBelongsToProfile(bob, bobId));

    (bool verified, bool archived) = profile.profileExistsAndArchivedForId(bobId);
    assertTrue(verified);
    assertFalse(archived);
  }

  function test_archiveAndRestoreProfile() public {
    address alice = address(0xA11CE);
    uint256 aliceId = _mintProfile(alice);

    vm.prank(alice);
    profile.archiveProfile();

    (, bool archived,) = profile.profileStatusById(aliceId);
    assertTrue(archived);

    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(ProfileAccess.selector, aliceId, "Profile is archived"));
    profile.archiveProfile();

    vm.prank(alice);
    profile.restoreProfile();

    (, archived,) = profile.profileStatusById(aliceId);
    assertFalse(archived);

    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(ProfileAccess.selector, aliceId, "Profile is not archived"));
    profile.restoreProfile();

    address stranger = address(0xBAD);
    vm.prank(stranger);
    vm.expectRevert(abi.encodeWithSelector(ProfileNotFoundForAddress.selector, stranger));
    profile.archiveProfile();
  }

  function test_registerDeleteAndRestoreCompromisedAddresses() public {
    address alice = address(0xA11CE);
    address secondary = address(0xA22CE);
    address tertiary = address(0xA33CE);
    uint256 aliceId = _mintProfile(alice);

    _registerAddress(alice, secondary, aliceId, 11);
    _registerAddress(alice, tertiary, aliceId, 12);

    address[] memory addresses = profile.addressesForProfile(aliceId);
    assertEq(addresses.length, 3);
    assertTrue(profile.addressBelongsToProfile(secondary, aliceId));

    vm.prank(alice);
    profile.deleteAddressAtIndex(1, true);
    assertEq(profile.profileIdByAddress(secondary), 0);
    assertTrue(profile.isAddressCompromised(secondary));

    vm.prank(admin);
    profile.restoreCompromisedAddress(secondary);
    assertFalse(profile.isAddressCompromised(secondary));

    vm.prank(alice);
    profile.deleteAddress(tertiary, false);
    assertEq(profile.profileIdByAddress(tertiary), 0);

    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(AddressAuthorization.selector, alice, "Address == msg.sender"));
    profile.deleteAddressAtIndex(0, false);
  }

  function test_mockProfileCreationAndAttestationAssignment() public {
    address mockSubject = address(0xBEEF);
    bytes32 attestationHash = keccak256("profile-attestation");

    vm.prank(reviewCaller);
    uint256 mockAddressId = profile.incrementProfileCount(false, mockSubject, bytes32(0));

    (bool verified, bool archived, bool mock, uint256 profileId) = profile.profileStatusByAddress(mockSubject);
    assertFalse(verified);
    assertFalse(archived);
    assertTrue(mock);
    assertEq(profileId, mockAddressId);

    vm.prank(attestationCaller);
    uint256 mockAttestationId = profile.incrementProfileCount(true, address(0), attestationHash);
    assertEq(profile.profileIdByAttestation(attestationHash), mockAttestationId);

    address alice = address(0xA11CE);
    uint256 aliceId = _mintProfile(alice);

    vm.prank(attestationCaller);
    profile.assignExistingProfileToAttestation(attestationHash, aliceId);

    assertEq(profile.profileIdByAttestation(attestationHash), aliceId);
    assertEq(vouchHook.lastAttestationHash(), attestationHash);
    assertEq(vouchHook.lastProfileId(), aliceId);
    assertEq(vouchHook.callCount(), 1);

    (bool exists, bool isArchived) = profile.profileExistsAndArchivedForId(mockAddressId);
    assertFalse(exists);
    assertFalse(isArchived);
  }

  function test_profileAdminInviteAndAddressLimits() public {
    address alice = address(0xA11CE);
    address bob = address(0xB0B);
    address secondary = address(0xA22CE);
    address tertiary = address(0xA33CE);

    vm.prank(admin);
    profile.setDefaultNumberOfInvites(3);
    assertEq(profile.defaultNumberOfInvites(), 3);

    uint256 aliceId = _mintProfile(alice);
    uint256 bobId = _mintProfile(bob);
    assertEq(profile.inviteInfoForProfileId(aliceId).available, 3);

    vm.prank(admin);
    profile.addInvites(alice, 1);
    assertEq(profile.inviteInfoForProfileId(aliceId).available, 4);

    address[] memory users = new address[](2);
    users[0] = alice;
    users[1] = bob;
    vm.prank(admin);
    profile.addInvitesBatch(users, 1);
    assertEq(profile.inviteInfoForProfileId(aliceId).available, 5);
    assertEq(profile.inviteInfoForProfileId(bobId).available, 4);

    vm.prank(admin);
    profile.setMaxInvites(5);

    vm.prank(admin);
    vm.expectRevert(abi.encodeWithSelector(MaxInvitesReached.selector, aliceId));
    profile.addInvites(alice, 1);

    vm.prank(admin);
    vm.expectRevert(abi.encodeWithSelector(MaxInvitesReached.selector, 0));
    profile.setDefaultNumberOfInvites(2049);

    vm.prank(admin);
    vm.expectRevert(abi.encodeWithSelector(MaxInvitesReached.selector, 0));
    profile.setMaxInvites(2049);

    vm.prank(admin);
    profile.setMaxAddresses(2);

    _registerAddress(alice, secondary, aliceId, 21);

    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(MaxAddressesReached.selector, aliceId));
    profile.registerAddress(tertiary, aliceId, 22, _signatureForAddressRegistration(tertiary, aliceId, 22));

    vm.prank(admin);
    vm.expectRevert(abi.encodeWithSelector(MaxAddressesReached.selector, 0));
    profile.setMaxAddresses(2049);
  }

  function test_profileRevertsForInvalidInvitesAndUnauthorizedMocks() public {
    address alice = address(0xA11CE);
    uint256 aliceId = _mintProfile(alice);

    vm.prank(alice);
    vm.expectRevert(AddressNotInvited.selector);
    profile.createProfile(1);

    vm.prank(alice);
    profile.archiveProfile();

    vm.expectRevert(InvalidSender.selector);
    vm.prank(alice);
    profile.inviteAddress(address(0xCAFE));

    vm.prank(address(0xBAD));
    vm.expectRevert(InvalidSender.selector);
    profile.incrementProfileCount(false, address(0xBEEF), bytes32(0));

    vm.prank(address(0xBAD));
    vm.expectRevert(InvalidSender.selector);
    profile.assignExistingProfileToAttestation(keccak256("bad"), aliceId);
  }

  function test_profileInviteAndCreateAdditionalReverts() public {
    address alice = address(0xA11CE);
    address bob = address(0xB0B);
    address carol = address(0xCA20);
    address dave = address(0xDA40);
    uint256 aliceId = _mintProfile(alice);
    _mintProfile(bob);

    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(ProfileExistsForAddress.selector, bob));
    profile.inviteAddress(bob);

    vm.prank(owner);
    profile.inviteAddress(carol);

    vm.prank(owner);
    vm.expectRevert(AddressNotInvited.selector);
    profile.uninviteUser(dave);

    vm.prank(alice);
    profile.archiveProfile();

    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(ProfileAccess.selector, aliceId, "Profile is archived"));
    profile.uninviteUser(carol);

    vm.prank(owner);
    profile.inviteAddress(dave);

    vm.prank(dave);
    vm.expectRevert(InvalidSender.selector);
    profile.createProfile(999);
  }

  function test_profileRegisterAndDeleteAdditionalReverts() public {
    address alice = address(0xA11CE);
    address bob = address(0xB0B);
    address secondary = address(0xA22CE);
    address tertiary = address(0xA33CE);
    uint256 aliceId = _mintProfile(alice);
    _mintProfile(bob);

    vm.prank(bob);
    vm.expectRevert(abi.encodeWithSelector(ProfileNotFoundForAddress.selector, bob));
    profile.registerAddress(secondary, aliceId, 31, _signatureForAddressRegistration(secondary, aliceId, 31));

    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(ProfileExistsForAddress.selector, bob));
    profile.registerAddress(bob, aliceId, 32, _signatureForAddressRegistration(bob, aliceId, 32));

    vm.prank(alice);
    vm.expectRevert(InvalidIndex.selector);
    profile.deleteAddressAtIndex(99, false);

    address stranger = address(0xBAD);
    vm.prank(stranger);
    vm.expectRevert(abi.encodeWithSelector(ProfileNotFoundForAddress.selector, stranger));
    profile.deleteAddressAtIndex(0, false);

    vm.prank(alice);
    profile.archiveProfile();

    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(ProfileAccess.selector, aliceId, "Profile is archived"));
    profile.registerAddress(tertiary, aliceId, 33, _signatureForAddressRegistration(tertiary, aliceId, 33));

    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(ProfileAccess.selector, aliceId, "Profile is archived"));
    profile.deleteAddressAtIndex(0, false);
  }

  function test_profileCompromisedAddressBlocksCreateInviteAndRegister() public {
    address alice = address(0xA11CE);
    address compromised = address(0xA22CE);
    address target = address(0xCAFE);
    uint256 aliceId = _mintProfile(alice);
    _registerAddress(alice, compromised, aliceId, 41);

    vm.prank(alice);
    profile.deleteAddress(compromised, true);

    vm.prank(compromised);
    vm.expectRevert(abi.encodeWithSelector(AddressCompromised.selector, compromised));
    profile.createProfile(1);

    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(AddressCompromised.selector, compromised));
    profile.inviteAddress(compromised);

    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(AddressCompromised.selector, compromised));
    profile.registerAddress(compromised, aliceId, 42, _signatureForAddressRegistration(compromised, aliceId, 42));

    vm.prank(admin);
    profile.addInvites(alice, 1);

    vm.prank(alice);
    profile.inviteAddress(target);
    vm.prank(target);
    profile.createProfile(aliceId);
  }

  function test_profileUpgradeAuthorizedByOwner() public {
    EthosProfile nextImpl = new EthosProfile();

    vm.prank(owner);
    profile.upgradeToAndCall(address(nextImpl), "");

    assertEq(profile.profileCount(), 2);

    EthosProfile unauthorizedImpl = new EthosProfile();
    vm.expectRevert();
    vm.prank(address(0xBAD));
    profile.upgradeToAndCall(address(unauthorizedImpl), "");
  }

  function test_profileGettersRevertForMissingProfileOrAddress() public {
    vm.expectRevert(abi.encodeWithSelector(ProfileNotFound.selector, 0));
    profile.getProfile(0);

    address stranger = address(0xBAD);
    vm.expectRevert(abi.encodeWithSelector(ProfileNotFoundForAddress.selector, stranger));
    profile.addressBelongsToProfile(stranger, 1);

    vm.expectRevert(abi.encodeWithSelector(ProfileNotFoundForAddress.selector, stranger));
    profile.verifiedProfileIdForAddress(stranger);
  }

  function _mintProfile(address user) internal returns (uint256 profileId) {
    vm.prank(owner);
    profile.inviteAddress(user);
    vm.prank(user);
    profile.createProfile(1);
    profileId = profile.verifiedProfileIdForAddress(user);
  }

  function _registerAddress(address profileOwner, address newAddr, uint256 profileId, uint256 randValue) internal {
    bytes memory signature = _signatureForAddressRegistration(newAddr, profileId, randValue);
    vm.prank(profileOwner);
    profile.registerAddress(newAddr, profileId, randValue, signature);
  }

  function _signatureForAddressRegistration(address newAddr, uint256 profileId, uint256 randValue)
    internal
    view
    returns (bytes memory)
  {
    bytes32 messageHash = keccak256(abi.encodePacked(newAddr, profileId, randValue));
    bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, ethSignedHash);
    return abi.encodePacked(r, s, v);
  }
}
