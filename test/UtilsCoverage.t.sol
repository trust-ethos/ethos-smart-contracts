// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Test} from "forge-std/Test.sol";

import {IPausable} from "../src/interfaces/IPausable.sol";
import {IEthosProfile} from "../src/interfaces/IEthosProfile.sol";
import {Common} from "../src/legacy/Common.sol";
import {EthosVouch} from "../src/legacy/EthosVouch.sol";
import {ProfileNotFoundForAddress} from "../src/legacy/errors/ProfileErrors.sol";
import {SignatureVerifier} from "../src/legacy/SignatureVerifier.sol";
import {AccessControl} from "../src/utils/AccessControl.sol";
import {ContractAddressManager} from "../src/utils/ContractAddressManager.sol";
import {ETHOS_INTERACTION_CONTROL, ETHOS_PROFILE, SLASHER} from "../src/utils/Constants.sol";
import {InteractionControl} from "../src/utils/InteractionControl.sol";
import {SignatureControl} from "../src/utils/SignatureControl.sol";

contract MockPausable is IPausable {
  bool private _paused;
  uint256 public pauseCalls;
  uint256 public unpauseCalls;

  function paused() external view returns (bool) {
    return _paused;
  }

  function pause() external {
    _paused = true;
    pauseCalls++;
  }

  function unpause() external {
    _paused = false;
    unpauseCalls++;
  }
}

contract LegacyAccessControlHarness is AccessControl {
  function initialize(
    address owner,
    address admin,
    address expectedSigner_,
    address signatureVerifier_,
    address contractAddressManager_
  ) external initializer {
    __accessControl_init(owner, admin, expectedSigner_, signatureVerifier_, contractAddressManager_);
  }

  function ownerOnlyPing() external view onlyOwner returns (uint256) {
    return 1;
  }
}

contract CommonHarness is Common {
  function correctLength(uint256 arrayLength, uint256 maxLength, uint256 fromIdx) external pure returns (uint256) {
    return _correctLength(arrayLength, maxLength, fromIdx);
  }
}

contract MockLegacyProfile is IEthosProfile {
  uint256 internal _nextProfileId = 1;

  mapping(uint256 profileId => Profile profile) internal _profiles;
  mapping(address user => uint256 profileId) public profileIdByAddress;
  mapping(bytes32 attestationHash => uint256 profileId) public profileIdByAttestation;
  mapping(uint256 profile => mapping(address invitee => uint256 invitedAt)) public sentAt;

  function mintProfile(address user) external returns (uint256 profileId) {
    uint256 existingId = profileIdByAddress[user];
    if (existingId != 0) {
      profileId = existingId;
    } else {
      profileId = _nextProfileId++;
      profileIdByAddress[user] = profileId;
    }

    Profile storage profile = _profiles[profileId];
    if (profile.profileId == 0) {
      profile.profileId = profileId;
      profile.createdAt = block.timestamp == 0 ? 1 : block.timestamp;
      profile.addresses.push(user);
    }
  }

  function mintMockAddress(address user) external returns (uint256 profileId) {
    profileId = _nextProfileId++;
    profileIdByAddress[user] = profileId;
  }

  function mintMockAttestation(bytes32 attestationHash) external returns (uint256 profileId) {
    profileId = _nextProfileId++;
    profileIdByAttestation[attestationHash] = profileId;
  }

  function setArchived(uint256 profileId, bool archived) external {
    _profiles[profileId].archived = archived;
  }

  function profileExistsAndArchivedForId(uint256 profileId) external view returns (bool exists, bool archived) {
    (bool verified, bool isArchived, bool mock) = profileStatusById(profileId);
    exists = verified && !mock;
    archived = isArchived && !mock;
  }

  function addressBelongsToProfile(address user, uint256 profileId) external view returns (bool) {
    return profileIdByAddress[user] == profileId;
  }

  function verifiedProfileIdForAddress(address user) external view returns (uint256 profileId) {
    (bool verified, bool archived, bool mock, uint256 id) = profileStatusByAddress(user);
    if (!verified || archived || mock) revert ProfileNotFoundForAddress(user);
    return id;
  }

  function profileStatusById(uint256 profileId) public view returns (bool verified, bool archived, bool mock) {
    Profile storage profile = _profiles[profileId];
    verified = profile.profileId > 0;
    archived = verified && profile.archived;
    mock = profileId > 0 && !verified && profileId < _nextProfileId;
  }

  function profileStatusByAddress(address user)
    public
    view
    returns (bool verified, bool archived, bool mock, uint256 profileId)
  {
    profileId = profileIdByAddress[user];
    (verified, archived, mock) = profileStatusById(profileId);
  }

  function incrementProfileCount(bool isAttestation, address subject, bytes32 attestation)
    external
    returns (uint256 profileId)
  {
    if (isAttestation) {
      return this.mintMockAttestation(attestation);
    }
    return this.mintMockAddress(subject);
  }

  function assignExistingProfileToAttestation(bytes32 attestation, uint256 profileId) external {
    profileIdByAttestation[attestation] = profileId;
  }

  function getProfile(uint256 profileId) external view returns (Profile memory profile) {
    return _profiles[profileId];
  }

  function addressesForProfile(uint256 profileId) external view returns (address[] memory) {
    return _profiles[profileId].addresses;
  }
}

contract UtilsCoverageTest is Test {
  address internal owner = address(0xA11CE);
  address internal admin = address(0xAD1);
  address internal signer = address(0x5151);
  address internal slasher = address(0x51A5);
  address internal protocolFee = address(0xFEE);

  ContractAddressManager internal cam;
  SignatureVerifier internal verifier;

  function setUp() public {
    cam = new ContractAddressManager();
    verifier = new SignatureVerifier();
  }

  function test_contractAddressManager_updatesRotatesAndChecksEthosFlags() public {
    address first = address(0xF111);
    address second = address(0xF222);

    address[] memory addrs = new address[](1);
    string[] memory names = new string[](1);
    addrs[0] = first;
    names[0] = "TARGET";
    cam.updateContractAddressesForNames(addrs, names);

    assertEq(cam.getContractAddressForName("TARGET"), first);
    assertTrue(cam.checkIsEthosContract(first));

    addrs[0] = second;
    cam.updateContractAddressesForNames(addrs, names);

    assertEq(cam.getContractAddressForName("TARGET"), second);
    assertFalse(cam.checkIsEthosContract(first));
    assertTrue(cam.checkIsEthosContract(second));
  }

  function test_contractAddressManager_revertsOnLengthMismatch() public {
    address[] memory addrs = new address[](1);
    string[] memory names = new string[](2);

    vm.expectRevert(ContractAddressManager.InvalidInputLength.selector);
    cam.updateContractAddressesForNames(addrs, names);
  }

  function test_commonCorrectLengthBoundaries() public {
    CommonHarness common = new CommonHarness();

    assertEq(common.correctLength(0, 5, 0), 0);
    assertEq(common.correctLength(5, 0, 0), 0);
    assertEq(common.correctLength(5, 2, 5), 0);
    assertEq(common.correctLength(5, 2, 1), 2);
    assertEq(common.correctLength(5, 10, 3), 2);
  }

  function test_interactionControl_listUpdateRemovePauseAndUnpauseAll() public {
    InteractionControl ic = new InteractionControl(address(this), address(cam));
    MockPausable first = new MockPausable();
    MockPausable second = new MockPausable();

    address[] memory addrs = new address[](2);
    string[] memory names = new string[](2);
    addrs[0] = address(first);
    addrs[1] = address(second);
    names[0] = "FIRST";
    names[1] = "SECOND";
    cam.updateContractAddressesForNames(addrs, names);

    ic.addControlledContractNames(names);
    string[] memory controlled = ic.getControlledContractNames();
    assertEq(controlled.length, 2);
    assertEq(controlled[0], "FIRST");
    assertEq(controlled[1], "SECOND");

    ic.pauseAll();
    assertTrue(first.paused());
    assertTrue(second.paused());
    assertEq(first.pauseCalls(), 1);

    ic.pauseAll();
    assertEq(first.pauseCalls(), 1);

    ic.unpauseAll();
    assertFalse(first.paused());
    assertFalse(second.paused());
    assertEq(first.unpauseCalls(), 1);

    ic.unpauseAll();
    assertEq(first.unpauseCalls(), 1);

    ic.removeControlledContractName("FIRST");
    controlled = ic.getControlledContractNames();
    assertEq(controlled.length, 1);
    assertEq(controlled[0], "SECOND");

    ic.updateContractAddressManager(address(0xCAFE));
    assertEq(ic.contractAddressManager(), address(0xCAFE));
  }

  function test_interactionControl_pauseAndUnpauseSpecificContract() public {
    InteractionControl ic = new InteractionControl(address(this), address(cam));
    MockPausable target = new MockPausable();

    address[] memory addrs = new address[](1);
    string[] memory names = new string[](1);
    addrs[0] = address(target);
    names[0] = "TARGET";
    cam.updateContractAddressesForNames(addrs, names);

    ic.pauseContract("TARGET");
    assertTrue(target.paused());

    ic.unpauseContract("TARGET");
    assertFalse(target.paused());
  }

  function test_interactionControl_revertsForNonOwner() public {
    InteractionControl ic = new InteractionControl(address(this), address(cam));
    string[] memory names = new string[](1);
    names[0] = "TARGET";

    vm.startPrank(address(0xBAD));
    vm.expectRevert();
    ic.addControlledContractNames(names);
    vm.expectRevert();
    ic.pauseAll();
    vm.stopPrank();
  }

  function test_legacyAccessControl_ownerAdminAndPausePaths() public {
    LegacyAccessControlHarness access = _deployLegacyAccessControl();
    address nextOwner = address(0x0A0A);
    address extraAdmin = address(0x0B0B);
    ContractAddressManager nextCam = new ContractAddressManager();
    SignatureVerifier nextVerifier = new SignatureVerifier();

    vm.prank(owner);
    assertEq(access.ownerOnlyPing(), 1);

    vm.prank(owner);
    access.updateOwner(nextOwner);
    assertTrue(access.hasRole(access.OWNER_ROLE(), nextOwner));
    assertFalse(access.hasRole(access.OWNER_ROLE(), owner));

    vm.prank(nextOwner);
    access.addAdmin(extraAdmin);
    assertTrue(access.hasRole(access.ADMIN_ROLE(), extraAdmin));

    vm.prank(nextOwner);
    access.removeAdmin(extraAdmin);
    assertFalse(access.hasRole(access.ADMIN_ROLE(), extraAdmin));

    vm.prank(admin);
    access.updateContractAddressManager(address(nextCam));
    assertEq(address(access.contractAddressManager()), address(nextCam));

    vm.prank(admin);
    access.updateSignatureVerifier(address(nextVerifier));
    assertEq(access.signatureVerifier(), address(nextVerifier));
  }

  function test_legacyAccessControl_pauseUnpauseAndUnauthorizedInteractionControl() public {
    LegacyAccessControlHarness access = _deployLegacyAccessControl();
    InteractionControl ic = new InteractionControl(address(this), address(cam));

    address[] memory addrs = new address[](1);
    string[] memory names = new string[](1);
    addrs[0] = address(ic);
    names[0] = ETHOS_INTERACTION_CONTROL;
    cam.updateContractAddressesForNames(addrs, names);

    vm.expectRevert(
      abi.encodeWithSelector(
        IAccessControl.AccessControlUnauthorizedAccount.selector, address(this), keccak256("ETHOS_INTERACTION_CONTROL")
      )
    );
    access.pause();

    addrs[0] = address(access);
    names[0] = "ACCESS";
    cam.updateContractAddressesForNames(addrs, names);
    ic.pauseContract("ACCESS");
    assertTrue(access.paused());

    ic.unpauseContract("ACCESS");
    assertFalse(access.paused());
  }

  function test_legacyAccessControl_initializeRejectsZeroCoreAddresses() public {
    LegacyAccessControlHarness access = LegacyAccessControlHarness(
      address(new ERC1967Proxy(address(_deployLegacyAccessControlImplementationOnly()), ""))
    );

    vm.expectRevert(SignatureControl.ZeroAddress.selector);
    access.initialize(address(0), admin, signer, address(verifier), address(cam));
  }

  function test_legacyVouch_initializeSetsDefaultsAndRejectsZeroFeeRecipient() public {
    EthosVouch vouch = _deployLegacyVouch();

    assertEq(vouch.protocolFeeAddress(), address(0xFEE));
    assertEq(vouch.entryProtocolFeeBasisPoints(), 100);
    assertEq(vouch.entryDonationFeeBasisPoints(), 200);
    assertEq(vouch.entryVouchersPoolFeeBasisPoints(), 300);
    assertEq(vouch.exitFeeBasisPoints(), 100);
    assertEq(vouch.configuredMinimumVouchAmount(), 0.0001 ether);
    assertEq(vouch.maximumVouches(), 256);
    assertEq(vouch.unhealthyResponsePeriod(), 24 hours);

    EthosVouch proxy = EthosVouch(address(new ERC1967Proxy(address(new EthosVouch()), "")));
    vm.expectRevert(EthosVouch.InvalidFeeProtocolAddress.selector);
    proxy.initialize(owner, admin, signer, address(verifier), address(cam), address(0), 0, 0, 0, 0);
  }

  function test_legacyVouch_adminSettersAndFeeCap() public {
    EthosVouch vouch = _deployLegacyVouch();

    vm.startPrank(admin);
    vouch.setEntryProtocolFeeBasisPoints(150);
    vouch.setEntryDonationFeeBasisPoints(250);
    vouch.setEntryVouchersPoolFeeBasisPoints(350);
    vouch.setExitFeeBasisPoints(200);
    vouch.setMinimumVouchAmount(0.0002 ether);
    vouch.updateMaximumVouches(128);
    vouch.updateUnhealthyResponsePeriod(2 days);
    vm.stopPrank();

    assertEq(vouch.entryProtocolFeeBasisPoints(), 150);
    assertEq(vouch.entryDonationFeeBasisPoints(), 250);
    assertEq(vouch.entryVouchersPoolFeeBasisPoints(), 350);
    assertEq(vouch.exitFeeBasisPoints(), 200);
    assertEq(vouch.configuredMinimumVouchAmount(), 0.0002 ether);
    assertEq(vouch.maximumVouches(), 128);
    assertEq(vouch.unhealthyResponsePeriod(), 2 days);

    vm.prank(admin);
    vm.expectRevert(
      abi.encodeWithSelector(EthosVouch.MaximumVouchesExceeded.selector, 257, "Maximum vouches cannot exceed 256")
    );
    vouch.updateMaximumVouches(257);

    vm.prank(admin);
    vm.expectRevert(abi.encodeWithSelector(EthosVouch.MinimumVouchAmount.selector, 0.0001 ether));
    vouch.setMinimumVouchAmount(0.0001 ether - 1);

    vm.prank(admin);
    vm.expectRevert(abi.encodeWithSelector(EthosVouch.FeesExceedMaximum.selector, 1050, 1000));
    vouch.setExitFeeBasisPoints(300);
  }

  function test_legacyVouch_ownerSetterUpgradeAndPauseGating() public {
    EthosVouch vouch = _deployLegacyVouch();
    InteractionControl ic = new InteractionControl(address(this), address(cam));

    address[] memory addrs = new address[](2);
    string[] memory names = new string[](2);
    addrs[0] = address(ic);
    addrs[1] = address(vouch);
    names[0] = ETHOS_INTERACTION_CONTROL;
    names[1] = "LEGACY_VOUCH";
    cam.updateContractAddressesForNames(addrs, names);

    vm.prank(owner);
    vouch.setProtocolFeeAddress(address(0xFEE2));
    assertEq(vouch.protocolFeeAddress(), address(0xFEE2));

    vm.prank(owner);
    vm.expectRevert(EthosVouch.InvalidFeeProtocolAddress.selector);
    vouch.setProtocolFeeAddress(address(0));

    EthosVouch newImpl = new EthosVouch();
    vm.prank(owner);
    vouch.upgradeToAndCall(address(newImpl), "");
    assertEq(vouch.protocolFeeAddress(), address(0xFEE2));

    ic.pauseContract("LEGACY_VOUCH");
    assertTrue(vouch.paused());

    vm.prank(admin);
    vm.expectRevert();
    vouch.setMinimumVouchAmount(0.0002 ether);

    ic.unpauseContract("LEGACY_VOUCH");
    assertFalse(vouch.paused());
  }

  function test_legacyVouch_emptyViewsAndMissingVouchValidation() public {
    EthosVouch vouch = _deployLegacyVouch();

    (bool exists, bool allowed) = vouch.targetExistsAndAllowedForId(1);
    assertFalse(exists);
    assertFalse(allowed);
    assertFalse(vouch.vouchExistsFor(1, 2));

    vm.expectRevert(abi.encodeWithSelector(EthosVouch.NotAuthorForVouch.selector, 0, 1));
    vouch.verifiedVouchByAuthorForSubjectProfileId(1, 2);
  }

  function test_legacyVouch_profileVouchIncreaseClaimUnvouchAndMarkUnhealthy() public {
    vm.warp(100);
    (EthosVouch vouch, MockLegacyProfile profile) = _deployLegacyVouchWithProfile();
    address alice = address(0xA100);
    address bob = address(0xB0B0);
    uint256 aliceId = _mintVerifiedProfile(profile, alice);
    uint256 bobId = _mintVerifiedProfile(profile, bob);

    vm.prank(alice);
    vouch.vouchByProfileId{value: 1 ether}(bobId, "solid", "profile");

    assertEq(vouch.vouchCount(), 1);
    assertTrue(vouch.vouchExistsFor(aliceId, bobId));
    (bool exists, bool allowed) = vouch.targetExistsAndAllowedForId(0);
    assertTrue(exists);
    assertTrue(allowed);

    EthosVouch.Vouch memory first = vouch.verifiedVouchByAuthorForSubjectProfileId(aliceId, bobId);
    assertEq(first.authorProfileId, aliceId);
    assertEq(first.subjectProfileId, bobId);
    assertGt(first.balance, vouch.configuredMinimumVouchAmount());

    vm.prank(alice);
    vouch.increaseVouch{value: 0.5 ether}(0, bytes32(0), address(0));

    EthosVouch.Vouch memory increased = vouch.verifiedVouchByAuthorForSubjectProfileId(aliceId, bobId);
    assertGt(increased.balance, first.balance);

    uint256 reward = vouch.rewardsByProfileId(bobId);
    assertGt(reward, 0);
    uint256 bobBalanceBefore = bob.balance;

    vm.prank(bob);
    vouch.claimRewards();

    assertEq(vouch.rewardsByProfileId(bobId), 0);
    assertEq(bob.balance, bobBalanceBefore + reward);

    vm.prank(alice);
    vouch.unvouch(0);

    assertFalse(vouch.vouchExistsFor(aliceId, bobId));
    vm.prank(alice);
    vouch.markUnhealthy(0);

    EthosVouch.Vouch memory archived = vouch.verifiedVouchByAuthorForSubjectProfileId(aliceId, bobId);
    assertTrue(archived.archived);
    assertTrue(archived.unhealthy);
    assertEq(archived.balance, 0);
  }

  function test_legacyVouch_unvouchMaintainsAuthorAndSubjectIndexesAfterSwapRemoval() public {
    vm.warp(100);
    (EthosVouch vouch, MockLegacyProfile profile) = _deployLegacyVouchWithProfile();
    address alice = address(0xA100);
    address bob = address(0xB0B0);
    address carol = address(0xCA20);
    address dave = address(0xDA40);
    uint256 aliceId = _mintVerifiedProfile(profile, alice);
    uint256 bobId = _mintVerifiedProfile(profile, bob);
    uint256 carolId = _mintVerifiedProfile(profile, carol);
    uint256 daveId = _mintVerifiedProfile(profile, dave);

    vm.prank(alice);
    vouch.vouchByProfileId{value: 1 ether}(bobId, "first", "");
    vm.prank(alice);
    vouch.vouchByProfileId{value: 1 ether}(carolId, "second", "");
    vm.prank(dave);
    vouch.vouchByProfileId{value: 1 ether}(bobId, "third", "");

    vm.prank(alice);
    vouch.unvouch(0);

    assertEq(vouch.vouchIdsByAuthor(aliceId, 0), 1);
    assertEq(vouch.vouchIdsByAuthorIndex(aliceId, 1), 0);
    assertEq(vouch.vouchIdsForSubjectProfileId(bobId, 0), 2);
    assertEq(vouch.vouchIdsForSubjectProfileIdIndex(bobId, 2), 0);
    assertTrue(vouch.vouchExistsFor(daveId, bobId));
  }

  function test_legacyVouch_mockAddressVouchRewardsBecomeClaimableAfterAddressVerifies() public {
    vm.warp(100);
    (EthosVouch vouch, MockLegacyProfile profile) = _deployLegacyVouchWithProfile();
    address alice = address(0xA100);
    address mockSubject = address(0xBEEF);
    _mintVerifiedProfile(profile, alice);
    profile.mintMockAddress(mockSubject);

    vm.prank(alice);
    vouch.vouchByAddress{value: 1 ether}(mockSubject, "mock address", "");

    uint256 reward = vouch.rewardsByAddress(mockSubject);
    assertGt(reward, 0);

    profile.mintProfile(mockSubject);
    uint256 subjectBalanceBefore = mockSubject.balance;

    vm.prank(mockSubject);
    vouch.claimRewards();

    assertEq(vouch.rewardsByAddress(mockSubject), 0);
    assertEq(mockSubject.balance, subjectBalanceBefore + reward);
  }

  function test_legacyVouch_attestationClaimMovesVouchAndRewardsCanBeClaimedByAttestation() public {
    vm.warp(100);
    (EthosVouch vouch, MockLegacyProfile profile) = _deployLegacyVouchWithProfile();
    address alice = address(0xA100);
    address subject = address(0x5150);
    uint256 aliceId = _mintVerifiedProfile(profile, alice);
    bytes32 attestationHash = keccak256("attestation");
    profile.mintMockAttestation(attestationHash);

    vm.prank(alice);
    vouch.vouchByAttestation{value: 1 ether}(attestationHash, "mock attestation", "");

    assertEq(vouch.vouchAttestationHash(0), attestationHash);
    uint256 reward = vouch.rewardsByAttestationHash(attestationHash);
    assertGt(reward, 0);

    uint256 subjectId = _mintVerifiedProfile(profile, subject);

    vm.prank(address(profile));
    vouch.handleAttestationClaim(attestationHash, subjectId);
    profile.assignExistingProfileToAttestation(attestationHash, subjectId);

    EthosVouch.Vouch memory moved = vouch.verifiedVouchByAuthorForSubjectProfileId(aliceId, subjectId);
    assertEq(moved.subjectProfileId, subjectId);
    assertEq(vouch.vouchAttestationHash(0), bytes32(0));

    uint256 subjectBalanceBefore = subject.balance;
    vm.prank(subject);
    vouch.claimRewardsByAttestation(attestationHash);

    assertEq(vouch.rewardsByAttestationHash(attestationHash), 0);
    assertEq(subject.balance, subjectBalanceBefore + reward);
  }

  function test_legacyVouch_freezeSlashUnfreezeAndSlasherGuards() public {
    vm.warp(100);
    (EthosVouch vouch, MockLegacyProfile profile) = _deployLegacyVouchWithProfile();
    address alice = address(0xA100);
    address bob = address(0xB0B0);
    uint256 aliceId = _mintVerifiedProfile(profile, alice);
    uint256 bobId = _mintVerifiedProfile(profile, bob);

    vm.prank(alice);
    vouch.vouchByProfileId{value: 1 ether}(bobId, "slashable", "");
    EthosVouch.Vouch memory beforeSlash = vouch.verifiedVouchByAuthorForSubjectProfileId(aliceId, bobId);

    vm.prank(address(0xBAD));
    vm.expectRevert(EthosVouch.NotSlasher.selector);
    vouch.freeze(aliceId);

    vm.prank(slasher);
    vouch.freeze(aliceId);
    assertTrue(vouch.frozenAuthors(aliceId));

    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(EthosVouch.PendingSlash.selector, 0, aliceId));
    vouch.unvouch(0);

    vm.prank(slasher);
    vm.expectRevert(EthosVouch.InvalidSlashPercentage.selector);
    vouch.slash(aliceId, 1001);

    uint256 protocolBefore = protocolFee.balance;
    vm.prank(slasher);
    uint256 slashed = vouch.slash(aliceId, 500);

    assertGt(slashed, 0);
    assertEq(protocolFee.balance, protocolBefore + slashed);
    EthosVouch.Vouch memory afterSlash = vouch.verifiedVouchByAuthorForSubjectProfileId(aliceId, bobId);
    assertLt(afterSlash.balance, beforeSlash.balance);

    vm.prank(slasher);
    vouch.unfreeze(aliceId);
    assertFalse(vouch.frozenAuthors(aliceId));
  }

  function test_legacyVouch_vouchValidationReverts() public {
    vm.warp(100);
    (EthosVouch vouch, MockLegacyProfile profile) = _deployLegacyVouchWithProfile();
    address alice = address(0xA100);
    address bob = address(0xB0B0);
    uint256 aliceId = _mintVerifiedProfile(profile, alice);
    uint256 bobId = _mintVerifiedProfile(profile, bob);

    profile.setArchived(bobId, true);
    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(EthosVouch.InvalidEthosProfileForVouch.selector, bobId));
    vouch.vouchByProfileId{value: 1 ether}(bobId, "archived", "");
    profile.setArchived(bobId, false);

    uint256 minimum = vouch.configuredMinimumVouchAmount();
    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(EthosVouch.MinimumVouchAmount.selector, minimum));
    vouch.vouchByProfileId{value: 1 wei}(bobId, "small", "");

    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(EthosVouch.SelfVouch.selector, aliceId, aliceId));
    vouch.vouchByProfileId{value: 1 ether}(aliceId, "self", "");

    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(EthosVouch.InvalidEthosProfileForVouch.selector, 0));
    vouch.vouchByProfileId{value: 1 ether}(0, "missing", "");

    vm.prank(alice);
    vouch.vouchByProfileId{value: 1 ether}(bobId, "first", "");

    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(EthosVouch.AlreadyVouched.selector, aliceId, bobId));
    vouch.vouchByProfileId{value: 1 ether}(bobId, "duplicate", "");
  }

  function test_legacyVouch_rewardClaimReverts() public {
    vm.warp(100);
    (EthosVouch vouch, MockLegacyProfile profile) = _deployLegacyVouchWithProfile();
    address alice = address(0xA100);
    _mintVerifiedProfile(profile, alice);
    bytes32 attestationHash = keccak256("attestation");

    vm.prank(address(0xBAD));
    vm.expectRevert(abi.encodeWithSelector(ProfileNotFoundForAddress.selector, address(0xBAD)));
    vouch.claimRewards();

    vm.prank(alice);
    vm.expectRevert(EthosVouch.InsufficientRewardsBalance.selector);
    vouch.claimRewards();

    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(EthosVouch.InvalidAttestationHash.selector, attestationHash));
    vouch.claimRewardsByAttestation(attestationHash);
  }

  function test_legacyVouch_verifiedAddressAndAttestationRoutesUseProfileVouchPath() public {
    vm.warp(100);
    (EthosVouch vouch, MockLegacyProfile profile) = _deployLegacyVouchWithProfile();
    address alice = address(0xA100);
    address carol = address(0xCA20);
    address bob = address(0xB0B0);
    uint256 aliceId = _mintVerifiedProfile(profile, alice);
    uint256 carolId = _mintVerifiedProfile(profile, carol);
    uint256 bobId = _mintVerifiedProfile(profile, bob);
    bytes32 attestationHash = keccak256("verified-attestation");
    profile.assignExistingProfileToAttestation(attestationHash, bobId);

    vm.prank(alice);
    vouch.vouchByAddress{value: 1 ether}(bob, "verified address", "");

    vm.prank(carol);
    vouch.vouchByAttestation{value: 1 ether}(attestationHash, "verified attestation", "");

    assertTrue(vouch.vouchExistsFor(aliceId, bobId));
    assertTrue(vouch.vouchExistsFor(carolId, bobId));
  }

  function test_legacyVouch_unvouchUnhealthyAndVerifiedSubjectAddressView() public {
    vm.warp(100);
    (EthosVouch vouch, MockLegacyProfile profile) = _deployLegacyVouchWithProfile();
    address alice = address(0xA100);
    address bob = address(0xB0B0);
    address carol = address(0xCA20);
    uint256 aliceId = _mintVerifiedProfile(profile, alice);
    uint256 bobId = _mintVerifiedProfile(profile, bob);
    uint256 carolId = _mintVerifiedProfile(profile, carol);

    vm.prank(alice);
    vouch.vouchByProfileId{value: 1 ether}(bobId, "unhealthy", "");

    vm.prank(carol);
    vouch.vouchByProfileId{value: 1 ether}(bobId, "active", "");

    EthosVouch.Vouch memory active = vouch.verifiedVouchByAuthorForSubjectAddress(carolId, bob);
    assertEq(active.authorProfileId, carolId);
    assertEq(active.subjectProfileId, bobId);

    vm.prank(alice);
    vouch.unvouchUnhealthy(0);

    EthosVouch.Vouch memory unhealthy = vouch.verifiedVouchByAuthorForSubjectProfileId(aliceId, bobId);
    assertTrue(unhealthy.archived);
    assertTrue(unhealthy.unhealthy);
  }

  function test_legacyVouch_mockIncreaseValidationRevertsForMissingOrMismatchedSubject() public {
    vm.warp(100);
    (EthosVouch vouch, MockLegacyProfile profile) = _deployLegacyVouchWithProfile();
    address alice = address(0xA100);
    address mockSubject = address(0xBEEF);
    address otherMockSubject = address(0xBEEF1);
    bytes32 otherAttestation = keccak256("other-attestation");
    _mintVerifiedProfile(profile, alice);
    uint256 mockId = profile.mintMockAddress(mockSubject);
    uint256 otherMockId = profile.mintMockAddress(otherMockSubject);
    uint256 otherAttestationId = profile.mintMockAttestation(otherAttestation);

    vm.prank(alice);
    vouch.vouchByAddress{value: 1 ether}(mockSubject, "mock", "");

    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(EthosVouch.InvalidEthosProfileForVouch.selector, mockId));
    vouch.increaseVouch{value: 1 ether}(0, bytes32(0), address(0));

    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(EthosVouch.InvalidEthosProfileForVouch.selector, otherAttestationId));
    vouch.increaseVouch{value: 1 ether}(0, otherAttestation, address(0));

    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(EthosVouch.InvalidEthosProfileForVouch.selector, otherMockId));
    vouch.increaseVouch{value: 1 ether}(0, bytes32(0), otherMockSubject);
  }

  function test_legacyVouch_authorAndSubjectMaximumReverts() public {
    vm.warp(100);
    (EthosVouch vouch, MockLegacyProfile profile) = _deployLegacyVouchWithProfile();
    address alice = address(0xA100);
    address bob = address(0xB0B0);
    address carol = address(0xCA20);
    address dave = address(0xDA40);
    uint256 bobId = _mintVerifiedProfile(profile, bob);
    uint256 carolId = _mintVerifiedProfile(profile, carol);
    _mintVerifiedProfile(profile, alice);
    _mintVerifiedProfile(profile, dave);

    vm.prank(admin);
    vouch.updateMaximumVouches(1);

    vm.prank(alice);
    vouch.vouchByProfileId{value: 1 ether}(bobId, "first", "");

    vm.prank(alice);
    vm.expectRevert();
    vouch.vouchByProfileId{value: 1 ether}(carolId, "author max", "");

    vm.prank(dave);
    vm.expectRevert();
    vouch.vouchByProfileId{value: 1 ether}(bobId, "subject max", "");
  }

  function test_legacyVouch_invalidAddressAttestationAndMockProfileRoutesRevert() public {
    vm.warp(100);
    (EthosVouch vouch, MockLegacyProfile profile) = _deployLegacyVouchWithProfile();
    address alice = address(0xA100);
    address bob = address(0xB0B0);
    _mintVerifiedProfile(profile, alice);
    uint256 bobId = _mintVerifiedProfile(profile, bob);
    uint256 mockId = profile.mintMockAddress(address(0xBEEF));
    bytes32 attestationHash = keccak256("archived-attestation");
    profile.assignExistingProfileToAttestation(attestationHash, bobId);

    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(EthosVouch.InvalidEthosProfileForVouch.selector, 0));
    vouch.vouchByAddress{value: 1 ether}(address(0xF00D), "unknown address", "");

    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(EthosVouch.InvalidEthosProfileForVouch.selector, 0));
    vouch.vouchByAttestation{value: 1 ether}(keccak256("unknown"), "unknown attestation", "");

    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(EthosVouch.InvalidEthosProfileForVouch.selector, mockId));
    vouch.vouchByProfileId{value: 1 ether}(mockId, "mock profile", "");

    profile.setArchived(bobId, true);

    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(EthosVouch.InvalidEthosProfileForVouch.selector, bobId));
    vouch.vouchByAddress{value: 1 ether}(bob, "archived address", "");

    vm.prank(alice);
    vm.expectRevert(abi.encodeWithSelector(EthosVouch.InvalidEthosProfileForVouch.selector, bobId));
    vouch.vouchByAttestation{value: 1 ether}(attestationHash, "archived attestation", "");
  }

  function _deployLegacyAccessControl() internal returns (LegacyAccessControlHarness access) {
    access = LegacyAccessControlHarness(
      address(new ERC1967Proxy(address(_deployLegacyAccessControlImplementationOnly()), ""))
    );
    access.initialize(owner, admin, signer, address(verifier), address(cam));
  }

  function _deployLegacyAccessControlImplementationOnly() internal returns (LegacyAccessControlHarness) {
    return new LegacyAccessControlHarness();
  }

  function _deployLegacyVouch() internal returns (EthosVouch vouch) {
    vouch = EthosVouch(address(new ERC1967Proxy(address(new EthosVouch()), "")));
    vouch.initialize(owner, admin, signer, address(verifier), address(cam), protocolFee, 100, 200, 300, 100);
  }

  function _deployLegacyVouchWithProfile() internal returns (EthosVouch vouch, MockLegacyProfile profile) {
    vouch = _deployLegacyVouch();
    profile = new MockLegacyProfile();

    address[] memory addrs = new address[](2);
    string[] memory names = new string[](2);
    addrs[0] = address(profile);
    addrs[1] = slasher;
    names[0] = ETHOS_PROFILE;
    names[1] = SLASHER;
    cam.updateContractAddressesForNames(addrs, names);
  }

  function _mintVerifiedProfile(MockLegacyProfile profile, address user) internal returns (uint256 profileId) {
    vm.deal(user, 100 ether);
    profileId = profile.mintProfile(user);
  }
}
