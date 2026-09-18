// SPDX-License-Identifier: MIT
pragma solidity 0.8.26 || 0.8.33;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {EthosSlash} from "../src/legacy/EthosSlash.sol";
import {IEthosVouchV2Slashable} from "../src/interfaces/IEthosVouchV2Slashable.sol";
import {AttestationDetails} from "../src/utils/Structs.sol";
import {SlashFixture} from "./helpers/SlashFixture.sol";

/// @dev Trivial upgrade target used to prove the UUPS upgrade path is owner-gated.
contract EthosSlashV2Mock is EthosSlash {
  function version() external pure returns (uint256) {
    return 2;
  }
}

/// @dev Malicious VouchV2 stand-in that reenters EthosSlash, to prove the shared nonReentrant
///      guard. `arm` selects the reentry target (ExecuteResolution / CreateSlash) and the trigger
///      hook (Slash, fired during executeResolution's burn; or Freeze, fired during createSlash's
///      snapshot). The Freeze trigger proves createSlash itself acquires the lock before fanning
///      out to VouchV2 — not just that the lock is shared once executeResolution holds it. For the
///      CreateSlash target the createSlash args are irrelevant: the guard fires in the modifier,
///      before createSlash's body runs any validation.
contract ReentrantVouchV2 is IEthosVouchV2Slashable {
  enum Reenter {
    None,
    ExecuteResolution,
    CreateSlash
  }

  enum Trigger {
    Slash,
    Freeze
  }

  EthosSlash private _target;
  uint256 private _targetSlashId;
  Reenter private _mode;
  Trigger private _trigger;
  mapping(address => bool) public frozen;

  function arm(EthosSlash target, uint256 slashId, Reenter mode, Trigger trigger) external {
    _target = target;
    _targetSlashId = slashId;
    _mode = mode;
    _trigger = trigger;
  }

  function freeze(address account) external override {
    frozen[account] = true;
    if (_trigger == Trigger.Freeze) _fire();
  }

  function unfreeze(address account) external override {
    frozen[account] = false;
  }

  function slash(address, uint256) external override returns (uint256) {
    if (_trigger == Trigger.Slash) _fire();
    return 0;
  }

  function activeBalanceOf(address) external pure override returns (uint256) {
    return 0;
  }

  function _fire() private {
    Reenter mode = _mode;
    _mode = Reenter.None; // disarm so the reentry itself doesn't recurse if the guard were absent
    if (mode == Reenter.ExecuteResolution) {
      _target.executeResolution(_targetSlashId, 100);
    } else if (mode == Reenter.CreateSlash) {
      _target.createSlash(
        address(0xDEAD),
        0,
        "",
        "",
        AttestationDetails({account: "", service: ""}),
        EthosSlash.SlashType.SCORE,
        type(uint256).max,
        1,
        0,
        ""
      );
    }
  }
}

contract EthosSlashTest is SlashFixture {
  // Mirror of the events under test for vm.expectEmit.
  event SlashCreated(
    uint256 id,
    uint256 createdAt,
    uint256 duration,
    address indexed subject,
    bytes32 indexed attestationHash,
    uint256 authorProfileId,
    uint256 cancelledAt,
    uint256 amount,
    EthosSlash.SlashType slashType,
    string comment,
    string metadata
  );
  event SlashEdited(uint256 id, string newComment, string newMetadata);
  event SlashCancelled(uint256 id, address cancelledBy, uint256 cancelledAt);
  event SlashExtended(uint256 id, uint256 newDuration);
  event EditWindowUpdated(uint256 newEditWindow);
  event CancelWindowUpdated(uint256 newCancelWindow);
  event DefaultDurationUpdated(uint256 newDefaultDuration);
  event FinancialSlashCreated(
    uint256 indexed id,
    uint256 subjectProfileId,
    uint256 authorProfileId,
    uint256 subjectAddrCount,
    uint256 authorAddrCount
  );
  event SlashResolved(uint256 indexed id, EthosSlash.SlashResolution indexed resolution, uint256 bps);
  event ResolutionExecuted(uint256 indexed id);

  uint256 internal constant DEFAULT_DURATION = 48 hours;
  uint256 internal constant DEFAULT_EDIT_WINDOW = 1 hours;
  uint256 internal constant DEFAULT_CANCEL_WINDOW = 1 hours;
  // Representative valid burn percentage (5%), comfortably under MAX_SLASH_BPS (10%).
  uint256 internal constant SLASH_BPS = 500;

  address internal _author = address(0xA17430);
  address internal _subject = address(0x50B1EC7);
  address internal _financialSubject = address(0xF1A);
  address internal _financialSubjectAlt = address(0xF1B);
  uint256 internal _authorProfileId;
  bytes32 internal _adminRole;
  bytes32 internal _ownerRole;

  function setUp() public {
    _deploySlashStack();
    _authorProfileId = _mintProfile(_author);
    _adminRole = _slash.ADMIN_ROLE();
    _ownerRole = _slash.OWNER_ROLE();
  }

  // ---------------------------------------------------------------------------
  // initialize
  // ---------------------------------------------------------------------------

  function test_initialize_grantsRoles() public view {
    assertTrue(_slash.hasRole(_ownerRole, _owner));
    assertTrue(_slash.hasRole(_adminRole, _admin));
  }

  function test_initialize_setsDefaults() public view {
    assertEq(_slash.defaultDuration(), DEFAULT_DURATION);
    assertEq(_slash.editWindow(), DEFAULT_EDIT_WINDOW);
    assertEq(_slash.cancelWindow(), DEFAULT_CANCEL_WINDOW);
    assertEq(_slash.slashCount(), 1);
  }

  function test_initialize_revertsOnDoubleInit() public {
    vm.expectRevert(abi.encodeWithSignature("InvalidInitialization()"));
    _slash.initialize(_owner, _admin, _signer, address(_sigVerifier), address(_cam));
  }

  // ---------------------------------------------------------------------------
  // createSlash (signed)
  // ---------------------------------------------------------------------------

  function test_createSlash_byAddress_recordsSlash() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "bad actor", "{}", EthosSlash.SlashType.SCORE, 1);

    (
      uint256 storedId,
      uint256 createdAt,
      uint256 duration,
      address subject,
      uint256 authorProfileId,
      uint256 cancelledAt,
      uint256 amount,
      EthosSlash.SlashType slashType,,
    ) = _readSlash(id);

    assertEq(storedId, 1);
    assertEq(createdAt, block.timestamp);
    assertEq(duration, DEFAULT_DURATION);
    assertEq(subject, _subject);
    assertEq(authorProfileId, _authorProfileId);
    assertEq(cancelledAt, 0);
    assertEq(amount, 100);
    assertEq(uint256(slashType), uint256(EthosSlash.SlashType.SCORE));
    assertEq(_slash.slashCount(), 2);
  }

  function test_createSlash_byAttestation_recordsSlash() public {
    AttestationDetails memory attestation = AttestationDetails({account: "0xACC", service: "x.com"});
    bytes memory sig = _signCreateSlash(
      _authorProfileId, 7, NO_EXPIRY, address(0), 5, "comment", "meta", attestation, EthosSlash.SlashType.SCORE
    );

    uint256 id = _slash.slashCount();
    vm.prank(_author);
    _slash.createSlash(address(0), 5, "comment", "meta", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 7, 0, sig);

    (,,, address subject,,,,,,, AttestationDetails memory storedAttestation) = _slash.slashes(id);
    assertEq(subject, address(0));
    assertEq(storedAttestation.account, "0xACC");
    assertEq(storedAttestation.service, "x.com");
    assertEq(_slash.slashCount(), 2);
  }

  function test_createSlash_emitsSlashCreated() public {
    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory sig =
      _signCreateSlash(_authorProfileId, 1, NO_EXPIRY, _subject, 100, "c", "m", attestation, EthosSlash.SlashType.XP);

    vm.expectEmit(true, true, false, true, address(_slash));
    emit SlashCreated(
      1,
      block.timestamp,
      DEFAULT_DURATION,
      _subject,
      bytes32(0),
      _authorProfileId,
      0,
      100,
      EthosSlash.SlashType.XP,
      "c",
      "m"
    );

    vm.prank(_author);
    _slash.createSlash(_subject, 100, "c", "m", attestation, EthosSlash.SlashType.XP, NO_EXPIRY, 1, 0, sig);
  }

  function test_createSlash_revertsOnReplayedSignature() public {
    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory sig = _signCreateSlash(
      _authorProfileId, 1, NO_EXPIRY, _subject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE
    );

    vm.prank(_author);
    _slash.createSlash(_subject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 1, 0, sig);

    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSignature("SignatureWasUsed()"));
    _slash.createSlash(_subject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 1, 0, sig);
  }

  function test_createSlash_revertsOnBadSignature() public {
    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory sig = _signCreateSlash(
      _authorProfileId, 1, NO_EXPIRY, _subject, 999, "c", "m", attestation, EthosSlash.SlashType.SCORE
    );

    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSignature("InvalidSignature()"));
    _slash.createSlash(_subject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 1, 0, sig);
  }

  function test_createSlash_revertsOnSignatureFieldSwap() public {
    // A valid sig is bound to its exact payload. Reusing it with a mutated field (here the
    // subject) must fail verification — the contract re-hashes the actual call args.
    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory sig = _signCreateSlash(
      _authorProfileId, 1, NO_EXPIRY, _subject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE
    );

    address swappedSubject = address(0xBEEF);
    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSignature("InvalidSignature()"));
    _slash.createSlash(swappedSubject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 1, 0, sig);
  }

  function test_createSlash_revertsOnCrossAuthorSignatureReuse() public {
    // A sig signed for one author's profileId can't be lifted by another caller: the contract
    // derives authorProfileId from msg.sender and re-hashes, so the payloads diverge.
    address otherAuthor = address(0xB0B);
    _mintProfile(otherAuthor);
    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory sig = _signCreateSlash(
      _authorProfileId, 1, NO_EXPIRY, _subject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE
    );

    vm.prank(otherAuthor);
    vm.expectRevert(abi.encodeWithSignature("InvalidSignature()"));
    _slash.createSlash(_subject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 1, 0, sig);
  }

  function test_createSlash_revertsWhenSelfSlash() public {
    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory sig =
      _signCreateSlash(_authorProfileId, 1, NO_EXPIRY, _author, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE);

    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSignature("SelfSlash(address)", _author));
    _slash.createSlash(_author, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 1, 0, sig);
  }

  function test_createSlash_revertsWhenSubjectSharesAuthorProfile() public {
    // A second address co-owned by the author's profile is still "self" — slashing it must
    // trip the same-profile guard (distinct from the subject == msg.sender short-circuit).
    address coOwned = address(0xC0FE);
    _registerAddress(_author, coOwned, _authorProfileId);

    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory sig =
      _signCreateSlash(_authorProfileId, 1, NO_EXPIRY, coOwned, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE);

    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSignature("SelfSlash(address)", coOwned));
    _slash.createSlash(coOwned, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 1, 0, sig);
  }

  function test_createSlash_revertsWhenAttestationSharesAuthorProfile() public {
    // An attestation that resolves to the author's own profile is self-slashing via the
    // attestation path — must trip the same-profile guard with SelfSlash(address(0)).
    string memory service = "x.com";
    string memory account = "@author";
    _linkAttestationToProfile(service, account, _authorProfileId);

    AttestationDetails memory attestation = AttestationDetails({account: account, service: service});
    bytes memory sig = _signCreateSlash(
      _authorProfileId, 1, NO_EXPIRY, address(0), 100, "c", "m", attestation, EthosSlash.SlashType.SCORE
    );

    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSignature("SelfSlash(address)", address(0)));
    _slash.createSlash(address(0), 100, "c", "m", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 1, 0, sig);
  }

  function test_createSlash_revertsWhenBothSubjectAndAttestationSet() public {
    AttestationDetails memory attestation = AttestationDetails({account: "0xACC", service: "x.com"});
    bytes memory sig = _signCreateSlash(
      _authorProfileId, 1, NO_EXPIRY, _subject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE
    );

    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSignature("InvalidSlashDetails(string)", "Both set"));
    _slash.createSlash(_subject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 1, 0, sig);
  }

  function test_createSlash_revertsWhenNeitherSubjectNorAttestationSet() public {
    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory sig = _signCreateSlash(
      _authorProfileId, 1, NO_EXPIRY, address(0), 100, "c", "m", attestation, EthosSlash.SlashType.SCORE
    );

    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSignature("InvalidSlashDetails(string)", "None set"));
    _slash.createSlash(address(0), 100, "c", "m", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 1, 0, sig);
  }

  function test_createSlash_revertsWhenAuthorHasNoProfile() public {
    address stranger = address(0xDEAD);
    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory sig =
      _signCreateSlash(0, 1, NO_EXPIRY, _subject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE);

    vm.prank(stranger);
    vm.expectRevert(abi.encodeWithSignature("ProfileNotFoundForAddress(address)", stranger));
    _slash.createSlash(_subject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 1, 0, sig);
  }

  function test_createSlash_revertsWhenPaused() public {
    _pauseSlash();
    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory sig = _signCreateSlash(
      _authorProfileId, 1, NO_EXPIRY, _subject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE
    );

    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
    _slash.createSlash(_subject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 1, 0, sig);
  }

  function testFuzz_createSlash_acceptsAnyAmount(uint256 amount) public {
    uint256 id = _createSlashWithSig(_author, _subject, amount, "c", "m", EthosSlash.SlashType.SCORE, 42);
    (,,,,,, uint256 storedAmount,,,) = _readSlash(id);
    assertEq(storedAmount, amount);
  }

  // ---------------------------------------------------------------------------
  // cancelSlash
  // ---------------------------------------------------------------------------

  function test_cancelSlash_byAuthor_setsCancelledAt() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);

    vm.prank(_author);
    _slash.cancelSlash(id);

    (,,,,, uint256 cancelledAt,,,,) = _readSlash(id);
    assertEq(cancelledAt, block.timestamp);
    assertTrue(_slash.isClosed(id));
  }

  function test_cancelSlash_byAdmin_setsCancelledAt() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);

    vm.prank(_admin);
    _slash.cancelSlash(id);

    (,,,,, uint256 cancelledAt,,,,) = _readSlash(id);
    assertEq(cancelledAt, block.timestamp);
  }

  function test_cancelSlash_emitsSlashCancelled() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);

    vm.expectEmit(false, false, false, true, address(_slash));
    emit SlashCancelled(id, _author, block.timestamp);

    vm.prank(_author);
    _slash.cancelSlash(id);
  }

  function test_cancelSlash_revertsWhenNotFound() public {
    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSignature("SlashNotFound(uint256)", uint256(999)));
    _slash.cancelSlash(999);
  }

  function test_cancelSlash_revertsWhenNotAuthor() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    address other = address(0xC0FFEE);
    _mintProfile(other);

    vm.prank(other);
    vm.expectRevert(abi.encodeWithSignature("NotSlashAuthor(uint256,address)", id, other));
    _slash.cancelSlash(id);
  }

  function test_cancelSlash_authorRevertsAfterCancelWindow() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);

    vm.warp(block.timestamp + DEFAULT_CANCEL_WINDOW + 1);
    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSignature("CancelWindowExpired(uint256)", id));
    _slash.cancelSlash(id);
  }

  function test_cancelSlash_adminCanCancelAfterWindow() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);

    vm.warp(block.timestamp + DEFAULT_CANCEL_WINDOW + 1);
    vm.prank(_admin);
    _slash.cancelSlash(id);

    (,,,,, uint256 cancelledAt,,,,) = _readSlash(id);
    assertGt(cancelledAt, 0);
  }

  function test_cancelSlash_revertsWhenAlreadyCancelled() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    vm.prank(_author);
    _slash.cancelSlash(id);

    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSignature("SlashIsCancelled(uint256)", id));
    _slash.cancelSlash(id);
  }

  function test_cancelSlash_revertsWhenClosed() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);

    vm.warp(block.timestamp + DEFAULT_DURATION + 1);
    vm.prank(_admin);
    vm.expectRevert(abi.encodeWithSignature("SlashIsClosed(uint256)", id));
    _slash.cancelSlash(id);
  }

  function test_cancelSlash_revertsWhenPaused() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    _pauseSlash();

    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
    _slash.cancelSlash(id);
  }

  function testFuzz_cancelSlash_authorRevertsAfterWindow(uint256 offset) public {
    offset = bound(offset, DEFAULT_CANCEL_WINDOW + 1, DEFAULT_DURATION - 1);
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);

    vm.warp(block.timestamp + offset);
    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSignature("CancelWindowExpired(uint256)", id));
    _slash.cancelSlash(id);
  }

  function test_cancelSlash_revertsForProfilelessCaller() public {
    // Distinct from the profiled-other-user case: a caller with no profile reads profileId 0,
    // which won't match the (non-zero) author profile.
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    address stranger = address(0x57A11);

    vm.prank(stranger);
    vm.expectRevert(abi.encodeWithSignature("NotSlashAuthor(uint256,address)", id, stranger));
    _slash.cancelSlash(id);
  }

  function test_cancelSlash_attestationKeyedSlash() public {
    AttestationDetails memory attestation = AttestationDetails({account: "@victim", service: "x.com"});
    bytes memory sig = _signCreateSlash(
      _authorProfileId, 1, NO_EXPIRY, address(0), 100, "c", "m", attestation, EthosSlash.SlashType.SCORE
    );
    uint256 id = _slash.slashCount();
    vm.prank(_author);
    _slash.createSlash(address(0), 100, "c", "m", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 1, 0, sig);

    vm.prank(_author);
    _slash.cancelSlash(id);
    (,,,,, uint256 cancelledAt,,,,) = _readSlash(id);
    assertGt(cancelledAt, 0);
  }

  // ---------------------------------------------------------------------------
  // editSlash
  // ---------------------------------------------------------------------------

  function test_editSlash_byAuthor_updatesCommentAndMetadata() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "old", "oldmeta", EthosSlash.SlashType.SCORE, 1);

    vm.prank(_author);
    _slash.editSlash(id, "new", "newmeta");

    (,,,,,,,, string memory comment, string memory metadata) = _readSlash(id);
    assertEq(comment, "new");
    assertEq(metadata, "newmeta");
  }

  function test_editSlash_emitsSlashEdited() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "old", "oldmeta", EthosSlash.SlashType.SCORE, 1);

    vm.expectEmit(false, false, false, true, address(_slash));
    emit SlashEdited(id, "new", "newmeta");

    vm.prank(_author);
    _slash.editSlash(id, "new", "newmeta");
  }

  function test_editSlash_revertsWhenNotFound() public {
    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSignature("SlashNotFound(uint256)", uint256(999)));
    _slash.editSlash(999, "c", "m");
  }

  function test_editSlash_revertsAfterEditWindow() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "old", "oldmeta", EthosSlash.SlashType.SCORE, 1);

    vm.warp(block.timestamp + DEFAULT_EDIT_WINDOW + 1);
    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSignature("EditWindowExpired(uint256)", id));
    _slash.editSlash(id, "new", "newmeta");
  }

  function test_editSlash_revertsWhenNotAuthor() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "old", "oldmeta", EthosSlash.SlashType.SCORE, 1);
    address other = address(0xC0FFEE);
    _mintProfile(other);

    vm.prank(other);
    vm.expectRevert(abi.encodeWithSignature("NotSlashAuthor(uint256,address)", id, other));
    _slash.editSlash(id, "new", "newmeta");
  }

  function test_editSlash_revertsWhenPaused() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "old", "oldmeta", EthosSlash.SlashType.SCORE, 1);
    _pauseSlash();

    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
    _slash.editSlash(id, "new", "newmeta");
  }

  function test_editSlash_revertsForProfilelessCaller() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "old", "oldmeta", EthosSlash.SlashType.SCORE, 1);
    address stranger = address(0x57A11);

    vm.prank(stranger);
    vm.expectRevert(abi.encodeWithSignature("NotSlashAuthor(uint256,address)", id, stranger));
    _slash.editSlash(id, "new", "newmeta");
  }

  function test_editSlash_revertsWhenSlashCancelled() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "old", "oldmeta", EthosSlash.SlashType.SCORE, 1);
    vm.prank(_author);
    _slash.cancelSlash(id);

    // isEditable short-circuits on isClosed (cancelled), so this hits a different branch than
    // the past-edit-window case.
    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSignature("EditWindowExpired(uint256)", id));
    _slash.editSlash(id, "new", "newmeta");
  }

  function test_editSlash_revertsWhenExpiredByDuration() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "old", "oldmeta", EthosSlash.SlashType.SCORE, 1);

    // Past the full duration (not just the edit window) — exercises the isClosed-by-expiry
    // branch inside isEditable.
    vm.warp(block.timestamp + DEFAULT_DURATION + 1);
    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSignature("EditWindowExpired(uint256)", id));
    _slash.editSlash(id, "new", "newmeta");
  }

  // ---------------------------------------------------------------------------
  // extendSlash
  // ---------------------------------------------------------------------------

  function test_extendSlash_byAdmin_updatesDuration() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);

    vm.prank(_admin);
    _slash.extendSlash(id, DEFAULT_DURATION * 2);

    (,, uint256 duration,,,,,,,) = _readSlash(id);
    assertEq(duration, DEFAULT_DURATION * 2);
  }

  function test_extendSlash_emitsSlashExtended() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);

    vm.expectEmit(false, false, false, true, address(_slash));
    emit SlashExtended(id, DEFAULT_DURATION * 2);

    vm.prank(_admin);
    _slash.extendSlash(id, DEFAULT_DURATION * 2);
  }

  function test_extendSlash_revertsWhenNotAdmin() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);

    vm.prank(_author);
    vm.expectRevert(
      abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, _author, _adminRole)
    );
    _slash.extendSlash(id, DEFAULT_DURATION * 2);
  }

  function test_extendSlash_revertsWhenNotFound() public {
    vm.prank(_admin);
    vm.expectRevert(abi.encodeWithSignature("SlashNotFound(uint256)", uint256(999)));
    _slash.extendSlash(999, DEFAULT_DURATION * 2);
  }

  function test_extendSlash_revertsWhenCancelled() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    vm.prank(_author);
    _slash.cancelSlash(id);

    vm.prank(_admin);
    vm.expectRevert(abi.encodeWithSignature("SlashIsCancelled(uint256)", id));
    _slash.extendSlash(id, DEFAULT_DURATION * 2);
  }

  function test_extendSlash_revertsWhenClosed() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);

    vm.warp(block.timestamp + DEFAULT_DURATION + 1);
    vm.prank(_admin);
    vm.expectRevert(abi.encodeWithSignature("SlashIsClosed(uint256)", id));
    _slash.extendSlash(id, DEFAULT_DURATION * 3);
  }

  function test_extendSlash_revertsWhenDurationNotIncreased() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);

    vm.prank(_admin);
    vm.expectRevert(abi.encodeWithSignature("InvalidDuration(uint256,uint256)", id, DEFAULT_DURATION));
    _slash.extendSlash(id, DEFAULT_DURATION);
  }

  function test_extendSlash_revertsWhenPaused() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    _pauseSlash();

    vm.prank(_admin);
    vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
    _slash.extendSlash(id, DEFAULT_DURATION * 2);
  }

  function test_extendSlash_revertsAboveMaxDuration() public {
    // Admin can't extend a slash's duration past MAX_SLASH_DURATION (bounds the freeze window).
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    uint256 tooLong = _slash.MAX_SLASH_DURATION() + 1;

    vm.prank(_admin);
    vm.expectRevert(abi.encodeWithSignature("InvalidDuration(uint256,uint256)", id, tooLong));
    _slash.extendSlash(id, tooLong);
  }

  function test_extendSlash_succeedsAtMaxDuration() public {
    // Exactly MAX_SLASH_DURATION is allowed (the cap is `>`, not `>=`).
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    uint256 maxDuration = _slash.MAX_SLASH_DURATION();

    vm.prank(_admin);
    _slash.extendSlash(id, maxDuration);

    (,, uint256 duration,,,,,,,) = _readSlash(id);
    assertEq(duration, maxDuration);
  }

  function test_maxSlashDurationIsSevenDays() public view {
    assertEq(_slash.MAX_SLASH_DURATION(), 7 days);
  }

  function test_extendSlash_financial_revertsAboveMaxDuration() public {
    // The cap's motivating case: a FINANCIAL slash (still PENDING) can't have its freeze window
    // extended past MAX_SLASH_DURATION. Also pins that _requirePendingIfFinancial doesn't
    // short-circuit the new ceiling check for a pending financial slash.
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    uint256 tooLong = _slash.MAX_SLASH_DURATION() + 1;

    vm.prank(_admin);
    vm.expectRevert(abi.encodeWithSignature("InvalidDuration(uint256,uint256)", id, tooLong));
    _slash.extendSlash(id, tooLong);
  }

  function test_extendSlash_uncallableWhenDefaultDurationExceedsMax() public {
    // Documented side effect (ADR-0005 §6): MAX_SLASH_DURATION caps extendSlash but NOT
    // setDefaultDuration. If an admin sets defaultDuration above the ceiling, a fresh slash's
    // duration already exceeds it, so extendSlash has an empty satisfiable interval — newDuration
    // must be both > the current duration AND <= MAX_SLASH_DURATION — and every value reverts. The
    // slash still resolves on its own clock; only the extend lever is dead. This pins that
    // accepted behavior so the auditor sees it's intentional, not an oversight.
    uint256 longDuration = _slash.MAX_SLASH_DURATION() + 1 days; // 8 days, above the 7-day ceiling
    vm.prank(_admin);
    _slash.setDefaultDuration(longDuration);

    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);

    // Above both the current duration and the ceiling → trips the ceiling check.
    uint256 above = longDuration + 1 days;
    vm.prank(_admin);
    vm.expectRevert(abi.encodeWithSignature("InvalidDuration(uint256,uint256)", id, above));
    _slash.extendSlash(id, above);

    // Within the cap but below the current duration → unambiguously the strictly-increasing check
    // (MAX_SLASH_DURATION is < the 8-day current duration and is not itself above the ceiling).
    uint256 withinCap = _slash.MAX_SLASH_DURATION();
    vm.prank(_admin);
    vm.expectRevert(abi.encodeWithSignature("InvalidDuration(uint256,uint256)", id, withinCap));
    _slash.extendSlash(id, withinCap);
  }

  // ---------------------------------------------------------------------------
  // setEditWindow / setCancelWindow / setDefaultDuration
  // ---------------------------------------------------------------------------

  function test_setEditWindow_updatesAndEmits() public {
    vm.expectEmit(false, false, false, true, address(_slash));
    emit EditWindowUpdated(2 hours);
    vm.prank(_admin);
    _slash.setEditWindow(2 hours);
    assertEq(_slash.editWindow(), 2 hours);
  }

  function test_setEditWindow_revertsWhenZero() public {
    vm.prank(_admin);
    vm.expectRevert(abi.encodeWithSignature("InvalidEditWindow(uint256)", uint256(0)));
    _slash.setEditWindow(0);
  }

  function test_setEditWindow_revertsWhenNotAdmin() public {
    vm.prank(_author);
    vm.expectRevert(
      abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, _author, _adminRole)
    );
    _slash.setEditWindow(2 hours);
  }

  function test_setCancelWindow_updatesAndEmits() public {
    vm.expectEmit(false, false, false, true, address(_slash));
    emit CancelWindowUpdated(3 hours);
    vm.prank(_admin);
    _slash.setCancelWindow(3 hours);
    assertEq(_slash.cancelWindow(), 3 hours);
  }

  function test_setCancelWindow_revertsWhenZero() public {
    vm.prank(_admin);
    vm.expectRevert(abi.encodeWithSignature("InvalidCancelWindow(uint256)", uint256(0)));
    _slash.setCancelWindow(0);
  }

  function test_setCancelWindow_revertsWhenNotAdmin() public {
    vm.prank(_author);
    vm.expectRevert(
      abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, _author, _adminRole)
    );
    _slash.setCancelWindow(3 hours);
  }

  function test_setDefaultDuration_updatesAndEmits() public {
    vm.expectEmit(false, false, false, true, address(_slash));
    emit DefaultDurationUpdated(72 hours);
    vm.prank(_admin);
    _slash.setDefaultDuration(72 hours);
    assertEq(_slash.defaultDuration(), 72 hours);
  }

  function test_setDefaultDuration_revertsWhenZero() public {
    vm.prank(_admin);
    vm.expectRevert(abi.encodeWithSignature("InvalidDefaultDuration(uint256)", uint256(0)));
    _slash.setDefaultDuration(0);
  }

  function test_setDefaultDuration_revertsWhenNotAdmin() public {
    vm.prank(_author);
    vm.expectRevert(
      abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, _author, _adminRole)
    );
    _slash.setDefaultDuration(72 hours);
  }

  function testFuzz_setEditWindow_acceptsBelowDuration(uint256 newWindow) public {
    // editWindow must stay below defaultDuration (enforced by the setter).
    newWindow = bound(newWindow, 1, _slash.defaultDuration() - 1);
    vm.prank(_admin);
    _slash.setEditWindow(newWindow);
    assertEq(_slash.editWindow(), newWindow);
  }

  // ---------------------------------------------------------------------------
  // Window setters cross-validate against defaultDuration
  // ---------------------------------------------------------------------------

  function test_setEditWindow_revertsWhenAtOrAboveDuration() public {
    vm.prank(_admin);
    vm.expectRevert(
      abi.encodeWithSignature("WindowNotBelowDuration(uint256,uint256)", DEFAULT_DURATION, DEFAULT_DURATION)
    );
    _slash.setEditWindow(DEFAULT_DURATION);
  }

  function test_setCancelWindow_revertsWhenAtOrAboveDuration() public {
    vm.prank(_admin);
    vm.expectRevert(
      abi.encodeWithSignature("WindowNotBelowDuration(uint256,uint256)", DEFAULT_DURATION + 1, DEFAULT_DURATION)
    );
    _slash.setCancelWindow(DEFAULT_DURATION + 1);
  }

  function test_setDefaultDuration_revertsWhenDurationBelowCancelWindow() public {
    // A duration below cancelWindow trips the cancelWindow check (which runs before the editWindow one).
    // Use 30m (distinct from the 1h windows) so the reverted args read unambiguously as (window, duration).
    vm.prank(_admin);
    vm.expectRevert(
      abi.encodeWithSignature("WindowNotBelowDuration(uint256,uint256)", DEFAULT_CANCEL_WINDOW, uint256(30 minutes))
    );
    _slash.setDefaultDuration(30 minutes);
  }

  function test_setDefaultDuration_acceptsAboveWindows() public {
    vm.prank(_admin);
    _slash.setDefaultDuration(DEFAULT_DURATION * 2);
    assertEq(_slash.defaultDuration(), DEFAULT_DURATION * 2);
  }

  function test_setDefaultDuration_revertsWhenDurationBelowEditWindow() public {
    // With cancelWindow below and editWindow above, a duration between them passes the
    // cancelWindow check and trips the editWindow check specifically.
    vm.startPrank(_admin);
    _slash.setCancelWindow(30 minutes);
    _slash.setEditWindow(2 hours);
    vm.expectRevert(
      abi.encodeWithSignature("WindowNotBelowDuration(uint256,uint256)", uint256(2 hours), uint256(1 hours))
    );
    _slash.setDefaultDuration(1 hours);
    vm.stopPrank();
  }

  // ---------------------------------------------------------------------------
  // view functions
  // ---------------------------------------------------------------------------

  function test_isOpen_trueForFreshSlash() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    assertTrue(_slash.isOpen(id));
    assertFalse(_slash.isClosed(id));
  }

  function test_isOpen_falseAfterDuration() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    vm.warp(block.timestamp + DEFAULT_DURATION + 1);
    assertFalse(_slash.isOpen(id));
    assertTrue(_slash.isClosed(id));
  }

  function test_isOpen_falseWhenCancelled() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    vm.prank(_author);
    _slash.cancelSlash(id);
    assertFalse(_slash.isOpen(id));
    assertTrue(_slash.isClosed(id));
  }

  function test_isOpen_falseForNonexistent() public view {
    assertFalse(_slash.isOpen(0));
    assertFalse(_slash.isOpen(999));
    assertFalse(_slash.isClosed(0));
    assertFalse(_slash.isClosed(999));
  }

  function test_isEditable_trueWithinWindow_falseAfter() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    assertTrue(_slash.isEditable(id));
    vm.warp(block.timestamp + DEFAULT_EDIT_WINDOW + 1);
    assertFalse(_slash.isEditable(id));
  }

  function test_isEditable_falseWhenClosed() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    vm.prank(_author);
    _slash.cancelSlash(id);
    assertFalse(_slash.isEditable(id));
  }

  function test_isCancellable_authorWithinWindow_adminAlways() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    assertTrue(_slash.isCancellable(id, false));
    assertTrue(_slash.isCancellable(id, true));

    vm.warp(block.timestamp + DEFAULT_CANCEL_WINDOW + 1);
    assertFalse(_slash.isCancellable(id, false));
    assertTrue(_slash.isCancellable(id, true));
  }

  function test_isCancellable_falseForNonexistent() public view {
    assertFalse(_slash.isCancellable(0, false));
    assertFalse(_slash.isCancellable(999, true));
  }

  function test_targetExistsAndAllowedForId_existsAndOpen() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    (bool exists, bool allowed) = _slash.targetExistsAndAllowedForId(id);
    assertTrue(exists);
    assertTrue(allowed);
  }

  function test_targetExistsAndAllowedForId_existsButClosedAfterCancel() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    vm.prank(_author);
    _slash.cancelSlash(id);
    (bool exists, bool allowed) = _slash.targetExistsAndAllowedForId(id);
    assertTrue(exists);
    assertFalse(allowed);
  }

  function test_targetExistsAndAllowedForId_existsButClosedAfterDuration() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    vm.warp(block.timestamp + DEFAULT_DURATION + 1);
    (bool exists, bool allowed) = _slash.targetExistsAndAllowedForId(id);
    assertTrue(exists);
    assertFalse(allowed);
  }

  function test_targetExistsAndAllowedForId_doesNotExist() public view {
    (bool exists, bool allowed) = _slash.targetExistsAndAllowedForId(999);
    assertFalse(exists);
    assertFalse(allowed);
  }

  // ---------------------------------------------------------------------------
  // storage-pointer status reads — cost must stay flat as comment/metadata grow
  // ---------------------------------------------------------------------------
  // Status helpers read scalars through a `Slash storage` pointer, so a bloated
  // comment/metadata is never SLOAD'd. EthosVote.voteFor and the EthosDiscussion
  // reply path call targetExistsAndAllowedForId on every interaction; a `Slash
  // memory` copy here would let an author tax every voter/replier. These pin the
  // flat cost — reverting to `memory` fails them by ~6 figures of gas.

  function test_statusViews_correctWithLargeCommentMetadata() public {
    string memory huge = string(new bytes(4096));
    uint256 id = _createSlashWithSig(_author, _subject, 100, huge, huge, EthosSlash.SlashType.SCORE, 1);

    assertTrue(_slash.isOpen(id));
    assertFalse(_slash.isClosed(id));
    assertTrue(_slash.isEditable(id));
    assertTrue(_slash.isCancellable(id, false));
    assertTrue(_slash.isCancellable(id, true));
    (bool exists, bool allowed) = _slash.targetExistsAndAllowedForId(id);
    assertTrue(exists);
    assertTrue(allowed);

    vm.prank(_author);
    _slash.cancelSlash(id);
    assertFalse(_slash.isOpen(id));
    assertTrue(_slash.isClosed(id));
  }

  function test_editSlash_toLargeCommentMetadata_succeeds() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "old", "oldmeta", EthosSlash.SlashType.SCORE, 1);

    vm.prank(_author);
    _slash.editSlash(id, string(new bytes(4096)), string(new bytes(4096)));

    (,,,,,,,, string memory comment, string memory metadata) = _readSlash(id);
    assertEq(bytes(comment).length, 4096);
    assertEq(bytes(metadata).length, 4096);
    assertTrue(_slash.isEditable(id));
  }

  function test_targetExistsAndAllowedForId_gasFlatAcrossCommentLength() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);

    // Warm slashCount and the scalar slots so the delta isolates struct-read cost.
    _slash.targetExistsAndAllowedForId(id);
    uint256 g = gasleft();
    _slash.targetExistsAndAllowedForId(id);
    uint256 gasSmall = g - gasleft();

    vm.prank(_author);
    _slash.editSlash(id, string(new bytes(4096)), string(new bytes(4096)));

    g = gasleft();
    _slash.targetExistsAndAllowedForId(id);
    uint256 gasBig = g - gasleft();

    assertApproxEqAbs(gasBig, gasSmall, 2000);
  }

  function test_cancelSlash_gasFlatAcrossCommentLength() public {
    address authorB = address(0xB0B);
    _mintProfile(authorB);
    string memory huge = string(new bytes(4096));
    uint256 bigId = _createSlashWithSig(_author, _subject, 100, huge, huge, EthosSlash.SlashType.SCORE, 1);
    uint256 smallId = _createSlashWithSig(authorB, address(0x5B11), 100, "c", "m", EthosSlash.SlashType.SCORE, 2);

    // Cancel the bloated slash first so any cold shared-slot cost is charged to it.
    vm.prank(_author);
    uint256 g = gasleft();
    _slash.cancelSlash(bigId);
    uint256 gasBig = g - gasleft();

    vm.prank(authorB);
    g = gasleft();
    _slash.cancelSlash(smallId);
    uint256 gasSmall = g - gasleft();

    assertApproxEqAbs(gasBig, gasSmall, 20000);
  }

  // ---------------------------------------------------------------------------
  // exact time boundaries
  // ---------------------------------------------------------------------------
  // The contract uses strict `>` for isOpen and `<=` for isClosed/isEditable/isCancellable,
  // so the instant `block.timestamp == createdAt + window` is the off-by-one-prone edge.

  function test_isClosed_atExactDurationBoundary() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    uint256 createdAt = block.timestamp;
    vm.warp(createdAt + DEFAULT_DURATION);
    assertFalse(_slash.isOpen(id));
    assertTrue(_slash.isClosed(id));
  }

  function test_isEditable_atExactEditWindowBoundary() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    uint256 createdAt = block.timestamp;
    vm.warp(createdAt + DEFAULT_EDIT_WINDOW);
    assertTrue(_slash.isEditable(id));
  }

  function test_cancelSlash_authorAtExactCancelWindowBoundary() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    uint256 createdAt = block.timestamp;
    vm.warp(createdAt + DEFAULT_CANCEL_WINDOW);
    assertTrue(_slash.isCancellable(id, false));

    vm.prank(_author);
    _slash.cancelSlash(id);
    (,,,,, uint256 cancelledAt,,,,) = _readSlash(id);
    assertGt(cancelledAt, 0);
  }

  function test_views_atNextUnmintedId() public {
    _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    // slashCount is the next, not-yet-minted id. The view guards reject it (`>= slashCount`),
    // so every view agrees it's non-existent — no phantom id reads a zeroed slot.
    uint256 nextId = _slash.slashCount();
    assertFalse(_slash.isOpen(nextId));
    assertFalse(_slash.isClosed(nextId));
    assertFalse(_slash.isCancellable(nextId, true));
    (bool exists,) = _slash.targetExistsAndAllowedForId(nextId);
    assertFalse(exists);
  }

  // ---------------------------------------------------------------------------
  // pause lifecycle
  // ---------------------------------------------------------------------------

  function test_pauseThenUnpause_resumesOperation() public {
    _pauseSlash();
    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory sig = _signCreateSlash(
      _authorProfileId, 1, NO_EXPIRY, _subject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE
    );

    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
    _slash.createSlash(_subject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 1, 0, sig);

    _unpauseSlash();
    vm.prank(_author);
    _slash.createSlash(_subject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 1, 0, sig);
    assertEq(_slash.slashCount(), 2);
  }

  // ---------------------------------------------------------------------------
  // UUPS upgrade
  // ---------------------------------------------------------------------------

  function test_upgrade_succeedsForOwner() public {
    address newImpl = address(new EthosSlashV2Mock());
    vm.prank(_owner);
    _slash.upgradeToAndCall(newImpl, "");
    assertEq(EthosSlashV2Mock(address(_slash)).version(), 2);
  }

  function test_upgrade_revertsForNonOwner() public {
    address newImpl = address(new EthosSlashV2Mock());
    vm.prank(_admin);
    vm.expectRevert(
      abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, _admin, _ownerRole)
    );
    _slash.upgradeToAndCall(newImpl, "");
  }

  // ---------------------------------------------------------------------------
  // createSlash FINANCIAL — snapshot + freeze
  // ---------------------------------------------------------------------------

  function test_createFinancial_profiledSubject_freezesAllSnapshotAddresses() public {
    uint256 subjectProfileId = _mintProfile(_financialSubject);
    _registerAddress(_financialSubject, _financialSubjectAlt, subjectProfileId);

    uint256 id = _createFinancialSlash(_author, _financialSubject, 1);

    // Subject profile's two addresses + the author's single address are all frozen.
    assertTrue(_vouchV2.frozen(_financialSubject));
    assertTrue(_vouchV2.frozen(_financialSubjectAlt));
    assertTrue(_vouchV2.frozen(_author));
    assertEq(_vouchV2.freezeCalls(), 3);

    EthosSlash.FinancialSlash memory fs = _slash.financialSlash(id);
    assertEq(fs.slashSubjectAddrs.length, 2);
    assertEq(fs.slashAuthorAddrs.length, 1);
    assertEq(uint256(fs.resolution), uint256(EthosSlash.SlashResolution.PENDING));
  }

  function test_createFinancial_bareAddressSubject_freezesSingleAddress() public {
    // _subject has no profile — only that one address is frozen on the subject side.
    uint256 id = _createFinancialSlash(_author, _subject, 1);

    assertTrue(_vouchV2.frozen(_subject));
    assertTrue(_vouchV2.frozen(_author));
    assertEq(_vouchV2.freezeCalls(), 2);

    EthosSlash.FinancialSlash memory fs = _slash.financialSlash(id);
    assertEq(fs.slashSubjectAddrs.length, 1);
    assertEq(fs.slashSubjectAddrs[0], _subject);
    assertEq(fs.slashAuthorAddrs.length, 1);
  }

  function test_createFinancial_mockProfileSubject_freezesBareAddress() public {
    // A mock profile carries no address array, so a profile-keyed snapshot would freeze nothing;
    // the snapshot must fall back to the bare address — it can still author slashable vouches.
    uint256 mockId = _mintMockProfileForAddress(_financialSubject);
    (,, bool mock) = _profile.profileStatusById(mockId);
    assertTrue(mock); // sanity: subject is a mock profile, not an unprofiled address

    uint256 id = _createFinancialSlash(_author, _financialSubject, 1);

    assertTrue(_vouchV2.frozen(_financialSubject));
    assertTrue(_vouchV2.frozen(_author));
    assertEq(_vouchV2.freezeCalls(), 2);

    EthosSlash.FinancialSlash memory fs = _slash.financialSlash(id);
    assertEq(fs.slashSubjectAddrs.length, 1);
    assertEq(fs.slashSubjectAddrs[0], _financialSubject);
  }

  function test_createFinancial_attestationLinkedToProfile_freezesProfileAddresses() public {
    uint256 subjectProfileId = _mintProfile(_financialSubject);
    _linkAttestationToProfile("x.com", "acct", subjectProfileId);

    uint256 id = _createFinancialSlashByAttestation(_author, "x.com", "acct", 7);

    // Attestation resolved to the subject profile → its address frozen.
    assertTrue(_vouchV2.frozen(_financialSubject));
    EthosSlash.FinancialSlash memory fs = _slash.financialSlash(id);
    assertEq(fs.slashSubjectAddrs.length, 1);
    assertEq(fs.slashSubjectAddrs[0], _financialSubject);
  }

  function test_createFinancial_revertsWhenAttestationHasNoAddresses() public {
    // Attestation resolves to no profile → no subject addresses to freeze/burn. A financial slash
    // that can only ever burn the author's own balance is rejected at create, not recorded as a no-op.
    AttestationDetails memory attestation = AttestationDetails({account: "0xACC", service: "x.com"});
    uint256 expectedId = _slash.slashCount();
    bytes memory sig = _signCreateSlash(
      _authorProfileId, 7, NO_EXPIRY, address(0), 0, "financial", "m", attestation, EthosSlash.SlashType.FINANCIAL
    );

    vm.expectRevert(abi.encodeWithSelector(EthosSlash.NoSubjectToSlash.selector, expectedId));
    vm.prank(_author);
    _slash.createSlash(
      address(0), 0, "financial", "m", attestation, EthosSlash.SlashType.FINANCIAL, NO_EXPIRY, 7, 0, sig
    );
  }

  function test_createFinancial_revertsWhenAttestationResolvesToMockProfile() public {
    // Attestation resolves to a mock profile: non-zero profileId, but no address array and no bare
    // address (subject == address(0)). The mock-attestation branch must hit the same NoSubjectToSlash
    // revert as an unlinked attestation, not slip past the _isMockProfile guard into a no-op record.
    uint256 mockId = _mintMockProfileForAttestation("x.com", "mockacct");
    (,, bool mock) = _profile.profileStatusById(mockId);
    assertTrue(mock);

    AttestationDetails memory attestation = AttestationDetails({account: "mockacct", service: "x.com"});
    uint256 expectedId = _slash.slashCount();
    bytes memory sig = _signCreateSlash(
      _authorProfileId, 8, NO_EXPIRY, address(0), 0, "financial", "m", attestation, EthosSlash.SlashType.FINANCIAL
    );

    vm.expectRevert(abi.encodeWithSelector(EthosSlash.NoSubjectToSlash.selector, expectedId));
    vm.prank(_author);
    _slash.createSlash(
      address(0), 0, "financial", "m", attestation, EthosSlash.SlashType.FINANCIAL, NO_EXPIRY, 8, 0, sig
    );
  }

  function test_createFinancial_emitsFinancialSlashCreated() public {
    uint256 subjectProfileId = _mintProfile(_financialSubject);
    uint256 expectedId = _slash.slashCount();

    vm.expectEmit(true, false, false, true, address(_slash));
    emit FinancialSlashCreated(expectedId, subjectProfileId, _authorProfileId, 1, 1);
    _createFinancialSlash(_author, _financialSubject, 1);
  }

  function test_financialSlash_zeroForNonFinancial() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    EthosSlash.FinancialSlash memory fs = _slash.financialSlash(id);
    assertEq(fs.slashSubjectAddrs.length, 0);
    assertEq(fs.bps, 0);
    assertEq(uint256(fs.resolution), uint256(EthosSlash.SlashResolution.PENDING));
  }

  function test_createFinancial_revertsWhenVouchV2NotRegistered() public {
    _deregisterVouchV2();
    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory sig = _signCreateSlash(
      _authorProfileId, 1, NO_EXPIRY, _subject, 0, "financial", "m", attestation, EthosSlash.SlashType.FINANCIAL
    );
    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSignature("VouchV2NotRegistered()"));
    _slash.createSlash(_subject, 0, "financial", "m", attestation, EthosSlash.SlashType.FINANCIAL, NO_EXPIRY, 1, 0, sig);
  }

  // ---------------------------------------------------------------------------
  // resolveSlash
  // ---------------------------------------------------------------------------

  function test_resolveSlash_recordsOutcomeAndBps() public {
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    _warpPastDuration();
    _resolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1);

    EthosSlash.FinancialSlash memory fs = _slash.financialSlash(id);
    assertEq(uint256(fs.resolution), uint256(EthosSlash.SlashResolution.SLASHED));
    assertEq(fs.bps, SLASH_BPS);
  }

  function test_resolveSlash_emitsSlashResolved() public {
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    _warpPastDuration();

    vm.expectEmit(true, true, false, true, address(_slash));
    emit SlashResolved(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS);
    _resolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1);
  }

  function test_resolveSlash_revertsBeforeDuration() public {
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    bytes memory sig = _signResolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1);
    vm.expectRevert(abi.encodeWithSignature("SlashDurationNotElapsed(uint256)", id));
    _slash.resolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1, sig);
  }

  function test_resolveSlash_revertsWhenNotFound() public {
    bytes memory sig = _signResolveSlash(999, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1);
    vm.expectRevert(abi.encodeWithSignature("SlashNotFound(uint256)", uint256(999)));
    _slash.resolveSlash(999, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1, sig);
  }

  function test_resolveSlash_revertsWhenNotFinancial() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    _warpPastDuration();
    bytes memory sig = _signResolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1);
    vm.expectRevert(abi.encodeWithSignature("SlashTypeNotFinancial(uint256)", id));
    _slash.resolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1, sig);
  }

  function test_resolveSlash_revertsOnSecondResolve() public {
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    _warpPastDuration();
    _resolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1);

    bytes memory sig = _signResolveSlash(id, EthosSlash.SlashResolution.DEFENDED, 100, 2);
    vm.expectRevert(
      abi.encodeWithSignature("AlreadyResolved(uint256,uint8)", id, uint8(EthosSlash.SlashResolution.SLASHED))
    );
    _slash.resolveSlash(id, EthosSlash.SlashResolution.DEFENDED, 100, 2, sig);
  }

  function test_resolveSlash_revertsOnPendingResolution() public {
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    _warpPastDuration();
    bytes memory sig = _signResolveSlash(id, EthosSlash.SlashResolution.PENDING, 0, 1);
    vm.expectRevert(abi.encodeWithSignature("InvalidResolution(uint8)", uint8(EthosSlash.SlashResolution.PENDING)));
    _slash.resolveSlash(id, EthosSlash.SlashResolution.PENDING, 0, 1, sig);
  }

  function test_resolveSlash_revertsOnCancelledResolution() public {
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    _warpPastDuration();
    bytes memory sig = _signResolveSlash(id, EthosSlash.SlashResolution.CANCELLED, 0, 1);
    vm.expectRevert(abi.encodeWithSignature("InvalidResolution(uint8)", uint8(EthosSlash.SlashResolution.CANCELLED)));
    _slash.resolveSlash(id, EthosSlash.SlashResolution.CANCELLED, 0, 1, sig);
  }

  function test_resolveSlash_maxSlashBpsIsTenPercent() public view {
    assertEq(_slash.MAX_SLASH_BPS(), 1_000);
    assertEq(_slash.BASIS_POINT_SCALE(), 10_000);
  }

  function test_resolveSlash_revertsWhenBpsExceedsMax() public {
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    _warpPastDuration();
    uint256 tooHigh = _slash.MAX_SLASH_BPS() + 1;
    bytes memory sig = _signResolveSlash(id, EthosSlash.SlashResolution.SLASHED, tooHigh, 1);
    vm.expectRevert(abi.encodeWithSignature("BpsTooHigh(uint256)", tooHigh));
    _slash.resolveSlash(id, EthosSlash.SlashResolution.SLASHED, tooHigh, 1, sig);
  }

  function test_resolveSlash_acceptsBpsAtMax() public {
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    _warpPastDuration();
    uint256 maxBps = _slash.MAX_SLASH_BPS();
    _resolveSlash(id, EthosSlash.SlashResolution.SLASHED, maxBps, 1);
    assertEq(_slash.financialSlash(id).bps, uint16(maxBps));
  }

  function test_resolveSlash_inconclusiveStoresZeroBps() public {
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    _warpPastDuration();
    // Sign and submit bps=SLASH_BPS; INCONCLUSIVE forces stored bps to 0.
    _resolveSlash(id, EthosSlash.SlashResolution.INCONCLUSIVE, SLASH_BPS, 1);

    EthosSlash.FinancialSlash memory fs = _slash.financialSlash(id);
    assertEq(uint256(fs.resolution), uint256(EthosSlash.SlashResolution.INCONCLUSIVE));
    assertEq(fs.bps, 0);
  }

  function test_resolveSlash_revertsWhenSignaturePayloadMismatch() public {
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    _warpPastDuration();
    // Signature is over bps=SLASH_BPS but the call submits a different bps — payload binding rejects it.
    bytes memory sig = _signResolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1);
    vm.expectRevert(abi.encodeWithSignature("InvalidSignature()"));
    _slash.resolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS + 100, 1, sig);
  }

  function test_resolveSlash_revertsWhenPaused() public {
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    _warpPastDuration();
    _pauseSlash();
    bytes memory sig = _signResolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1);
    vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
    _slash.resolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1, sig);
  }

  function test_resolveSlash_revertsOnBadSigner() public {
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    _warpPastDuration();
    // Correct payload, wrong key (not the expected signer) → rejected.
    bytes memory sig = _signResolveSlashWithKey(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1, 0xBAD);
    vm.expectRevert(abi.encodeWithSignature("InvalidSignature()"));
    _slash.resolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1, sig);
  }

  function test_resolveSlash_revertsAtFullScaleBps() public {
    // 100% (BASIS_POINT_SCALE) exceeds MAX_SLASH_BPS (10%) and reverts BpsTooHigh.
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    _warpPastDuration();
    uint256 fullScale = _slash.BASIS_POINT_SCALE();
    bytes memory sig = _signResolveSlash(id, EthosSlash.SlashResolution.SLASHED, fullScale, 1);
    vm.expectRevert(abi.encodeWithSignature("BpsTooHigh(uint256)", fullScale));
    _slash.resolveSlash(id, EthosSlash.SlashResolution.SLASHED, fullScale, 1, sig);
  }

  function test_resolveSlash_revertsAfterCancel() public {
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    vm.prank(_author);
    _slash.cancelSlash(id);
    _warpPastDuration();
    bytes memory sig = _signResolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1);
    vm.expectRevert(
      abi.encodeWithSignature("AlreadyResolved(uint256,uint8)", id, uint8(EthosSlash.SlashResolution.CANCELLED))
    );
    _slash.resolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1, sig);
  }

  function test_resolveSlash_succeedsAtExactDurationBoundary() public {
    uint256 createdAt = block.timestamp;
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    // Resolvable at exactly createdAt + duration (the gate is `<`, not `<=`).
    vm.warp(createdAt + DEFAULT_DURATION);
    _resolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1);
    assertEq(uint256(_slash.financialSlash(id).resolution), uint256(EthosSlash.SlashResolution.SLASHED));
  }

  function test_resolveSlash_revertsOneSecondBeforeBoundary() public {
    uint256 createdAt = block.timestamp;
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    vm.warp(createdAt + DEFAULT_DURATION - 1);
    bytes memory sig = _signResolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1);
    vm.expectRevert(abi.encodeWithSignature("SlashDurationNotElapsed(uint256)", id));
    _slash.resolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1, sig);
  }

  // ---------------------------------------------------------------------------
  // executeResolution
  // ---------------------------------------------------------------------------

  function test_executeResolution_slashedBurnsSubjectOnly() public {
    uint256 subjectProfileId = _mintProfile(_financialSubject);
    _registerAddress(_financialSubject, _financialSubjectAlt, subjectProfileId);
    uint256 id = _createFinancialSlash(_author, _financialSubject, 1);
    _warpPastDuration();
    _resolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1);

    _slash.executeResolution(id, 100);

    // Subject addresses burned at SLASH_BPS bps; author untouched.
    assertEq(_vouchV2.slashCallCount(_financialSubject), 1);
    assertEq(_vouchV2.lastSlashBps(_financialSubject), SLASH_BPS);
    assertEq(_vouchV2.slashCallCount(_financialSubjectAlt), 1);
    assertEq(_vouchV2.slashCallCount(_author), 0);

    // Every snapshot address unfrozen.
    assertFalse(_vouchV2.frozen(_financialSubject));
    assertFalse(_vouchV2.frozen(_financialSubjectAlt));
    assertFalse(_vouchV2.frozen(_author));

    // Snapshot drained + finalized.
    EthosSlash.FinancialSlash memory fs = _slash.financialSlash(id);
    assertEq(fs.slashSubjectAddrs.length, 0);
    assertEq(fs.slashAuthorAddrs.length, 0);
    assertTrue(fs.executedAt > 0);
  }

  function test_executeResolution_defendedBurnsAuthorOnly() public {
    // Asymmetric arrays (author 2 addrs, subject 1) so a subject<->author array swap is detectable.
    address authorAlt = address(0xA17431);
    _registerAddress(_author, authorAlt, _authorProfileId);
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    _warpPastDuration();
    _resolveSlash(id, EthosSlash.SlashResolution.DEFENDED, SLASH_BPS, 1);

    _slash.executeResolution(id, 100);

    assertEq(_vouchV2.slashCallCount(_author), 1);
    assertEq(_vouchV2.slashCallCount(authorAlt), 1);
    assertEq(_vouchV2.lastSlashBps(_author), SLASH_BPS);
    assertEq(_vouchV2.slashCallCount(_subject), 0);
    assertFalse(_vouchV2.frozen(_author));
    assertFalse(_vouchV2.frozen(authorAlt));
    assertFalse(_vouchV2.frozen(_subject));
  }

  function test_executeResolution_inconclusiveBurnsNothing() public {
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    _warpPastDuration();
    _resolveSlash(id, EthosSlash.SlashResolution.INCONCLUSIVE, 0, 1);

    _slash.executeResolution(id, 100);

    assertEq(_vouchV2.slashCallCount(_subject), 0);
    assertEq(_vouchV2.slashCallCount(_author), 0);
    assertFalse(_vouchV2.frozen(_subject));
    assertFalse(_vouchV2.frozen(_author));
  }

  function test_executeResolution_zeroBpsSkipsBurnButUnfreezes() public {
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    _warpPastDuration();
    _resolveSlash(id, EthosSlash.SlashResolution.SLASHED, 0, 1);

    _slash.executeResolution(id, 100);

    assertEq(_vouchV2.slashCallCount(_subject), 0); // bps 0 → no burn call
    assertFalse(_vouchV2.frozen(_subject));
  }

  function test_executeResolution_chunkedDrain() public {
    uint256 subjectProfileId = _mintProfile(_financialSubject);
    _registerAddress(_financialSubject, _financialSubjectAlt, subjectProfileId);
    uint256 id = _createFinancialSlash(_author, _financialSubject, 1);
    _warpPastDuration();
    _resolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1);

    // 2 subject + 1 author addresses. One op at a time leaves the snapshot partially drained.
    _slash.executeResolution(id, 1);
    assertEq(_slash.financialSlash(id).slashSubjectAddrs.length, 1);
    assertEq(_slash.financialSlash(id).executedAt, 0);

    // Drain the remainder.
    _slash.executeResolution(id, 10);
    EthosSlash.FinancialSlash memory fs = _slash.financialSlash(id);
    assertEq(fs.slashSubjectAddrs.length, 0);
    assertEq(fs.slashAuthorAddrs.length, 0);
    assertTrue(fs.executedAt > 0);
  }

  function test_executeResolution_emitsResolutionExecutedOnce() public {
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    _warpPastDuration();
    _resolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1);

    vm.expectEmit(true, false, false, false, address(_slash));
    emit ResolutionExecuted(id);
    _slash.executeResolution(id, 10);
  }

  function test_executeResolution_idempotentAfterDrain() public {
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    _warpPastDuration();
    _resolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1);

    _slash.executeResolution(id, 10);
    uint256 burnsAfterFirst = _vouchV2.slashCallCount(_subject);
    uint64 executedAt = _slash.financialSlash(id).executedAt;

    // Re-running past drain is a no-op: no extra burns, executedAt unchanged.
    _slash.executeResolution(id, 10);
    assertEq(_vouchV2.slashCallCount(_subject), burnsAfterFirst);
    assertEq(_slash.financialSlash(id).executedAt, executedAt);
  }

  function test_executeResolution_revertsWhenMaxOpsZero() public {
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    _warpPastDuration();
    _resolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1);
    vm.expectRevert(abi.encodeWithSignature("MaxOpsZero()"));
    _slash.executeResolution(id, 0);
  }

  function test_executeResolution_revertsWhenNotFinancial() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    vm.expectRevert(abi.encodeWithSignature("SlashTypeNotFinancial(uint256)", id));
    _slash.executeResolution(id, 10);
  }

  function test_executeResolution_revertsWhenNotFound() public {
    vm.expectRevert(abi.encodeWithSignature("SlashNotFound(uint256)", uint256(999)));
    _slash.executeResolution(999, 10);
  }

  function test_executeResolution_revertsWhenResolutionPending() public {
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    vm.expectRevert(abi.encodeWithSignature("ResolutionPending(uint256)", id));
    _slash.executeResolution(id, 10);
  }

  function test_executeResolution_revertsWhenVouchV2NotRegistered() public {
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    _warpPastDuration();
    _resolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1);
    _deregisterVouchV2();
    vm.expectRevert(abi.encodeWithSignature("VouchV2NotRegistered()"));
    _slash.executeResolution(id, 10);
  }

  function test_executeResolution_maxOpsDrainsSubjectArrayExactly() public {
    uint256 subjectProfileId = _mintProfile(_financialSubject);
    _registerAddress(_financialSubject, _financialSubjectAlt, subjectProfileId);
    uint256 id = _createFinancialSlash(_author, _financialSubject, 1);
    _warpPastDuration();
    _resolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1);

    // 2 subject addrs: maxOps=2 drains exactly the subject array, leaves the author array, no finalize.
    _slash.executeResolution(id, 2);
    EthosSlash.FinancialSlash memory fs = _slash.financialSlash(id);
    assertEq(fs.slashSubjectAddrs.length, 0);
    assertEq(fs.slashAuthorAddrs.length, 1);
    assertEq(fs.executedAt, 0);
  }

  function test_executeResolution_mockProfileSubject_burnsBareAddressOnce() public {
    // The bare-address fallback (mock-profile subject) must survive the full lifecycle: a SLASHED
    // resolution burns the snapshotted address exactly once and unfreezes it on drain.
    _mintMockProfileForAddress(_financialSubject);
    uint256 id = _createFinancialSlash(_author, _financialSubject, 1);

    _warpPastDuration();
    _resolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1);
    _slash.executeResolution(id, 10);

    assertEq(_vouchV2.slashCallCount(_financialSubject), 1);
    assertEq(_vouchV2.lastSlashBps(_financialSubject), SLASH_BPS);
    assertEq(_vouchV2.slashCallCount(_author), 0); // SLASHED burns subject, not author
    assertFalse(_vouchV2.frozen(_financialSubject));
    assertFalse(_vouchV2.frozen(_author));

    EthosSlash.FinancialSlash memory fs = _slash.financialSlash(id);
    assertEq(fs.slashSubjectAddrs.length, 0);
    assertTrue(fs.executedAt > 0);
  }

  function test_executeResolution_revertsOnReentrancy() public {
    // Point VouchV2 at a malicious mock that reenters executeResolution from inside slash().
    // The nonReentrant guard must revert the reentry (and thus the whole tx).
    ReentrantVouchV2 reentrant = new ReentrantVouchV2();
    _setVouchV2(address(reentrant));

    uint256 id = _createFinancialSlash(_author, _subject, 1);
    _warpPastDuration();
    _resolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1);
    reentrant.arm(_slash, id, ReentrantVouchV2.Reenter.ExecuteResolution, ReentrantVouchV2.Trigger.Slash);

    vm.expectRevert(abi.encodeWithSignature("ReentrancyGuardReentrantCall()"));
    _slash.executeResolution(id, 100);
  }

  function test_executeResolution_blocksReentrantCreateSlash() public {
    // Cross-function: while executeResolution holds the shared guard, a burn callback that tries
    // to reenter createSlash must revert. Proves createSlash is nonReentrant and the guard is
    // shared (the reentry trips the modifier before createSlash's body runs).
    ReentrantVouchV2 reentrant = new ReentrantVouchV2();
    _setVouchV2(address(reentrant));

    uint256 id = _createFinancialSlash(_author, _subject, 1);
    _warpPastDuration();
    _resolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1);
    reentrant.arm(_slash, id, ReentrantVouchV2.Reenter.CreateSlash, ReentrantVouchV2.Trigger.Slash);

    vm.expectRevert(abi.encodeWithSignature("ReentrancyGuardReentrantCall()"));
    _slash.executeResolution(id, 100);
  }

  function test_createSlash_revertsOnReentrancyViaFreeze() public {
    // Proves createSlash acquires the guard before fanning out to VouchV2 — not just that the lock
    // is shared once executeResolution holds it. The malicious VouchV2 reenters createSlash from
    // inside freeze(), which createSlash calls during the FINANCIAL snapshot; the guard createSlash
    // itself holds must revert the reentry.
    ReentrantVouchV2 reentrant = new ReentrantVouchV2();
    _setVouchV2(address(reentrant));
    reentrant.arm(_slash, 0, ReentrantVouchV2.Reenter.CreateSlash, ReentrantVouchV2.Trigger.Freeze);

    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory sig = _signCreateSlash(
      _authorProfileId, 1, NO_EXPIRY, _subject, 0, "financial", "m", attestation, EthosSlash.SlashType.FINANCIAL
    );

    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSignature("ReentrancyGuardReentrantCall()"));
    _slash.createSlash(_subject, 0, "financial", "m", attestation, EthosSlash.SlashType.FINANCIAL, NO_EXPIRY, 1, 0, sig);
  }

  // ---------------------------------------------------------------------------
  // reinitV2ReentrancyGuard (upgrade-time guard init)
  // ---------------------------------------------------------------------------

  function test_reinitV2ReentrancyGuard_ownerCanCallOnce() public {
    vm.prank(_owner);
    _slash.reinitV2ReentrancyGuard();
  }

  function test_reinitV2ReentrancyGuard_revertsOnSecondCall() public {
    // reinitializer(2) is one-shot: the second call trips OZ's InvalidInitialization.
    vm.prank(_owner);
    _slash.reinitV2ReentrancyGuard();

    vm.prank(_owner);
    vm.expectRevert(abi.encodeWithSignature("InvalidInitialization()"));
    _slash.reinitV2ReentrancyGuard();
  }

  function test_reinitV2ReentrancyGuard_revertsForNonOwner() public {
    vm.prank(_admin);
    vm.expectRevert(
      abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, _admin, _ownerRole)
    );
    _slash.reinitV2ReentrancyGuard();
  }

  // ---------------------------------------------------------------------------
  // Freeze refcount + snapshot dedup
  // ---------------------------------------------------------------------------

  function test_createFinancial_dedupesDuplicateRegisteredAddress() public {
    // EthosProfile.registerAddress lets the same (address, profile) be registered twice with
    // distinct signatures, so addressesForProfile can list an address more than once. The snapshot
    // must hold it once — otherwise executeResolution pops it twice and double-burns it.
    uint256 pid = _mintProfile(_financialSubject);
    address dup = address(0xD0B1E);
    _registerAddress(_financialSubject, dup, pid); // first registration
    _registerAddress(_financialSubject, dup, pid, 9_999); // second, distinct sig → dup in the list

    uint256 id = _createFinancialSlash(_author, _financialSubject, 1);

    // Three raw subject entries (_financialSubject, dup, dup) collapse to two; each frozen once
    // (3 freezes total: subject primary + dup + author).
    EthosSlash.FinancialSlash memory fs = _slash.financialSlash(id);
    assertEq(fs.slashSubjectAddrs.length, 2);
    assertTrue(_vouchV2.frozen(dup));
    assertEq(_vouchV2.freezeCalls(), 3);

    // SLASHED burns each snapshot address exactly once — dup is not double-burned.
    _warpPastDuration();
    _resolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1);
    _slash.executeResolution(id, 100);

    assertEq(_vouchV2.slashCallCount(dup), 1);
    assertFalse(_vouchV2.frozen(dup));
  }

  function test_createFinancial_dedupesDuplicateAuthorAddress() public {
    // The author snapshot runs through the same _snapshotAndFreeze dedup as the subject side. A
    // duplicate-registered author address must be frozen once and, on a DEFENDED burn, slashed once.
    address dupAuthor = address(0xA17D00);
    _registerAddress(_author, dupAuthor, _authorProfileId); // first registration
    _registerAddress(_author, dupAuthor, _authorProfileId, 7_777); // second, distinct sig → dup in the list

    uint256 id = _createFinancialSlash(_author, _subject, 1);

    // Author snapshot collapses (_author, dupAuthor, dupAuthor) to two entries.
    EthosSlash.FinancialSlash memory fs = _slash.financialSlash(id);
    assertEq(fs.slashAuthorAddrs.length, 2);
    assertTrue(_vouchV2.frozen(dupAuthor));

    // DEFENDED burns the author side — dupAuthor is slashed once, not twice.
    _warpPastDuration();
    _resolveSlash(id, EthosSlash.SlashResolution.DEFENDED, SLASH_BPS, 1);
    _slash.executeResolution(id, 100);

    assertEq(_vouchV2.slashCallCount(dupAuthor), 1);
    assertFalse(_vouchV2.frozen(dupAuthor));
  }

  function test_freezeRefCount_keepsAddressFrozenAcrossOverlappingSlashes() public {
    // An address can be frozen by two open slashes in different roles — author of one, subject of
    // another — which the per-author/per-subject cap permits (distinct keys). With a boolean freeze
    // flag, resolving the first slash would unfreeze the address while the second still needs it
    // locked. The refcount keeps it frozen until BOTH resolve.
    address carol = address(0xCA401);
    _mintProfile(carol);

    // Slash A: _author slashes _subject — freezes _subject (subject side) and _author (author side).
    uint256 idA = _createFinancialSlash(_author, _subject, 1);
    // Slash B: carol slashes _author — freezes _author (subject side) and carol (author side).
    // _author is now held by both A (as author) and B (as subject); its second freeze is refcounted.
    uint256 idB = _createFinancialSlash(carol, _author, 2);

    assertTrue(_vouchV2.frozen(_author));
    assertEq(_vouchV2.freezeCalls(), 3); // _subject, _author (A); carol (B) — _author's 2nd freeze is a no-op

    _warpPastDuration();

    // Resolve + execute A. _author leaves A's snapshot but stays frozen — B still holds it.
    _resolveSlash(idA, EthosSlash.SlashResolution.INCONCLUSIVE, 0, 1);
    _slash.executeResolution(idA, 100);
    assertTrue(_vouchV2.frozen(_author)); // refcount 2 → 1, still frozen
    assertFalse(_vouchV2.frozen(_subject)); // A released its own subject
    assertEq(_vouchV2.unfreezeCalls(), 1); // only _subject actually unfrozen

    // Resolve + execute B. The last holder releases _author.
    _resolveSlash(idB, EthosSlash.SlashResolution.INCONCLUSIVE, 0, 2);
    _slash.executeResolution(idB, 100);
    assertFalse(_vouchV2.frozen(_author)); // refcount 1 → 0
  }

  function test_freezeRefCount_burnsOncePerSlashAcrossOverlap() public {
    // The overlap test above uses INCONCLUSIVE (no burn). This one interleaves real burns: _author is
    // the author of slash A and the subject of slash B, so resolving A DEFENDED and B SLASHED each
    // burns _author once. The shared address is slashed exactly once per slash (never double-counted
    // within a slash) and stays frozen until the second slash drains.
    address carol = address(0xCA402);
    _mintProfile(carol);

    uint256 idA = _createFinancialSlash(_author, _subject, 1); // A: _author (author) slashes _subject
    uint256 idB = _createFinancialSlash(carol, _author, 2); // B: carol slashes _author (subject); refcount(_author)=2

    _warpPastDuration();

    // A DEFENDED → burns A's author side (_author). _author stays frozen — B still holds it.
    _resolveSlash(idA, EthosSlash.SlashResolution.DEFENDED, SLASH_BPS, 1);
    _slash.executeResolution(idA, 100);
    assertEq(_vouchV2.slashCallCount(_author), 1);
    assertEq(_vouchV2.lastSlashBps(_author), SLASH_BPS);
    assertTrue(_vouchV2.frozen(_author)); // refcount 2 → 1
    assertFalse(_vouchV2.frozen(_subject)); // A released its own subject
    assertEq(_vouchV2.unfreezeCalls(), 1); // only _subject hit the 1→0 edge; _author stayed frozen

    // B SLASHED → burns B's subject side (_author) a second time, then the last holder releases it.
    _resolveSlash(idB, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 2);
    _slash.executeResolution(idB, 100);
    assertEq(_vouchV2.slashCallCount(_author), 2); // once per slash — never double-counted within either
    assertFalse(_vouchV2.frozen(_author)); // refcount 1 → 0
    assertFalse(_vouchV2.frozen(carol));
    assertEq(_vouchV2.unfreezeCalls(), 3); // A: _subject; B: _author (1→0) + carol
  }

  function test_executeResolution_operatesOnCreateTimeSnapshotNotLiveProfile() public {
    // The snapshot is fixed at createSlash. An address added to the subject's profile mid-slash is
    // not in the snapshot, so it is never frozen, burned, or unfrozen — and the refcount stays
    // balanced against the create-time set.
    uint256 subjectProfileId = _mintProfile(_financialSubject);
    _registerAddress(_financialSubject, _financialSubjectAlt, subjectProfileId);

    uint256 id = _createFinancialSlash(_author, _financialSubject, 1);
    assertEq(_vouchV2.freezeCalls(), 3); // 2 subject addrs + author

    // Add a third address to the subject profile AFTER the snapshot was taken.
    address lateAddr = address(0x1A7E);
    _registerAddress(_financialSubject, lateAddr, subjectProfileId);
    assertFalse(_vouchV2.frozen(lateAddr)); // not in the snapshot → never frozen
    assertEq(_vouchV2.freezeCalls(), 3); // the late registration triggers no freeze

    _warpPastDuration();
    _resolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1);
    _slash.executeResolution(id, 100);

    // Only the create-time snapshot addresses are burned + unfrozen; lateAddr is untouched.
    assertEq(_vouchV2.slashCallCount(_financialSubject), 1);
    assertEq(_vouchV2.slashCallCount(_financialSubjectAlt), 1);
    assertEq(_vouchV2.slashCallCount(lateAddr), 0);
    assertFalse(_vouchV2.frozen(_financialSubject));
    assertFalse(_vouchV2.frozen(_financialSubjectAlt));

    EthosSlash.FinancialSlash memory fs = _slash.financialSlash(id);
    assertEq(fs.slashSubjectAddrs.length, 0);
    assertTrue(fs.executedAt > 0);
  }

  function test_createFinancial_revertsWhenSelfSlash() public {
    // The self-slash guard runs in createSlash before the FINANCIAL branch, so a financial self-slash
    // reverts before any freeze fanout — no snapshot is taken and VouchV2.freeze is never called.
    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory sig = _signCreateSlash(
      _authorProfileId, 1, NO_EXPIRY, _author, 0, "financial", "m", attestation, EthosSlash.SlashType.FINANCIAL
    );
    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSignature("SelfSlash(address)", _author));
    _slash.createSlash(_author, 0, "financial", "m", attestation, EthosSlash.SlashType.FINANCIAL, NO_EXPIRY, 1, 0, sig);
    assertEq(_vouchV2.freezeCalls(), 0);
  }

  // ---------------------------------------------------------------------------
  // cancelSlash FINANCIAL
  // ---------------------------------------------------------------------------

  function test_cancelSlash_financial_recordsCancelled() public {
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    vm.prank(_author);
    _slash.cancelSlash(id);

    EthosSlash.FinancialSlash memory fs = _slash.financialSlash(id);
    assertEq(uint256(fs.resolution), uint256(EthosSlash.SlashResolution.CANCELLED));
    assertEq(fs.bps, 0);
  }

  function test_cancelSlash_financial_thenExecuteUnfreezesWithoutBurn() public {
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    assertTrue(_vouchV2.frozen(_subject));

    vm.prank(_author);
    _slash.cancelSlash(id);
    _slash.executeResolution(id, 10);

    assertFalse(_vouchV2.frozen(_subject));
    assertFalse(_vouchV2.frozen(_author));
    assertEq(_vouchV2.slashCallCount(_subject), 0); // CANCELLED never burns
  }

  function test_cancelSlash_revertsAfterResolve() public {
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    _warpPastDuration();
    _resolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1);
    // Resolve happens past duration, so the slash is closed; cancel hits the closed guard.
    vm.prank(_admin);
    vm.expectRevert(abi.encodeWithSignature("SlashIsClosed(uint256)", id));
    _slash.cancelSlash(id);
  }

  // ---------------------------------------------------------------------------
  // Resolved/cancelled FINANCIAL slashes revert AlreadyResolved on edit/extend.
  // The terminal-state guard runs before the duration/closed checks, so it is the
  // canonical error once a FINANCIAL slash carries a resolution. SCORE/XP are unaffected
  // (the guard is a no-op for them — covered by the existing edit/extend tests).
  // ---------------------------------------------------------------------------

  function test_editSlash_revertsAlreadyResolvedAfterResolve() public {
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    _warpPastDuration();
    _resolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1);

    vm.prank(_author);
    vm.expectRevert(
      abi.encodeWithSignature("AlreadyResolved(uint256,uint8)", id, uint8(EthosSlash.SlashResolution.SLASHED))
    );
    _slash.editSlash(id, "new", "new");
  }

  function test_editSlash_revertsAlreadyResolvedAfterCancel() public {
    // cancelSlash records CANCELLED; the guard catches it before the edit-window check.
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    vm.prank(_author);
    _slash.cancelSlash(id);

    vm.prank(_author);
    vm.expectRevert(
      abi.encodeWithSignature("AlreadyResolved(uint256,uint8)", id, uint8(EthosSlash.SlashResolution.CANCELLED))
    );
    _slash.editSlash(id, "new", "new");
  }

  function test_extendSlash_revertsAlreadyResolvedAfterResolve() public {
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    _warpPastDuration();
    _resolveSlash(id, EthosSlash.SlashResolution.SLASHED, SLASH_BPS, 1);

    vm.prank(_admin);
    vm.expectRevert(
      abi.encodeWithSignature("AlreadyResolved(uint256,uint8)", id, uint8(EthosSlash.SlashResolution.SLASHED))
    );
    _slash.extendSlash(id, DEFAULT_DURATION * 2);
  }

  function test_extendSlash_revertsAlreadyResolvedAfterCancel() public {
    uint256 id = _createFinancialSlash(_author, _subject, 1);
    vm.prank(_author);
    _slash.cancelSlash(id);
    // The guard runs before the cancelledAt/closed checks → AlreadyResolved, not SlashIsCancelled.
    vm.prank(_admin);
    vm.expectRevert(
      abi.encodeWithSignature("AlreadyResolved(uint256,uint8)", id, uint8(EthosSlash.SlashResolution.CANCELLED))
    );
    _slash.extendSlash(id, DEFAULT_DURATION * 2);
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /// @dev Decodes the public `slashes(uint256)` getter. AttestationDetails (the last
  ///      tuple field) is dropped — no test asserts on it.
  function _readSlash(uint256 id)
    internal
    view
    returns (
      uint256 storedId,
      uint256 createdAt,
      uint256 duration,
      address subject,
      uint256 authorProfileId,
      uint256 cancelledAt,
      uint256 amount,
      EthosSlash.SlashType slashType,
      string memory comment,
      string memory metadata
    )
  {
    (
      storedId, createdAt, duration, subject, authorProfileId, cancelledAt, amount, slashType, comment, metadata,
    ) = _slash.slashes(id);
  }

  // ---------------------------------------------------------------------------
  // signature expiry
  // ---------------------------------------------------------------------------

  function test_createSlash_succeedsWithFutureDeadline() public {
    uint256 id =
      _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1, block.timestamp + 5 minutes);
    assertEq(_slash.slashCount(), id + 1);
  }

  function test_createSlash_succeedsAtDeadlineBoundary() public {
    // Guard is `block.timestamp > deadline`, so deadline == now still passes.
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1, block.timestamp);
    assertEq(_slash.slashCount(), id + 1);
  }

  function test_createSlash_revertsWhenSignatureExpired() public {
    uint256 deadline = block.timestamp + 5 minutes;
    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory sig =
      _signCreateSlash(_authorProfileId, 1, deadline, _subject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE);

    vm.warp(deadline + 1);
    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSignature("SignatureExpired(uint256,uint256)", deadline, block.timestamp));
    _slash.createSlash(_subject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE, deadline, 1, 0, sig);
  }

  // ---------------------------------------------------------------------------
  // check ordering — pins expiry-before-cap and sig-verify-before-cap
  // ---------------------------------------------------------------------------

  function test_createSlash_signatureExpiredWinsOverSubjectCap() public {
    // With an open slash already on _subject, an expired sig from a different author must revert
    // SignatureExpired — not SubjectHasOpenSlash. Pins expiry-check before cap-check.
    _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1, NO_EXPIRY);

    address authorB = address(0xB0B);
    uint256 bProfileId = _mintProfile(authorB);
    uint256 deadline = block.timestamp + 5 minutes;
    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory sig =
      _signCreateSlash(bProfileId, 2, deadline, _subject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE);

    vm.warp(deadline + 1);
    vm.prank(authorB);
    vm.expectRevert(abi.encodeWithSignature("SignatureExpired(uint256,uint256)", deadline, block.timestamp));
    _slash.createSlash(_subject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE, deadline, 2, 0, sig);
  }

  function test_createSlash_invalidSignatureWinsOverSubjectCap() public {
    // With an open slash already on _subject, an invalid sig must revert InvalidSignature — not
    // SubjectHasOpenSlash. Pins validateAndSaveSignature before cap-check (closes the info-leak
    // where an unauthenticated caller could probe open-slash state via the cap revert).
    _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1, NO_EXPIRY);

    address authorB = address(0xB0B);
    uint256 bProfileId = _mintProfile(authorB);
    AttestationDetails memory attestation = _emptyAttestation();
    // Sign for amount=999 then submit with amount=100 — payload mismatch → InvalidSignature.
    bytes memory sig =
      _signCreateSlash(bProfileId, 2, NO_EXPIRY, _subject, 999, "c", "m", attestation, EthosSlash.SlashType.SCORE);

    vm.prank(authorB);
    vm.expectRevert(abi.encodeWithSignature("InvalidSignature()"));
    _slash.createSlash(_subject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 2, 0, sig);
  }

  // ---------------------------------------------------------------------------
  // concurrent-slash cap — subject
  // ---------------------------------------------------------------------------

  function test_subjectCap_blocksSecondSlashOnSameSubject() public {
    // _subject is a bare address (no profile) → capped via its address slot. A different author B
    // (so the author cap doesn't fire first) cannot open a second slash on the same subject.
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);

    address authorB = address(0xB0B);
    uint256 bProfileId = _mintProfile(authorB);
    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory sig =
      _signCreateSlash(bProfileId, 2, NO_EXPIRY, _subject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE);

    vm.prank(authorB);
    vm.expectRevert(abi.encodeWithSignature("SubjectHasOpenSlash(uint256)", id));
    _slash.createSlash(_subject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 2, 0, sig);
  }

  function test_subjectCap_blocksSiblingWalletOfSameProfile() public {
    // Subject profile P with two wallets; slashing via walletA must block a slash via walletB.
    address walletA = address(0x5A);
    address walletB = address(0x5B);
    uint256 pId = _mintProfile(walletA);
    _registerAddress(walletA, walletB, pId);

    uint256 id = _createSlashWithSig(_author, walletA, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);

    address authorB = address(0xB0B);
    uint256 bProfileId = _mintProfile(authorB);
    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory sig =
      _signCreateSlash(bProfileId, 2, NO_EXPIRY, walletB, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE);

    vm.prank(authorB);
    vm.expectRevert(abi.encodeWithSignature("SubjectHasOpenSlash(uint256)", id));
    _slash.createSlash(walletB, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 2, 0, sig);
  }

  function test_subjectCap_blocksAttestationOfAlreadySlashedProfile() public {
    // Slashing an address of profile P must block a slash via P's attestation (same profile slot).
    address wallet = address(0x5C);
    uint256 pId = _mintProfile(wallet);
    _linkAttestationToProfile("x.com", "alice", pId);

    uint256 id = _createSlashWithSig(_author, wallet, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);

    address authorB = address(0xB0B);
    uint256 bProfileId = _mintProfile(authorB);
    AttestationDetails memory att = AttestationDetails({service: "x.com", account: "alice"});
    bytes memory sig =
      _signCreateSlash(bProfileId, 2, NO_EXPIRY, address(0), 100, "c", "m", att, EthosSlash.SlashType.SCORE);

    vm.prank(authorB);
    vm.expectRevert(abi.encodeWithSignature("SubjectHasOpenSlash(uint256)", id));
    _slash.createSlash(address(0), 100, "c", "m", att, EthosSlash.SlashType.SCORE, NO_EXPIRY, 2, 0, sig);
  }

  function test_subjectCap_blocksProfilelessAttestation() public {
    // An attestation with no linked profile is capped via its attestation-hash slot.
    AttestationDetails memory att = AttestationDetails({service: "x.com", account: "nobody"});
    bytes memory sig1 =
      _signCreateSlash(_authorProfileId, 1, NO_EXPIRY, address(0), 100, "c", "m", att, EthosSlash.SlashType.SCORE);
    uint256 id = _slash.slashCount();
    vm.prank(_author);
    _slash.createSlash(address(0), 100, "c", "m", att, EthosSlash.SlashType.SCORE, NO_EXPIRY, 1, 0, sig1);

    address authorB = address(0xB0B);
    uint256 bProfileId = _mintProfile(authorB);
    bytes memory sig2 =
      _signCreateSlash(bProfileId, 2, NO_EXPIRY, address(0), 100, "c", "m", att, EthosSlash.SlashType.SCORE);
    vm.prank(authorB);
    vm.expectRevert(abi.encodeWithSignature("SubjectHasOpenSlash(uint256)", id));
    _slash.createSlash(address(0), 100, "c", "m", att, EthosSlash.SlashType.SCORE, NO_EXPIRY, 2, 0, sig2);
  }

  function test_subjectCap_freesAfterCancel() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    vm.prank(_author);
    _slash.cancelSlash(id);
    // Both author and subject slots freed (cancelled → !isOpen); a fresh slash succeeds.
    uint256 id2 = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 2);
    assertEq(_slash.slashCount(), id2 + 1);
  }

  function test_subjectCap_freesAfterDurationExpiry() public {
    // NO_EXPIRY so the 48h warp can't expire the signatures — this isolates the cap-frees-on-expiry path.
    _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1, NO_EXPIRY);
    vm.warp(block.timestamp + DEFAULT_DURATION + 1);
    uint256 id2 = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 2, NO_EXPIRY);
    assertEq(_slash.slashCount(), id2 + 1);
  }

  // ---------------------------------------------------------------------------
  // concurrent-slash cap — author
  // ---------------------------------------------------------------------------

  function test_authorCap_blocksSecondSlashBySameAuthor() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);

    address subjectW = address(0x5717);
    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory sig = _signCreateSlash(
      _authorProfileId, 2, NO_EXPIRY, subjectW, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE
    );

    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSignature("AuthorHasOpenSlash(uint256)", id));
    _slash.createSlash(subjectW, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 2, 0, sig);
  }

  function test_authorCap_bindsAcrossAuthorWallets() public {
    // The author cap is keyed by profile, so a second wallet of the same author profile is also
    // blocked: the contract derives authorProfileId from msg.sender, and both wallets resolve to it.
    address authorWalletB = address(0xA17431);
    _registerAddress(_author, authorWalletB, _authorProfileId);

    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);

    address subjectW = address(0x5718);
    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory sig = _signCreateSlash(
      _authorProfileId, 2, NO_EXPIRY, subjectW, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE
    );

    vm.prank(authorWalletB);
    vm.expectRevert(abi.encodeWithSignature("AuthorHasOpenSlash(uint256)", id));
    _slash.createSlash(subjectW, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 2, 0, sig);
  }

  function test_authorCap_freesAfterCancel() public {
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    vm.prank(_author);
    _slash.cancelSlash(id);
    uint256 id2 = _createSlashWithSig(_author, address(0x5717), 100, "c", "m", EthosSlash.SlashType.SCORE, 2);
    assertEq(_slash.slashCount(), id2 + 1);
  }

  function test_authorCap_freesAfterDurationExpiry() public {
    _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1, NO_EXPIRY);
    vm.warp(block.timestamp + DEFAULT_DURATION + 1);
    uint256 id2 = _createSlashWithSig(_author, address(0x5717), 100, "c", "m", EthosSlash.SlashType.SCORE, 2, NO_EXPIRY);
    assertEq(_slash.slashCount(), id2 + 1);
  }

  // ---------------------------------------------------------------------------
  // expiry — additional edge cases
  // ---------------------------------------------------------------------------

  function test_createSlash_revertsWhenDeadlineZero() public {
    uint256 deadline = 0;
    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory sig =
      _signCreateSlash(_authorProfileId, 1, deadline, _subject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE);

    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSignature("SignatureExpired(uint256,uint256)", deadline, block.timestamp));
    _slash.createSlash(_subject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE, deadline, 1, 0, sig);
  }

  // ---------------------------------------------------------------------------
  // concurrent-slash cap — additional coverage
  // ---------------------------------------------------------------------------

  function test_subjectCap_blocksAcrossSlashTypes() public {
    // An open SCORE slash must block an XP slash on the same subject — cap is type-agnostic.
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);

    address authorB = address(0xB0B);
    uint256 bProfileId = _mintProfile(authorB);
    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory sig =
      _signCreateSlash(bProfileId, 2, NO_EXPIRY, _subject, 100, "c", "m", attestation, EthosSlash.SlashType.XP);

    vm.prank(authorB);
    vm.expectRevert(abi.encodeWithSignature("SubjectHasOpenSlash(uint256)", id));
    _slash.createSlash(_subject, 100, "c", "m", attestation, EthosSlash.SlashType.XP, NO_EXPIRY, 2, 0, sig);
  }

  function test_subjectCap_documentsProfileCreationRaceGap() public {
    // DOCUMENTED LIMITATION (ADR-0004): identifiers that don't share a resolvable profile at create
    // time get independent slots. Slash a bare attestation (no linked profile), then link the
    // attestation to a freshly-created profile, then slash via that profile's wallet — the second
    // slash *succeeds* because the profile slot was empty when the first slash claimed only the
    // attestation-hash slot.
    AttestationDetails memory att = AttestationDetails({service: "x.com", account: "racetarget"});
    bytes memory sig1 =
      _signCreateSlash(_authorProfileId, 1, NO_EXPIRY, address(0), 100, "c", "m", att, EthosSlash.SlashType.SCORE);
    vm.prank(_author);
    _slash.createSlash(address(0), 100, "c", "m", att, EthosSlash.SlashType.SCORE, NO_EXPIRY, 1, 0, sig1);

    address wallet = address(0xACE);
    uint256 pId = _mintProfile(wallet);
    _linkAttestationToProfile("x.com", "racetarget", pId);

    address authorB = address(0xB0B);
    uint256 bProfileId = _mintProfile(authorB);
    AttestationDetails memory empty = _emptyAttestation();
    bytes memory sig2 =
      _signCreateSlash(bProfileId, 2, NO_EXPIRY, wallet, 100, "c", "m", empty, EthosSlash.SlashType.SCORE);
    uint256 id2 = _slash.slashCount();
    vm.prank(authorB);
    _slash.createSlash(wallet, 100, "c", "m", empty, EthosSlash.SlashType.SCORE, NO_EXPIRY, 2, 0, sig2);
    assertEq(_slash.slashCount(), id2 + 1);
  }

  function test_subjectCap_documentsAddressProfileCreationRaceGap() public {
    // DOCUMENTED LIMITATION (ADR-0004), bare-address branch: slashing a profileless address fills
    // only its address slot (profileId=0). If a profile is later created with that address as the
    // primary wallet, a sibling wallet of the new profile is *not* blocked — its resolved keys
    // (profile slot + sibling-address slot) are both empty.
    address victim = address(0x5717ACE);
    _createSlashWithSig(_author, victim, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);

    uint256 pId = _mintProfile(victim);
    address sibling = address(0x5717ACE2);
    _registerAddress(victim, sibling, pId);

    address authorB = address(0xB0B);
    uint256 bProfileId = _mintProfile(authorB);
    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory sig =
      _signCreateSlash(bProfileId, 2, NO_EXPIRY, sibling, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE);

    uint256 idBefore = _slash.slashCount();
    vm.prank(authorB);
    _slash.createSlash(sibling, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 2, 0, sig);
    assertEq(_slash.slashCount(), idBefore + 1);
  }

  function test_subjectCap_freesAfterAdminCancel() public {
    // Admin can cancel any open slash (no cancel-window restriction). Slot frees on next create.
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    vm.prank(_admin);
    _slash.cancelSlash(id);
    uint256 id2 = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 2);
    assertEq(_slash.slashCount(), id2 + 1);
  }

  function test_subjectCap_blocksPastOriginalDurationWhenExtended() public {
    // Admin extends a slash to 2× duration; the cap slot must remain claimed past the original end
    // because isOpen() reads the current `duration` field.
    uint256 id = _createSlashWithSig(_author, _subject, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);
    vm.prank(_admin);
    _slash.extendSlash(id, DEFAULT_DURATION * 2);
    vm.warp(block.timestamp + DEFAULT_DURATION + 1);

    address authorB = address(0xB0B);
    uint256 bProfileId = _mintProfile(authorB);
    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory sig =
      _signCreateSlash(bProfileId, 2, NO_EXPIRY, _subject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE);

    vm.prank(authorB);
    vm.expectRevert(abi.encodeWithSignature("SubjectHasOpenSlash(uint256)", id));
    _slash.createSlash(_subject, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 2, 0, sig);
  }

  function test_subjectCap_persistsAfterAddressDisconnect() public {
    // Subject profile P with wallets W1 (primary) and W2. Slash W2 → claims profile slot AND W2's
    // address slot. P then unregisters W2 (deleteAddressAtIndex). A second slash via W1 must still
    // be blocked: the profile slot is the un-bypassable backstop.
    address walletA = address(0x5A);
    address walletB = address(0x5B);
    uint256 pId = _mintProfile(walletA);
    _registerAddress(walletA, walletB, pId);

    uint256 id = _createSlashWithSig(_author, walletB, 100, "c", "m", EthosSlash.SlashType.SCORE, 1);

    // walletA (primary) deletes walletB from the profile; profile is now {walletA} only.
    vm.prank(walletA);
    _profile.deleteAddressAtIndex(1, false);

    address authorB = address(0xB0B);
    uint256 bProfileId = _mintProfile(authorB);
    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory sig =
      _signCreateSlash(bProfileId, 2, NO_EXPIRY, walletA, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE);

    vm.prank(authorB);
    vm.expectRevert(abi.encodeWithSignature("SubjectHasOpenSlash(uint256)", id));
    _slash.createSlash(walletA, 100, "c", "m", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 2, 0, sig);
  }
}
