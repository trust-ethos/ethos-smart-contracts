// SPDX-License-Identifier: MIT
pragma solidity 0.8.26 || 0.8.33;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ContractAddressManager} from "../../src/utils/ContractAddressManager.sol";
import {InteractionControl} from "../../src/utils/InteractionControl.sol";
import {SignatureVerifier} from "../../src/legacy/SignatureVerifier.sol";
import {EthosProfile} from "../../src/legacy/EthosProfile.sol";
import {EthosSlash} from "../../src/legacy/EthosSlash.sol";
import {IEthosVouchV2Slashable} from "../../src/interfaces/IEthosVouchV2Slashable.sol";
import {AttestationDetails} from "../../src/utils/Structs.sol";
import {
  ETHOS_PROFILE,
  ETHOS_ATTESTATION,
  ETHOS_INTERACTION_CONTROL,
  ETHOS_VOUCH_V2
} from "../../src/utils/Constants.sol";

/// @dev Minimal stand-in for EthosAttestation. EthosSlash only ever calls
///      `getServiceAndAccountHash` on the attestation contract (for attestation-keyed
///      slashes); everything else it needs about a subject profile comes from
///      EthosProfile. Mirrors the real hash so attestation lookups against the real
///      EthosProfile stay consistent.
contract MockEthosAttestation {
  function getServiceAndAccountHash(string calldata service, string calldata account) external pure returns (bytes32) {
    if (bytes(service).length == 0 || bytes(account).length == 0) {
      revert("MockEthosAttestation: empty service/account");
    }
    return keccak256(abi.encode(service, account));
  }
}

/// @dev Stand-in for EthosVouchV2's SLASHER command surface. Records freeze / unfreeze /
///      slash calls so tests can assert EthosSlash's fanout (which addresses were frozen,
///      which were burned and at what bps) without standing up the full V2 stack + WHUF.
contract MockVouchV2 is IEthosVouchV2Slashable {
  mapping(address => bool) public frozen;
  mapping(address => uint256) public slashCallCount;
  mapping(address => uint256) public lastSlashBps;
  // Settable per-address "live" active vouch balance that activeBalanceOf reports. Tests set it,
  // then drain it between signing and createSlash to model unvouch / deleteAddress shedding.
  mapping(address => uint256) public activeBalance;
  uint256 public freezeCalls;
  uint256 public unfreezeCalls;

  function freeze(address account) external override {
    frozen[account] = true;
    freezeCalls++;
  }

  function unfreeze(address account) external override {
    frozen[account] = false;
    unfreezeCalls++;
  }

  function slash(address account, uint256 bps) external override returns (uint256 amountApplied) {
    slashCallCount[account]++;
    lastSlashBps[account] = bps;
    return 0;
  }

  function activeBalanceOf(address account) external view override returns (uint256) {
    return activeBalance[account];
  }

  function setActiveBalance(address account, uint256 amount) external {
    activeBalance[account] = amount;
  }
}

/// @title SlashFixture
/// @notice Stands up the full dependency graph EthosSlash needs: a real
///         ContractAddressManager, SignatureVerifier, EthosProfile, and
///         InteractionControl, plus a lightweight attestation mock. Inherit and call
///         `_deploySlashStack()` in setUp().
/// @dev Pragma is the `0.8.26 || 0.8.33` disjunction because it imports the strict
///      0.8.26 legacy contracts (EthosProfile, EthosSlash); the compilation unit
///      resolves to 0.8.26. The test contract (`address(this)`) owns the CAM and
///      InteractionControl so it can register addresses and pause without extra pranks.
abstract contract SlashFixture is Test {
  string internal constant ETHOS_SLASH = "ETHOS_SLASH";
  /// @dev Sentinel deadline for tests that don't exercise expiry. Constant (not block.timestamp-based)
  ///      so it survives a vm.warp between signing and submission.
  uint256 internal constant NO_EXPIRY = type(uint256).max;

  ContractAddressManager internal _cam;
  SignatureVerifier internal _sigVerifier;
  InteractionControl internal _ic;
  EthosProfile internal _profile;
  MockEthosAttestation internal _attestation;
  MockVouchV2 internal _vouchV2;
  EthosSlash internal _slash;

  address internal _owner = address(0x1);
  address internal _admin = address(0x2);
  uint256 internal _signerPrivateKey = 0xA11CE;
  address internal _signer;

  /// @dev Owner profile (id 1) is minted by EthosProfile.initialize and holds the invites
  ///      every other test profile is created from.
  uint256 internal constant OWNER_PROFILE_ID = 1;

  function _deploySlashStack() internal {
    _signer = vm.addr(_signerPrivateKey);

    _cam = new ContractAddressManager();
    _sigVerifier = new SignatureVerifier();
    _attestation = new MockEthosAttestation();
    _vouchV2 = new MockVouchV2();
    _ic = new InteractionControl(address(this), address(_cam));

    _profile = EthosProfile(_deployProxy(address(new EthosProfile())));
    _profile.initialize(_owner, _admin, _signer, address(_sigVerifier), address(_cam));

    _slash = EthosSlash(_deployProxy(address(new EthosSlash())));
    _slash.initialize(_owner, _admin, _signer, address(_sigVerifier), address(_cam));

    _registerAddresses();
  }

  function _registerAddresses() private {
    address[] memory addrs = new address[](5);
    string[] memory names = new string[](5);
    addrs[0] = address(_profile);
    names[0] = ETHOS_PROFILE;
    addrs[1] = address(_attestation);
    names[1] = ETHOS_ATTESTATION;
    addrs[2] = address(_ic);
    names[2] = ETHOS_INTERACTION_CONTROL;
    addrs[3] = address(_slash);
    names[3] = ETHOS_SLASH;
    addrs[4] = address(_vouchV2);
    names[4] = ETHOS_VOUCH_V2;
    _cam.updateContractAddressesForNames(addrs, names);

    string[] memory controlled = new string[](1);
    controlled[0] = ETHOS_SLASH;
    _ic.addControlledContractNames(controlled);
  }

  function _deployProxy(address impl) internal returns (address) {
    return address(new ERC1967Proxy(impl, ""));
  }

  // --- Profile helpers ---

  /// @dev Invites `user` from the owner profile and creates their profile.
  ///      Returns the newly verified profileId.
  function _mintProfile(address user) internal returns (uint256) {
    vm.prank(_owner);
    _profile.inviteAddress(user);
    vm.prank(user);
    _profile.createProfile(OWNER_PROFILE_ID);
    return _profile.verifiedProfileIdForAddress(user);
  }

  /// @dev Mints a mock profile for `subject` — the tracking-only id EthosProfile issues when an
  ///      address is reviewed/attested but never joins. Pranks as the registered attestation
  ///      contract (a permitted caller of incrementProfileCount). A mock profile sets
  ///      profileIdByAddress[subject] but never populates its address array.
  function _mintMockProfileForAddress(address subject) internal returns (uint256 mockId) {
    vm.prank(address(_attestation));
    mockId = _profile.incrementProfileCount(false, subject, bytes32(0));
  }

  /// @dev Mints a mock profile keyed to an attestation hash — the tracking-only id EthosProfile
  ///      issues for an attestation whose subject has no profile. Sets profileIdByAttestation[hash]
  ///      but populates no address array. Hash matches MockEthosAttestation.getServiceAndAccountHash.
  function _mintMockProfileForAttestation(string memory service, string memory account)
    internal
    returns (uint256 mockId)
  {
    vm.prank(address(_attestation));
    mockId = _profile.incrementProfileCount(true, address(0), keccak256(abi.encode(service, account)));
  }

  /// @dev Registers a second address onto an existing profile. `profileOwner` must already
  ///      belong to `profileId`. Mirrors EthosProfile._keccakForRegisterAddress.
  function _registerAddress(address profileOwner, address newAddr, uint256 profileId) internal {
    _registerAddress(profileOwner, newAddr, profileId, uint256(keccak256(abi.encodePacked(newAddr, profileId))));
  }

  /// @dev Explicit-randValue overload. Each registration consumes a distinct signature, so the same
  ///      `(newAddr, profileId)` can be registered more than once — EthosProfile only rejects an
  ///      address already bound to a *different* profile — yielding a profile that lists the address
  ///      twice (the duplicate-snapshot case the freeze dedup defends against).
  function _registerAddress(address profileOwner, address newAddr, uint256 profileId, uint256 randValue) internal {
    bytes memory sig = _signHash(keccak256(abi.encodePacked(newAddr, profileId, randValue)));
    vm.prank(profileOwner);
    _profile.registerAddress(newAddr, profileId, randValue, sig);
  }

  /// @dev Links an attestation hash to `profileId` on the real EthosProfile by pranking as
  ///      the registered attestation contract. Returns the hash, which matches what
  ///      MockEthosAttestation.getServiceAndAccountHash produces for the same inputs.
  function _linkAttestationToProfile(string memory service, string memory account, uint256 profileId)
    internal
    returns (bytes32 attestationHash)
  {
    attestationHash = keccak256(abi.encode(service, account));
    vm.prank(address(_attestation));
    _profile.assignExistingProfileToAttestation(attestationHash, profileId);
  }

  // --- Signature helpers ---

  function _signHash(bytes32 messageHash) internal view returns (bytes memory) {
    return _signHashWithKey(messageHash, _signerPrivateKey);
  }

  /// @dev Like _signHash but with an arbitrary key — for negative signature tests.
  function _signHashWithKey(bytes32 messageHash, uint256 pk) internal pure returns (bytes memory) {
    bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(messageHash);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethSignedHash);
    return abi.encodePacked(r, s, v);
  }

  /// @dev Mirrors EthosSlash._keccakForCreateSlash. `authorProfileId` is the value the
  ///      contract derives from msg.sender via verifiedProfileIdForAddress.
  function _signCreateSlash(
    uint256 authorProfileId,
    uint256 randValue,
    uint256 deadline,
    address subject,
    uint256 amount,
    string memory comment,
    string memory metadata,
    AttestationDetails memory attestationDetails,
    EthosSlash.SlashType slashType
  ) internal view returns (bytes memory) {
    // authorMinBalance defaults to 0 (no floor) for the SCORE/XP and unfloored-FINANCIAL call sites.
    return _signCreateSlash(
      authorProfileId, randValue, deadline, subject, amount, comment, metadata, attestationDetails, slashType, 0
    );
  }

  /// @dev Balance-floor overload. Mirrors EthosSlash._keccakForCreateSlash with the
  ///      `authorMinBalance` field bound.
  function _signCreateSlash(
    uint256 authorProfileId,
    uint256 randValue,
    uint256 deadline,
    address subject,
    uint256 amount,
    string memory comment,
    string memory metadata,
    AttestationDetails memory attestationDetails,
    EthosSlash.SlashType slashType,
    uint256 authorMinBalance
  ) internal view returns (bytes memory) {
    return _signHash(
      keccak256(
        abi.encode(
          authorProfileId,
          randValue,
          deadline,
          subject,
          amount,
          comment,
          metadata,
          attestationDetails,
          slashType,
          authorMinBalance
        )
      )
    );
  }

  // --- Slash helpers ---

  function _emptyAttestation() internal pure returns (AttestationDetails memory) {
    return AttestationDetails({account: "", service: ""});
  }

  /// @dev Creates an address-keyed slash signed for `author`. Assumes `author` already
  ///      has a verified profile (call `_mintProfile` first).
  function _createSlashWithSig(
    address author,
    address subject,
    uint256 amount,
    string memory comment,
    string memory metadata,
    EthosSlash.SlashType slashType,
    uint256 randValue
  ) internal returns (uint256 slashId) {
    // Never-expiring default so positive call sites don't churn on expiry.
    return _createSlashWithSig(author, subject, amount, comment, metadata, slashType, randValue, NO_EXPIRY);
  }

  /// @dev Explicit-deadline overload for the expiry tests.
  function _createSlashWithSig(
    address author,
    address subject,
    uint256 amount,
    string memory comment,
    string memory metadata,
    EthosSlash.SlashType slashType,
    uint256 randValue,
    uint256 deadline
  ) internal returns (uint256 slashId) {
    uint256 authorProfileId = _profile.verifiedProfileIdForAddress(author);
    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory sig = _signCreateSlash(
      authorProfileId, randValue, deadline, subject, amount, comment, metadata, attestation, slashType
    );

    // slashCount is the id the create will assign (1-indexed, post-incremented).
    slashId = _slash.slashCount();
    vm.prank(author);
    _slash.createSlash(subject, amount, comment, metadata, attestation, slashType, deadline, randValue, 0, sig);
  }

  /// @dev Creates an address-keyed FINANCIAL slash signed for `author`. The author profile
  ///      (and the subject's profile, if any) get snapshotted + frozen in MockVouchV2.
  function _createFinancialSlash(address author, address subject, uint256 randValue)
    internal
    returns (uint256 slashId)
  {
    return _createSlashWithSig(author, subject, 0, "financial", "m", EthosSlash.SlashType.FINANCIAL, randValue);
  }

  /// @dev Creates an attestation-keyed FINANCIAL slash signed for `author`. The attestation's
  ///      linked profile (if any) and the author profile get snapshotted + frozen in MockVouchV2.
  function _createFinancialSlashByAttestation(
    address author,
    string memory service,
    string memory account,
    uint256 randValue
  ) internal returns (uint256 slashId) {
    uint256 authorProfileId = _profile.verifiedProfileIdForAddress(author);
    AttestationDetails memory attestation = AttestationDetails({account: account, service: service});
    bytes memory sig = _signCreateSlash(
      authorProfileId,
      randValue,
      NO_EXPIRY,
      address(0),
      0,
      "financial",
      "m",
      attestation,
      EthosSlash.SlashType.FINANCIAL
    );
    slashId = _slash.slashCount();
    vm.prank(author);
    _slash.createSlash(
      address(0), 0, "financial", "m", attestation, EthosSlash.SlashType.FINANCIAL, NO_EXPIRY, randValue, 0, sig
    );
  }

  /// @dev Mirrors EthosSlash._keccakForResolveSlash — binds the slash proxy address.
  function _signResolveSlash(uint256 slashId, EthosSlash.SlashResolution resolution, uint256 bps, uint256 nonce)
    internal
    view
    returns (bytes memory)
  {
    return _signHash(keccak256(abi.encode(address(_slash), slashId, resolution, bps, nonce)));
  }

  /// @dev Same payload as _signResolveSlash but signed by an arbitrary key — for bad-signer tests.
  function _signResolveSlashWithKey(
    uint256 slashId,
    EthosSlash.SlashResolution resolution,
    uint256 bps,
    uint256 nonce,
    uint256 pk
  ) internal view returns (bytes memory) {
    return _signHashWithKey(keccak256(abi.encode(address(_slash), slashId, resolution, bps, nonce)), pk);
  }

  /// @dev Signs and submits resolveSlash. Resolve is permissionless; only the signature must
  ///      come from the expected signer, so the caller here is irrelevant.
  function _resolveSlash(uint256 slashId, EthosSlash.SlashResolution resolution, uint256 bps, uint256 nonce) internal {
    bytes memory sig = _signResolveSlash(slashId, resolution, bps, nonce);
    _slash.resolveSlash(slashId, resolution, bps, nonce, sig);
  }

  /// @dev Advances time just past the default duration so a slash becomes resolvable.
  function _warpPastDuration() internal {
    vm.warp(block.timestamp + _slash.defaultDuration() + 1);
  }

  /// @dev Points the ETHOS_VOUCH_V2 registration at `addr`. The test contract owns the CAM,
  ///      so no prank is needed. Pass address(0) to deregister.
  function _setVouchV2(address addr) internal {
    address[] memory addrs = new address[](1);
    string[] memory names = new string[](1);
    addrs[0] = addr;
    names[0] = ETHOS_VOUCH_V2;
    _cam.updateContractAddressesForNames(addrs, names);
  }

  /// @dev Clears the ETHOS_VOUCH_V2 registration so EthosSlash._vouchV2() reverts
  ///      VouchV2NotRegistered.
  function _deregisterVouchV2() internal {
    _setVouchV2(address(0));
  }

  // --- Pause helpers ---

  function _pauseSlash() internal {
    _ic.pauseContract(ETHOS_SLASH);
  }

  function _unpauseSlash() internal {
    _ic.unpauseContract(ETHOS_SLASH);
  }
}
