// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ITargetStatus} from "../interfaces/ITargetStatus.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {
  ReentrancyGuardTransientUpgradeable
} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardTransientUpgradeable.sol";
import {AccessControl} from "../utils/AccessControl.sol";
import {IEthosProfile} from "../interfaces/IEthosProfile.sol";
import {IEthosVouchV2Slashable} from "../interfaces/IEthosVouchV2Slashable.sol";
import {ETHOS_PROFILE, ETHOS_ATTESTATION, ETHOS_VOUCH_V2} from "../utils/Constants.sol";
import {IEthosAttestation} from "../interfaces/IEthosAttestation.sol";
import {AttestationDetails} from "../utils/Structs.sol";

contract EthosSlash is ITargetStatus, AccessControl, UUPSUpgradeable, ReentrancyGuardTransientUpgradeable {
  error InvalidSlashDetails(string reason);
  error SelfSlash(address subject);
  error SlashNotFound(uint256 slashId);
  error SlashIsCancelled(uint256 slashId);
  error SlashIsClosed(uint256 slashId);
  error InvalidDuration(uint256 slashId, uint256 newDuration);
  error NotSlashAuthor(uint256 slashId, address caller);
  error EditWindowExpired(uint256 slashId);
  error InvalidEditWindow(uint256 newEditWindow);
  error CancelWindowExpired(uint256 slashId);
  error InvalidCancelWindow(uint256 newCancelWindow);
  error InvalidDefaultDuration(uint256 newDefaultDuration);
  error WindowNotBelowDuration(uint256 window, uint256 duration);
  error SignatureExpired(uint256 deadline, uint256 blockTimestamp);
  error AuthorHasOpenSlash(uint256 lastSlashId);
  error SubjectHasOpenSlash(uint256 lastSlashId);
  error SlashTypeNotFinancial(uint256 slashId);
  error SlashDurationNotElapsed(uint256 slashId);
  error AlreadyResolved(uint256 slashId, SlashResolution current);
  error InvalidResolution(SlashResolution attempted);
  error BpsTooHigh(uint256 bps);
  error MaxOpsZero();
  error ResolutionPending(uint256 slashId);
  error VouchV2NotRegistered();
  error NoSubjectToSlash(uint256 slashId);
  error AuthorBalanceBelowFloor(uint256 liveBalance, uint256 authorMinBalance);

  uint256 public defaultDuration;
  // Read live by isEditable()/isCancellable(), not snapshotted per slash, so changing a setter
  // retroactively re-times every open slash. Intentional.
  uint256 public editWindow;
  uint256 public cancelWindow;

  /**
   * @dev Constructor that disables initializers when the implementation contract is deployed.
   * This prevents the implementation contract from being initialized, which is important for
   * security since the implementation contract should never be used directly, only through
   * delegatecall from the proxy.
   */
  constructor() {
    _disableInitializers();
  }

  /**
   * @dev Type of slash penalty
   * SCORE: Affects credibility score only
   * FINANCIAL: Involves financial penalties
   * XP: Affects XP balance
   */
  enum SlashType {
    SCORE,
    FINANCIAL,
    XP
  }

  /**
   * @dev Terminal state of a FINANCIAL slash. Element 0 MUST be PENDING so that
   *      unwritten storage slots default to "not resolved" rather than to a real
   *      terminal value.
   *
   * PENDING:      financial slash recorded, not yet resolved or cancelled.
   * CANCELLED:    closed early via cancelSlash within cancelWindow. No burn.
   * SLASHED:      vote upheld; subject's vouches are burned for `bps`.
   * DEFENDED:     vote rejected; slash author's vouches are burned for `bps`.
   * INCONCLUSIVE: no decisive outcome; no burn.
   *
   * All four non-PENDING resolutions unfreeze both snapshot sets via executeResolution.
   */
  enum SlashResolution {
    PENDING,
    CANCELLED,
    SLASHED,
    DEFENDED,
    INCONCLUSIVE
  }

  /**
   * @dev Structure containing all slash details
   * @param id Unique, incremental identifier for the slash (non-zero)
   * @param createdAt Timestamp when slash was created
   * @param duration How long the slash remains active
   * @param subject Address being slashed (if slashing by address)
   * @param authorProfileId Profile ID of the slash creator
   * @param cancelledAt Timestamp when slash was cancelled (if applicable)
   * @param amount Severity/amount of the slash
   * @param slashType Type of penalty (SCORE, FINANCIAL, or XP)
   * @param comment Description of why the slash was created
   * @param metadata Additional data about the slash
   * @param attestationDetails Details about attestation (if slashing by attestation)
   */
  struct Slash {
    uint256 id; // id may not be 0
    uint256 createdAt;
    uint256 duration;
    address subject;
    uint256 authorProfileId;
    uint256 cancelledAt;
    uint256 amount;
    SlashType slashType;
    string comment;
    string metadata;
    AttestationDetails attestationDetails;
  }

  /**
   * @dev Per-slash FINANCIAL state, populated at createSlash time when slashType == FINANCIAL.
   *      Trimmed to the load-bearing minimum; observational state lives in events.
   * @param slashSubjectAddrs Subject profile's address snapshot. Popped by executeResolution.
   * @param slashAuthorAddrs  Slash author profile's address snapshot. Popped by executeResolution.
   * @param resolution PENDING until cancelled or resolved.
   * @param bps Burn percentage; 0 for CANCELLED / INCONCLUSIVE. uint16 packs with `resolution`.
   * @param executedAt Block timestamp of the executeResolution call that drained the last
   *                   snapshot address. 0 until that moment. Used to gate ResolutionExecuted
   *                   re-emission on repeat executeResolution calls past drain.
   */
  struct FinancialSlash {
    address[] slashSubjectAddrs;
    address[] slashAuthorAddrs;
    SlashResolution resolution;
    uint16 bps;
    uint64 executedAt;
  }

  event SlashCreated(
    uint256 id,
    uint256 createdAt,
    uint256 duration,
    address indexed subject,
    bytes32 indexed attestationHash,
    uint256 authorProfileId,
    uint256 cancelledAt,
    uint256 amount,
    SlashType slashType,
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
  event SlashResolved(uint256 indexed id, SlashResolution indexed resolution, uint256 bps);
  event ResolutionExecuted(uint256 indexed id);

  uint256 public slashCount;
  mapping(uint256 => Slash) public slashes;
  // Concurrent-slash cap: at most one open slash per subject and per author. Each key maps to the
  // last slash created against it; createSlash reverts while the pointed-to slash isOpen. Slots are
  // never cleared — a cancelled or duration-expired slash (!isOpen) frees its slot lazily on the
  // next create. Subjects are keyed by both profile and submitted identifier (address / attestation
  // hash) so the same person can't be double-slashed via a sibling wallet or attestation.
  mapping(uint256 => uint256) public lastSlashIdByAuthorProfile;
  mapping(uint256 => uint256) public lastSlashIdBySubjectProfile;
  mapping(address => uint256) public lastSlashIdBySubjectAddress;
  mapping(bytes32 => uint256) public lastSlashIdBySubjectAttestationHash;
  // Per-slash FINANCIAL state. Read via the financialSlash(slashId) view.
  mapping(uint256 => FinancialSlash) private _financialSlashes;
  // Basis-point denominator; 10_000 = 100%.
  uint256 public constant BASIS_POINT_SCALE = 10_000;
  // Maximum burn percentage a single resolve can apply (1_000 = 10%). resolveSlash rejects any
  // higher bps. Fixed constant, not admin-settable.
  uint256 public constant MAX_SLASH_BPS = 1_000;
  // extendSlash ceiling; setDefaultDuration is intentionally uncapped.
  uint256 public constant MAX_SLASH_DURATION = 7 days;
  // How many live FINANCIAL slashes currently hold each address frozen. EthosSlash drives every
  // VouchV2 freeze/unfreeze, so it gates those calls on this counter (freeze on the 0->1 edge,
  // unfreeze on the 1->0 edge) and an address stays frozen while any slash still holds it — an
  // invariant the boolean VouchV2 flag can't express on its own.
  mapping(address => uint256) private _freezeRefCount;
  // Add storage gap as the last storage variable
  // This allows us to add new storage variables in future upgrades
  // by reducing the size of this gap
  uint256[44] private __gap;

  /**
   * @dev Parameters used for creating a new slash
   * @param authorProfileId Profile ID of the slash creator
   * @param randValue Random value for signature uniqueness
   * @param deadline Unix timestamp (seconds) after which the signature is no longer valid
   * @param subject Address being slashed
   * @param amount Severity/amount of the slash
   * @param comment Description of why the slash was created
   * @param metadata Additional data about the slash
   * @param attestationDetails Details about attestation
   * @param slashType Type of penalty (SCORE, FINANCIAL, or XP)
   * @param authorMinBalance Minimum active vouch balance the author must still hold at execution
   *        for a FINANCIAL slash; 0 means no floor. Bound in the signature so it can't be lowered.
   */
  struct CreateSlashParams {
    uint256 authorProfileId;
    uint256 randValue;
    uint256 deadline;
    address subject;
    uint256 amount;
    string comment;
    string metadata;
    AttestationDetails attestationDetails;
    SlashType slashType;
    uint256 authorMinBalance;
  }

  /**
   * @dev Resolved subject identifiers for the concurrent-slash cap. `profileId` is 0 when the
   *      submitted identifier doesn't resolve to a verified profile. Exactly one of `subjectAddress`
   *      and `attestationHash` is set, mirroring the address-or-attestation invariant enforced by
   *      `_validateSlashDetails`.
   * @param profileId Resolved subject profile id (0 if none).
   * @param subjectAddress Bare-address key (address(0) for attestation-keyed slashes).
   * @param attestationHash Attestation-hash key (bytes32(0) for address-keyed slashes).
   */
  struct SubjectKeys {
    uint256 profileId;
    address subjectAddress;
    bytes32 attestationHash;
  }

  /**
   * @dev Initializer function, called once when the contract is first deployed.
   * @param _owner Owner address.
   * @param _admin Admin address.
   * @param _expectedSigner ExpectedSigner address.
   * @param _signatureVerifier SignatureVerifier address.
   * @param _contractAddressManagerAddr ContractAddressManager address.
   */
  function initialize(
    address _owner,
    address _admin,
    address _expectedSigner,
    address _signatureVerifier,
    address _contractAddressManagerAddr
  ) external initializer {
    __accessControl_init(_owner, _admin, _expectedSigner, _signatureVerifier, _contractAddressManagerAddr);
    __UUPSUpgradeable_init();
    __ReentrancyGuardTransient_init();
    slashCount = 1; // Initialize slashCount to 1 since 0 indicates non-existent slash
    defaultDuration = 48 hours;
    editWindow = 1 hours;
    cancelWindow = 1 hours;
  }

  /**
   * @notice One-shot re-initializer for proxies upgraded from a version that pre-dates
   *         `ReentrancyGuardTransientUpgradeable` in the inheritance chain. The guard uses
   *         transient storage (no persistent slot), so calling this carries no runtime effect on
   *         the guard — `nonReentrant` works whether or not it ever runs. Its only effect is
   *         advancing the OZ `reinitializer` slot to 2 (locking out a future colliding reinit) and
   *         matching OZ's canonical init chain. Call it standalone or bundle it into the
   *         `upgradeToAndCall` for the upgrade; skipping it leaves the guard fully functional.
   */
  function reinitV2ReentrancyGuard() external onlyOwner reinitializer(2) {
    __ReentrancyGuardTransient_init();
  }

  /**
   * @notice restricts upgrading to owner
   * @param newImplementation address of new implementation contract
   */
  function _authorizeUpgrade(address newImplementation)
    internal
    override
    onlyOwner
    onlyNonZeroAddress(newImplementation)
  {
    // Intentionally left blank to ensure onlyOwner and zeroCheck modifiers run
  }

  /**
   * @dev Checks if a slash is currently open (not cancelled and within duration)
   * @param slashId The ID of the slash to check
   * @return bool True if the slash exists and is open, false otherwise
   */
  function isOpen(uint256 slashId) public view returns (bool) {
    if (slashId == 0 || slashId >= slashCount) return false;
    Slash storage slash = slashes[slashId];
    if (slash.cancelledAt > 0) return false;
    return slash.createdAt + slash.duration > block.timestamp;
  }

  /**
   * @dev Checks if a slash is closed (doesn't exist, cancelled, or past duration)
   * @param slashId The ID of the slash to check
   * @return bool True if the slash doesn't exist or is closed, false if it's open
   */
  function isClosed(uint256 slashId) public view returns (bool) {
    // a slash that doesn't exist is not open or closed
    if (slashId == 0 || slashId >= slashCount) return false;
    Slash storage slash = slashes[slashId];
    if (slash.cancelledAt > 0) return true;
    if (slash.createdAt + slash.duration <= block.timestamp) return true;
    return false;
  }

  /**
   * @dev Checks if a slash can currently be edited by its author.
   * A slash is editable if:
   * - It exists
   * - It is not cancelled
   * - It is within the edit window from creation time
   * - It has not expired (is still open)
   * @param slashId The ID of the slash to check
   * @return bool True if the slash can be edited, false otherwise
   */
  function isEditable(uint256 slashId) public view returns (bool) {
    if (isClosed(slashId)) return false;
    Slash storage slash = slashes[slashId];
    return block.timestamp <= slash.createdAt + editWindow;
  }

  /**
   * @dev Checks if a slash can currently be cancelled by its author or an admin.
   * A slash is cancellable if:
   * - It exists
   * - It has not already been cancelled
   * - It has not expired (is still open)
   * - For non-admins: It is within the cancel window from creation time
   * Note: Admins can cancel any open slash regardless of the cancel window.
   * @param slashId The ID of the slash to check
   * @param isAdmin Whether the caller is an admin
   * @return bool True if the slash can be cancelled by the specified caller type
   */
  function isCancellable(uint256 slashId, bool isAdmin) public view returns (bool) {
    if (slashId == 0 || slashId >= slashCount) return false;
    if (isClosed(slashId)) return false;
    if (isAdmin) return true;
    Slash storage slash = slashes[slashId];
    return block.timestamp <= slash.createdAt + cancelWindow;
  }

  /**
   * @dev Implementation of ITargetStatus interface to check if a slash exists and is allowed for voting and replies
   * @param _targetId The ID of the slash to check
   * @return exists True if the slash exists
   * @return allowed True if voting is allowed on the slash (currently only if open)
   */
  function targetExistsAndAllowedForId(uint256 _targetId) external view override returns (bool exists, bool allowed) {
    Slash storage slash = slashes[_targetId];
    exists = slash.id != 0; // id 0 means non-existent slash
    allowed = exists && isOpen(_targetId);
    return (exists, allowed);
  }

  /**
   * @dev Creates a new slash with signature verification
   * @param subject The address being slashed (if slashing by address)
   * @param amount The amount/severity of the slash
   * @param comment A description of why the slash was created
   * @param metadata Additional metadata about the slash
   * @param attestationDetails Details about the attestation (if slashing by attestation)
   * @param slashType Type of penalty (SCORE, FINANCIAL, or XP)
   * @param deadline Unix timestamp (seconds) after which the signature is no longer valid
   * @param randValue Random value for signature uniqueness
   * @param authorMinBalance Minimum active vouch balance the author must still hold at execution
   *        for a FINANCIAL slash; 0 means no floor
   * @param signature Signature from authorized signer
   */
  function createSlash(
    address subject,
    uint256 amount,
    string memory comment,
    string memory metadata,
    AttestationDetails calldata attestationDetails,
    SlashType slashType,
    uint256 deadline,
    uint256 randValue,
    uint256 authorMinBalance,
    bytes calldata signature
  ) external whenNotPaused nonReentrant {
    uint256 authorProfileId = _ethosProfile().verifiedProfileIdForAddress(msg.sender);
    _validateSlashDetails(subject, attestationDetails);

    // `deadline == now` still passes (guard is strict `>`).
    if (block.timestamp > deadline) revert SignatureExpired(deadline, block.timestamp);

    SubjectKeys memory keys = _subjectKeys(subject, attestationDetails);

    CreateSlashParams memory params = CreateSlashParams({
      authorProfileId: authorProfileId,
      randValue: randValue,
      deadline: deadline,
      subject: subject,
      amount: amount,
      comment: comment,
      metadata: metadata,
      attestationDetails: attestationDetails,
      slashType: slashType,
      authorMinBalance: authorMinBalance
    });

    validateAndSaveSignature(_keccakForCreateSlash(params), signature);

    _assertNoOpenSlashes(authorProfileId, keys);

    _createSlashInternal(
      subject, amount, comment, metadata, attestationDetails, slashType, authorProfileId, authorMinBalance, keys
    );
  }

  /**
   * @dev Internal function to create a slash, invoked by createSlash after signature verification.
   * @param subject The address being slashed
   * @param amount The amount/severity of the slash
   * @param comment A description of why the slash was created
   * @param metadata Additional metadata about the slash
   * @param attestationDetails Details about the attestation
   * @param slashType Type of penalty (SCORE, FINANCIAL, or XP)
   * @param authorProfileId The profile ID of the slash author
   * @param keys Resolved subject identifiers used to claim the concurrent-slash cap slots
   */
  function _createSlashInternal(
    address subject,
    uint256 amount,
    string memory comment,
    string memory metadata,
    AttestationDetails memory attestationDetails,
    SlashType slashType,
    uint256 authorProfileId,
    uint256 authorMinBalance,
    SubjectKeys memory keys
  ) private {
    Slash memory slash = Slash({
      id: slashCount,
      createdAt: block.timestamp,
      duration: defaultDuration,
      subject: subject,
      authorProfileId: authorProfileId,
      cancelledAt: 0,
      amount: amount,
      slashType: slashType,
      comment: comment,
      metadata: metadata,
      attestationDetails: attestationDetails
    });
    slashes[slashCount] = slash;

    // Claim cap slots; pointers self-heal via isOpen() (see createSlash).
    lastSlashIdByAuthorProfile[authorProfileId] = slash.id;
    if (keys.profileId != 0) lastSlashIdBySubjectProfile[keys.profileId] = slash.id;
    if (keys.subjectAddress != address(0)) lastSlashIdBySubjectAddress[keys.subjectAddress] = slash.id;
    else lastSlashIdBySubjectAttestationHash[keys.attestationHash] = slash.id;

    emit SlashCreated(
      slash.id,
      slash.createdAt,
      slash.duration,
      slash.subject,
      keys.attestationHash,
      slash.authorProfileId,
      slash.cancelledAt,
      slash.amount,
      slash.slashType,
      slash.comment,
      slash.metadata
    );

    if (slashType == SlashType.FINANCIAL) {
      _recordFinancialSlash(slash.id, subject, keys.profileId, authorProfileId, authorMinBalance);
    }

    slashCount++;
  }

  /**
   * @dev Extends the duration of an existing slash
   * @param slashId The ID of the slash to extend
   * @param newDuration The new duration in seconds
   */
  function extendSlash(uint256 slashId, uint256 newDuration) external onlyAdmin whenNotPaused {
    Slash storage slash = slashes[slashId];
    if (slash.id == 0) revert SlashNotFound(slashId);
    _requirePendingIfFinancial(slash, slashId);
    if (slash.cancelledAt > 0) revert SlashIsCancelled(slashId);
    if (isClosed(slashId)) revert SlashIsClosed(slashId);
    if (newDuration <= slash.duration) revert InvalidDuration(slashId, newDuration);
    // Bound the extension so admin can't keep a slash (and its frozen snapshot) open indefinitely.
    if (newDuration > MAX_SLASH_DURATION) revert InvalidDuration(slashId, newDuration);
    slash.duration = newDuration;
    emit SlashExtended(slashId, newDuration);
  }

  /**
   * @dev Allows the slash author to edit the comment and metadata
   * note: only within the first hour of the slash
   * @param slashId The ID of the slash to edit
   * @param newComment The new comment text
   * @param newMetadata The new metadata
   */
  function editSlash(uint256 slashId, string memory newComment, string memory newMetadata) external whenNotPaused {
    Slash storage slash = slashes[slashId];
    if (slash.id == 0) revert SlashNotFound(slashId);
    _requirePendingIfFinancial(slash, slashId);
    if (!isEditable(slashId)) revert EditWindowExpired(slashId);
    _validateSlashAuthor(slash, slashId);

    slash.comment = newComment;
    slash.metadata = newMetadata;

    emit SlashEdited(slashId, newComment, newMetadata);
  }

  /**
   * @dev Update the edit window. Applies retroactively to open slashes (see editWindow declaration).
   * @param newEditWindow The new edit window duration in seconds
   */
  function setEditWindow(uint256 newEditWindow) external onlyAdmin whenNotPaused {
    if (newEditWindow == 0) revert InvalidEditWindow(newEditWindow);
    // Window must stay below the slash's duration (same guard in setCancelWindow / setDefaultDuration).
    if (newEditWindow >= defaultDuration) revert WindowNotBelowDuration(newEditWindow, defaultDuration);
    editWindow = newEditWindow;
    emit EditWindowUpdated(newEditWindow);
  }

  /**
   * @dev Cancels an existing slash. Can be called by the author or an admin
   * @param slashId The ID of the slash to cancel
   */
  function cancelSlash(uint256 slashId) external whenNotPaused {
    Slash storage slash = slashes[slashId];
    if (slash.id == 0) revert SlashNotFound(slashId);

    bool isAdmin = hasRole(ADMIN_ROLE, msg.sender);
    if (!isCancellable(slashId, isAdmin)) {
      if (slash.cancelledAt > 0) revert SlashIsCancelled(slashId);
      if (isClosed(slashId)) revert SlashIsClosed(slashId);
      revert CancelWindowExpired(slashId);
    }

    // Allow either the original author or an admin to cancel
    if (!isAdmin) {
      _validateSlashAuthor(slash, slashId);
    }

    slash.cancelledAt = block.timestamp;

    emit SlashCancelled(slashId, msg.sender, block.timestamp);

    // FINANCIAL slashes also record the resolution so executeResolution can
    // run the unfreeze fanout. SCORE/XP slashes have no snapshot to unwind.
    if (slash.slashType == SlashType.FINANCIAL) {
      FinancialSlash storage fs = _financialSlashes[slashId];

      if (fs.resolution != SlashResolution.PENDING) revert AlreadyResolved(slashId, fs.resolution);

      fs.resolution = SlashResolution.CANCELLED;

      emit SlashResolved(slashId, SlashResolution.CANCELLED, 0);
    }
  }

  /**
   * @notice Records the resolution of a FINANCIAL slash. Time-gated to `t >= duration`.
   *         The on-chain fanout happens later via `executeResolution`.
   * @dev `resolution` must be SLASHED, DEFENDED, or INCONCLUSIVE.
   *      CANCELLED is reachable only via `cancelSlash`.
   * @param slashId    Slash id to resolve.
   * @param resolution Terminal resolution; one of SLASHED, DEFENDED, INCONCLUSIVE.
   * @param bps        Burn percentage in basis points. Validated `<= MAX_SLASH_BPS` for
   *                   all resolutions; stored as 0 for INCONCLUSIVE regardless of input.
   * @param nonce      Nonce for signature uniqueness across retries with different payloads.
   * @param signature  Signature from `expectedSigner` over the resolve payload.
   */
  function resolveSlash(
    uint256 slashId,
    SlashResolution resolution,
    uint256 bps,
    uint256 nonce,
    bytes calldata signature
  ) external whenNotPaused {
    Slash storage slash = slashes[slashId];

    if (slash.id == 0) revert SlashNotFound(slashId);
    if (slash.slashType != SlashType.FINANCIAL) revert SlashTypeNotFinancial(slashId);
    if (block.timestamp < slash.createdAt + slash.duration) revert SlashDurationNotElapsed(slashId);

    FinancialSlash storage fs = _financialSlashes[slashId];
    if (fs.resolution != SlashResolution.PENDING) revert AlreadyResolved(slashId, fs.resolution);

    // resolveSlash explicitly cannot land CANCELLED (cancelSlash's job) or PENDING (the sentinel).
    if (resolution == SlashResolution.PENDING || resolution == SlashResolution.CANCELLED) {
      revert InvalidResolution(resolution);
    }
    if (bps > MAX_SLASH_BPS) revert BpsTooHigh(bps);

    validateAndSaveSignature(_keccakForResolveSlash(slashId, resolution, bps, nonce), signature);

    fs.resolution = resolution;
    // INCONCLUSIVE doesn't burn; force bps to 0 for storage consistency.
    fs.bps = (resolution == SlashResolution.INCONCLUSIVE) ? 0 : uint16(bps);

    emit SlashResolved(slashId, resolution, fs.bps);
  }

  /**
   * @notice Drains the FINANCIAL slash's snapshot in chunks of up to `maxOps` addresses.
   *         For each address: pops it first (checks-effects-interactions), then calls
   *         `VouchV2.slash` (if the outcome's burn-direction matches the side) and unfreezes it.
   *
   * @dev Permissionless. Pop-before-process: each address is removed from the snapshot before
   *      the external calls, and a revert rolls the pop back with the rest of the tx, so
   *      VouchV2.slash runs at most once per address per resolution. Unfreeze is refcount-gated
   *      (fires only on the 1->0 edge). Drains slashSubjectAddrs then slashAuthorAddrs.
   *      Emits ResolutionExecuted exactly once (gated by the executedAt sentinel).
   * @param slashId Slash id whose snapshot to drain.
   * @param maxOps  Upper bound on per-address ops in this call. Must be > 0.
   */
  function executeResolution(uint256 slashId, uint256 maxOps) external whenNotPaused nonReentrant {
    if (maxOps == 0) revert MaxOpsZero();
    Slash storage slash = slashes[slashId];
    if (slash.id == 0) revert SlashNotFound(slashId);
    if (slash.slashType != SlashType.FINANCIAL) revert SlashTypeNotFinancial(slashId);

    FinancialSlash storage fs = _financialSlashes[slashId];
    if (fs.resolution == SlashResolution.PENDING) revert ResolutionPending(slashId);

    IEthosVouchV2Slashable vouch = _vouchV2();
    uint256 ops;
    uint256 bps = uint256(fs.bps);
    bool burnSubject = (fs.resolution == SlashResolution.SLASHED);
    bool burnAuthor = (fs.resolution == SlashResolution.DEFENDED);

    while (ops < maxOps && fs.slashSubjectAddrs.length > 0) {
      address addr = fs.slashSubjectAddrs[fs.slashSubjectAddrs.length - 1];
      // Pop before the external calls (checks-effects-interactions). The pop rolls back with the
      // rest of the tx on revert, so each address is still processed at most once per resolution.
      fs.slashSubjectAddrs.pop();
      if (burnSubject && bps > 0) {
        vouch.slash(addr, bps);
      }
      _unfreezeAddress(vouch, addr);
      ops++;
    }

    while (ops < maxOps && fs.slashAuthorAddrs.length > 0) {
      address addr = fs.slashAuthorAddrs[fs.slashAuthorAddrs.length - 1];
      fs.slashAuthorAddrs.pop();
      if (burnAuthor && bps > 0) {
        vouch.slash(addr, bps);
      }
      _unfreezeAddress(vouch, addr);
      ops++;
    }

    if (fs.slashSubjectAddrs.length == 0 && fs.slashAuthorAddrs.length == 0 && fs.executedAt == 0) {
      fs.executedAt = uint64(block.timestamp);
      emit ResolutionExecuted(slashId);
    }
  }

  /**
   * @notice Returns the FINANCIAL state for a slash. Zero struct for non-FINANCIAL slashes.
   * @param slashId Slash id.
   */
  function financialSlash(uint256 slashId) external view returns (FinancialSlash memory fs) {
    return _financialSlashes[slashId];
  }

  /**
   * @dev Update the cancel window. Applies retroactively to open slashes (see cancelWindow declaration).
   * @param newCancelWindow The new cancel window duration in seconds
   */
  function setCancelWindow(uint256 newCancelWindow) external onlyAdmin whenNotPaused {
    if (newCancelWindow == 0) revert InvalidCancelWindow(newCancelWindow);
    if (newCancelWindow >= defaultDuration) revert WindowNotBelowDuration(newCancelWindow, defaultDuration);
    cancelWindow = newCancelWindow;
    emit CancelWindowUpdated(newCancelWindow);
  }

  /**
   * @dev Allows admin to update the default duration for new slashes
   * @param newDefaultDuration The new default duration in seconds
   */
  function setDefaultDuration(uint256 newDefaultDuration) external onlyAdmin whenNotPaused {
    if (newDefaultDuration == 0) revert InvalidDefaultDuration(newDefaultDuration);
    // Reject a duration at or below either window, so a slash created at this duration keeps its
    // edit and cancel windows inside its lifetime.
    if (newDefaultDuration <= cancelWindow) revert WindowNotBelowDuration(cancelWindow, newDefaultDuration);
    if (newDefaultDuration <= editWindow) revert WindowNotBelowDuration(editWindow, newDefaultDuration);
    defaultDuration = newDefaultDuration;
    emit DefaultDurationUpdated(newDefaultDuration);
  }

  /**
   * @dev Internal function to get the EthosProfile contract
   * @return IEthosProfile The EthosProfile contract interface
   */
  function _ethosProfile() internal view returns (IEthosProfile) {
    return IEthosProfile(contractAddressManager.getContractAddressForName(ETHOS_PROFILE));
  }

  /**
   * @dev Internal function to get the EthosAttestation contract
   * @return IEthosAttestation The EthosAttestation contract interface
   */
  function _ethosAttestation() internal view returns (IEthosAttestation) {
    return IEthosAttestation(contractAddressManager.getContractAddressForName(ETHOS_ATTESTATION));
  }

  /**
   * @dev Resolves the EthosVouchV2 contract address per-call via ContractAddressManager.
   *      Reverts if the name isn't registered. Caller's downstream freeze/unfreeze/slash
   *      calls will additionally revert via VouchV2.onlySlasher if this proxy isn't
   *      registered as SLASHER.
   */
  function _vouchV2() internal view returns (IEthosVouchV2Slashable) {
    address addr = contractAddressManager.getContractAddressForName(ETHOS_VOUCH_V2);
    if (addr == address(0)) revert VouchV2NotRegistered();
    return IEthosVouchV2Slashable(addr);
  }

  /**
   * @dev FINANCIAL branch of _createSlashInternal: snapshots the subject's and author's
   *      vouch-author addresses and freezes each in VouchV2.
   *
   *      Subject snapshot has three cases:
   *      - subject resolves to a real profile -> snapshot every registered address of that profile.
   *      - bare address with no real profile -> snapshot just that address. VouchV2 vouches are
   *        authored by addresses, not profiles, so an address with no profile (or only a mock
   *        profile, which carries no address array) can still hold a slashable vouch balance.
   *      - attestation with no real profile -> no addresses to freeze; reverts NoSubjectToSlash
   *        (an attestation is not a vouch author, so the subject side could never be burned).
   */
  function _recordFinancialSlash(
    uint256 slashId,
    address subject,
    uint256 subjectProfileId,
    uint256 authorProfileId,
    uint256 authorMinBalance
  ) private {
    FinancialSlash storage fs = _financialSlashes[slashId];

    uint256 subjectCount;
    // A mock profileId is non-zero but carries no address array, so addressesForProfile would
    // freeze nothing; fall through to the bare-address branch to freeze the address directly.
    if (subjectProfileId != 0 && !_isMockProfile(subjectProfileId)) {
      subjectCount = _snapshotAndFreeze(fs.slashSubjectAddrs, subjectProfileId);
    } else if (subject != address(0)) {
      fs.slashSubjectAddrs.push(subject);
      _freezeAddress(_vouchV2(), subject);
      subjectCount = 1;
    }
    // With no subject addresses (e.g. an attestation with no linked profile) the slash could only
    // ever burn the author's own balance on DEFENDED while never touching the target. Reject it at
    // create rather than record a financial slash that can only lose the author money.
    if (subjectCount == 0) revert NoSubjectToSlash(slashId);

    // Author side: snapshot only when an author profile is present.
    uint256 authorCount;
    if (authorProfileId != 0) {
      authorCount = _snapshotAndFreeze(fs.slashAuthorAddrs, authorProfileId);
      // Close the sign->create TOCTOU: the author must still hold the active vouch balance Echo
      // bound at sign time. The freeze above is already applied, so the read is over the same
      // frozen set the DEFENDED burn drains, and any unvouch/deleteAddress done after signing
      // shows up here as a shortfall.
      _requireAuthorBalance(fs.slashAuthorAddrs, authorMinBalance);
    }

    emit FinancialSlashCreated(slashId, subjectProfileId, authorProfileId, subjectCount, authorCount);
  }

  /**
   * @dev Reverts unless the author's live active vouch balance, summed over the frozen author
   *      snapshot, is at least `authorMinBalance`. `authorMinBalance == 0` is "no floor bound" and
   *      returns immediately. Sums VouchV2.activeBalanceOf per address with a cross-address early
   *      exit (no slack): the moment the running total clears the floor it stops, so an author
   *      holding well above the floor pays only a few reads. The full per-address scan is paid
   *      only by an author sitting right at the floor — on their own createSlash.
   */
  function _requireAuthorBalance(address[] storage authorAddrs, uint256 authorMinBalance) private view {
    if (authorMinBalance == 0) return;
    IEthosVouchV2Slashable vouch = _vouchV2();
    uint256 total;
    uint256 len = authorAddrs.length;
    for (uint256 i = 0; i < len; i++) {
      total += vouch.activeBalanceOf(authorAddrs[i]);
      if (total >= authorMinBalance) return;
    }
    revert AuthorBalanceBelowFloor(total, authorMinBalance);
  }

  /**
   * @dev True if `profileId` is a mock profile (a tracking-only id minted for reviews or
   *      attestations on a subject that never joined; it has no registered address array).
   */
  function _isMockProfile(uint256 profileId) private view returns (bool) {
    (,, bool mock) = _ethosProfile().profileStatusById(profileId);
    return mock;
  }

  /**
   * @dev Reads the profile's current registered addresses, pushes each into the storage
   *      snapshot array, and freezes each in VouchV2. Returns the number of addresses processed.
   */
  function _snapshotAndFreeze(address[] storage snapshotArray, uint256 profileId) private returns (uint256) {
    address[] memory addrs = _ethosProfile().addressesForProfile(profileId);
    IEthosVouchV2Slashable vouch = _vouchV2();
    uint256 frozen;
    for (uint256 i = 0; i < addrs.length; i++) {
      address addr = addrs[i];
      // A profile can list the same address more than once; snapshot and freeze it once.
      if (_seenEarlier(addrs, i, addr)) continue;
      snapshotArray.push(addr);
      _freezeAddress(vouch, addr);
      frozen++;
    }
    return frozen;
  }

  /**
   * @dev True if `addr` already appears in `addrs[0..upTo)`. Used to dedupe a profile's address
   *      list so each address is frozen, burned, and unfrozen exactly once per slash.
   */
  function _seenEarlier(address[] memory addrs, uint256 upTo, address addr) private pure returns (bool) {
    for (uint256 j = 0; j < upTo; j++) {
      if (addrs[j] == addr) return true;
    }
    return false;
  }

  /**
   * @dev Freezes `addr` in VouchV2 on the 0->1 refcount edge only, so overlapping slashes share
   *      a single freeze and the address stays frozen until the last holder unfreezes it.
   */
  function _freezeAddress(IEthosVouchV2Slashable vouch, address addr) private {
    if (_freezeRefCount[addr]++ == 0) {
      vouch.freeze(addr);
    }
  }

  /**
   * @dev Unfreezes `addr` in VouchV2 on the 1->0 refcount edge only. The decrement cannot
   *      underflow: every snapshot address was frozen once by its own slash, so its refcount is
   *      at least 1 when executeResolution pops it here.
   */
  function _unfreezeAddress(IEthosVouchV2Slashable vouch, address addr) private {
    if (--_freezeRefCount[addr] == 0) {
      vouch.unfreeze(addr);
    }
  }

  /**
   * @dev keccak256 payload for resolveSlash. `address(this)` binding defends against
   *      cross-deployment replay (asymmetric with `_keccakForCreateSlash`).
   */
  function _keccakForResolveSlash(uint256 slashId, SlashResolution resolution, uint256 bps, uint256 nonce)
    private
    view
    returns (bytes32)
  {
    return keccak256(abi.encode(address(this), slashId, resolution, bps, nonce));
  }

  /**
   * @dev Validates that the caller is the author of the slash
   * @param slash The slash to validate
   * @param slashId The ID of the slash (for error reporting)
   */
  function _validateSlashAuthor(Slash storage slash, uint256 slashId) private view {
    uint256 callerProfileId = _ethosProfile().profileIdByAddress(msg.sender);
    if (callerProfileId != slash.authorProfileId) {
      revert NotSlashAuthor(slashId, msg.sender);
    }
  }

  /**
   * @dev Reverts if `slash` is a resolved FINANCIAL slash. SCORE/XP slashes carry no
   *      resolution and pass through. Keeps editSlash/extendSlash off terminal slashes
   *      directly, rather than relying on the duration-based isClosed/isEditable gates.
   */
  function _requirePendingIfFinancial(Slash storage slash, uint256 slashId) private view {
    if (slash.slashType != SlashType.FINANCIAL) return;
    SlashResolution resolution = _financialSlashes[slashId].resolution;
    if (resolution != SlashResolution.PENDING) revert AlreadyResolved(slashId, resolution);
  }

  /**
   * @dev Validates that either subject OR attestation is set, not both
   * @param subject Subject address
   * @param attestationDetails Attestation details
   */
  function _validateSlashDetails(address subject, AttestationDetails calldata attestationDetails) private view {
    _validateSubjectOrAttestationSet(subject, attestationDetails);
    _validateNotSelfSlash(subject, attestationDetails);
  }

  /**
   * @dev Validates that exactly one of subject or attestation is set
   */
  function _validateSubjectOrAttestationSet(address subject, AttestationDetails calldata attestationDetails)
    private
    pure
  {
    bool hasSubject = subject != address(0);
    bool hasAttestation = bytes(attestationDetails.account).length != 0 || bytes(attestationDetails.service).length != 0;

    if (!hasSubject && !hasAttestation) {
      revert InvalidSlashDetails("None set");
    }

    if (hasSubject && hasAttestation) {
      revert InvalidSlashDetails("Both set");
    }
  }

  /**
   * @dev Validates that the slash author is not slashing themselves
   */
  function _validateNotSelfSlash(address subject, AttestationDetails calldata attestationDetails) private view {
    // Direct address self-slash check
    if (subject == msg.sender) {
      revert SelfSlash(subject);
    }

    uint256 authorProfileId = _ethosProfile().profileIdByAddress(msg.sender);

    if (subject != address(0)) {
      _validateNotSameProfile(subject, authorProfileId);
    } else {
      _validateNotSameAttestationProfile(attestationDetails, authorProfileId);
    }
  }

  /**
   * @dev Validates that the subject's profile is not the same as the author's
   */
  function _validateNotSameProfile(address subject, uint256 authorProfileId) private view {
    uint256 subjectProfileId = _ethosProfile().profileIdByAddress(subject);
    if (authorProfileId == subjectProfileId) {
      revert SelfSlash(subject);
    }
  }

  /**
   * @dev Validates that the attestation's profile is not the same as the author's
   */
  function _validateNotSameAttestationProfile(AttestationDetails calldata attestationDetails, uint256 authorProfileId)
    private
    view
  {
    bytes32 attestationHash =
      _ethosAttestation().getServiceAndAccountHash(attestationDetails.service, attestationDetails.account);
    uint256 subjectProfileId = _ethosProfile().profileIdByAttestation(attestationHash);
    if (authorProfileId == subjectProfileId) {
      revert SelfSlash(address(0));
    }
  }

  /**
   * @dev keccak256 payload for createSlash signature verification. Does not bind
   *      `address(this)`; only the fund-moving resolveSlash payload binds it, for
   *      cross-deployment replay defense (see `_keccakForResolveSlash`).
   */
  function _keccakForCreateSlash(CreateSlashParams memory params) private pure returns (bytes32) {
    return keccak256(
      abi.encode(
        params.authorProfileId,
        params.randValue,
        params.deadline,
        params.subject,
        params.amount,
        params.comment,
        params.metadata,
        params.attestationDetails,
        params.slashType,
        params.authorMinBalance
      )
    );
  }

  /**
   * @dev Resolves a subject to its concurrent-slash-cap keys. Uses the non-reverting
   *      profileIdByAddress / profileIdByAttestation — a subject need not be a verified profile.
   * @param subject The address being slashed (address(0) when slashing by attestation).
   * @param attestationDetails Attestation service/account (zero values when slashing by address).
   * @return keys Resolved (profileId, subjectAddress, attestationHash) — exactly one of
   *         subjectAddress / attestationHash is non-zero; profileId is 0 if unresolved.
   */
  function _subjectKeys(address subject, AttestationDetails calldata attestationDetails)
    private
    view
    returns (SubjectKeys memory keys)
  {
    if (subject != address(0)) {
      keys.subjectAddress = subject;
      keys.profileId = _ethosProfile().profileIdByAddress(subject);
    } else {
      keys.attestationHash =
        _ethosAttestation().getServiceAndAccountHash(attestationDetails.service, attestationDetails.account);
      keys.profileId = _ethosProfile().profileIdByAttestation(keys.attestationHash);
    }
  }

  /**
   * @dev Reverts if the author profile or the subject (by any resolved key) already has an open
   *      slash. Self-healing: a cancelled or duration-expired slash (!isOpen) frees its slot
   *      lazily on the next create — slots are never explicitly cleared. `isOpen` short-circuits
   *      on slashId == 0, so empty slots pass.
   */
  function _assertNoOpenSlashes(uint256 authorProfileId, SubjectKeys memory keys) private view {
    uint256 authorLast = lastSlashIdByAuthorProfile[authorProfileId];
    if (isOpen(authorLast)) revert AuthorHasOpenSlash(authorLast);

    if (keys.profileId != 0) {
      uint256 subjectProfileLast = lastSlashIdBySubjectProfile[keys.profileId];
      if (isOpen(subjectProfileLast)) revert SubjectHasOpenSlash(subjectProfileLast);
    }
    if (keys.subjectAddress != address(0)) {
      uint256 subjectAddressLast = lastSlashIdBySubjectAddress[keys.subjectAddress];
      if (isOpen(subjectAddressLast)) revert SubjectHasOpenSlash(subjectAddressLast);
    } else {
      uint256 subjectAttestationLast = lastSlashIdBySubjectAttestationHash[keys.attestationHash];
      if (isOpen(subjectAttestationLast)) revert SubjectHasOpenSlash(subjectAttestationLast);
    }
  }
}
