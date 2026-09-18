// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {
  ERC20BurnableUpgradeable
} from "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20BurnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

import {AccessControlV2} from "./utils/AccessControlV2.sol";
import {SlashFreezable} from "./utils/SlashFreezable.sol";
import {IEthosRewards} from "./interfaces/IEthosRewards.sol";
import {IEthosVouchV2} from "./interfaces/IEthosVouchV2.sol";
import {IFreezable} from "./interfaces/IFreezable.sol";
import {ISlashable} from "./interfaces/ISlashable.sol";
import {ITargetStatus} from "./interfaces/ITargetStatus.sol";
import {ETHOS_REVIEW, ETHOS_REWARDS, SLASHER} from "./utils/Constants.sol";
import {
  AlreadyVouched,
  VouchAlreadyArchived,
  UnauthorizedVouchAccess,
  MaxVouchesExceeded,
  AmountBelowMinimum,
  AmountAboveMaximum,
  FeeBpsTooHigh,
  InsufficientPermitAllowance,
  UnexpectedTokenBehavior,
  VouchNotFound,
  TokenNotBurnable,
  InvalidBps,
  MaximumVouchesOutOfRange,
  ZeroAmount,
  AmountExceedsBalance,
  RemainingBelowMinimum,
  UnauthorizedComposer,
  InvalidAuthor
} from "./errors/VouchV2Errors.sol";
import {AccountFrozen} from "./errors/SlashFreezableErrors.sol";

/**
 * @title EthosVouchV2
 * @author Ethos Network
 * @notice UUPS-upgradeable contract for token-backed vouching with slashing support.
 *         Each vouch locks ERC-20 tokens on behalf of an author for a target (identified
 *         by a keccak256 hash of an arbitrary string). A registered slasher can freeze
 *         authors (preventing unvouch) and burn a percentage of all active vouch balances.
 *
 * @dev CEI pattern is enforced on every funds-moving path: vouch, increaseVouch, and
 *      unvouch perform all state writes (vouch struct, indexes, uniqueness mapping,
 *      archival) before any token transfer or burn. nonReentrant guards each entry
 *      point as defense-in-depth.
 *
 *      Fee rounding rules (favour the contract):
 *      - Entry and exit fees: Math.mulDiv with Rounding.Ceil (round UP).
 *      - Burn amount per vouch: Math.mulDiv with Rounding.Ceil (round UP).
 *
 *      Token assumptions: the backing ERC-20 must be non-rebasing and must not take a
 *      fee on transfer. An inbound balance-delta check in _checkTransferIn rejects any
 *      token whose post-transfer delta differs from the gross amount requested.
 *      The token must extend OpenZeppelin's ERC20BurnableUpgradeable — initialize
 *      probes this via burn(0) because burn support is not ERC-165 advertised, catching
 *      misconfiguration at deploy time rather than at the first slash.
 *
 *      Frozen accounts are blocked from author-initiated withdrawals — both unvouch
 *      and decreaseVouch — so a pending slash cannot be drained around. Slash
 *      operations (freeze/unfreeze/slash) flow through the registered slasher
 *      address resolved from ContractAddressManager. Pause blocks every
 *      state-changing path, including slasher-initiated freezes and slashes.
 *
 *      Fees are burned, not collected: entry and exit fees are destroyed via
 *      ERC20Burnable.burn rather than forwarded to a recipient. This removes the
 *      protocol-fee-address configuration surface entirely.
 *
 *      Configuration invariants:
 *      - configuredMinimumVouchAmount must be non-zero (zero would allow free
 *        reservations of (author, targetHash) entries).
 * @custom:security-contact security@ethos.network
 */
contract EthosVouchV2 is
  AccessControlV2,
  UUPSUpgradeable,
  ReentrancyGuardUpgradeable,
  SlashFreezable,
  IEthosVouchV2,
  ISlashable,
  ITargetStatus
{
  using SafeERC20 for ERC20BurnableUpgradeable;

  /// @notice Maximum combined entry + exit fee in basis points (10%).
  uint256 public constant MAX_TOTAL_FEES = 1000;
  /// @notice Denominator for basis-point calculations.
  uint256 public constant BASIS_POINT_SCALE = 10000;

  /// @notice Represents a single vouch from an author to a target.
  /// @dev Packed into 3 storage slots:
  ///      - slot 0: author (20) + archived (1) + unhealthy (1) = 22 bytes
  ///      - slot 1: targetHash
  ///      - slot 2: balance
  ///      Vouch/unvouch timestamps are not persisted — `Vouched`, `Unvouched`,
  ///      and `MarkedUnhealthy` events carry the vouchId and the containing
  ///      block's timestamp is available to any off-chain indexer, so
  ///      duplicating them in storage is dead state.
  struct Vouch {
    address author;
    bool archived;
    bool unhealthy;
    bytes32 targetHash;
    uint256 balance;
  }

  /// @notice Emitted when a new vouch is created.
  /// @param author    Address that created the vouch.
  /// @param targetHash keccak256 hash of the target string.
  /// @param vouchId   Unique ID assigned to this vouch.
  /// @param target    Raw target string.
  /// @param balance   Net token balance credited to the vouch.
  /// @param fee       Entry fee burned.
  /// @param metadata  Opaque metadata payload (empty when none supplied).
  event Vouched(
    address indexed author,
    bytes32 indexed targetHash,
    uint256 vouchId,
    string target,
    uint256 balance,
    uint256 fee,
    string metadata
  );

  /// @notice Emitted when an existing vouch balance is increased.
  /// @param vouchId    ID of the vouch that was increased.
  /// @param increment  Net amount added to the balance.
  /// @param fee        Entry fee burned.
  /// @param newBalance Updated vouch balance after the increase.
  event VouchIncreased(uint256 indexed vouchId, uint256 increment, uint256 fee, uint256 newBalance);

  /// @notice Emitted when a vouch balance is partially withdrawn without archiving.
  ///         Distinct from `Unvouched` so off-chain consumers can render a partial
  ///         withdrawal differently from a full exit.
  /// @param vouchId    ID of the vouch that was decreased.
  /// @param decrement  Gross amount removed from the balance (before exit fee).
  /// @param fee        Exit fee burned.
  /// @param newBalance Updated vouch balance after the decrease.
  event VouchDecreased(uint256 indexed vouchId, uint256 decrement, uint256 fee, uint256 newBalance);

  /// @notice Emitted when a vouch is archived (unvouched).
  /// @param vouchId     ID of the archived vouch.
  /// @param prevBalance Balance before archiving.
  /// @param fee         Exit fee burned.
  /// @param payout      Amount returned to the author.
  event Unvouched(uint256 indexed vouchId, uint256 prevBalance, uint256 fee, uint256 payout);

  /// @notice Emitted when a vouch is marked unhealthy via `unvouchUnhealthy`,
  ///         signalling the relationship ended due to distrust. Always paired
  ///         with an `Unvouched` event in the same transaction.
  /// @param vouchId    ID of the vouch marked unhealthy.
  /// @param author     Author who marked the vouch unhealthy.
  /// @param targetHash keccak256 hash of the vouch's target string.
  event MarkedUnhealthy(uint256 indexed vouchId, address indexed author, bytes32 indexed targetHash);

  /// @notice Emitted when a single vouch balance is slashed.
  /// @param vouchId     ID of the affected vouch.
  /// @param prevBalance Balance before the slash.
  /// @param newBalance  Balance after the slash.
  /// @param amount      Amount of tokens deducted (burned).
  event VouchSlashed(uint256 indexed vouchId, uint256 prevBalance, uint256 newBalance, uint256 amount);

  /// @notice Emitted after a full account slash pass completes.
  /// @param account       Address whose vouches were slashed.
  /// @param bps           Slash percentage in basis points.
  /// @param amountApplied Total tokens deducted across the account's active vouches.
  event AccountSlashed(address indexed account, uint256 bps, uint256 amountApplied);

  /// @notice Emitted when the entry fee bps is updated.
  /// @param prev Previous entry fee in basis points.
  /// @param next New entry fee in basis points.
  event EntryFeeBpsUpdated(uint256 prev, uint256 next);

  /// @notice Emitted when the exit fee bps is updated.
  /// @param prev Previous exit fee in basis points.
  /// @param next New exit fee in basis points.
  event ExitFeeBpsUpdated(uint256 prev, uint256 next);

  /// @notice Emitted when the minimum vouch amount is updated.
  /// @param prev Previous minimum vouch amount.
  /// @param next New minimum vouch amount.
  event MinimumVouchAmountUpdated(uint256 prev, uint256 next);

  /// @notice Emitted when the maximum vouch amount is updated.
  /// @param prev Previous maximum vouch amount.
  /// @param next New maximum vouch amount.
  event MaximumVouchAmountUpdated(uint256 prev, uint256 next);

  /// @notice Emitted when the maximum vouches per author is updated.
  /// @param prev Previous maximum vouches value.
  /// @param next New maximum vouches value.
  event MaximumVouchesUpdated(uint256 prev, uint256 next);

  /// @notice Emitted when a vouch's metadata string is set or replaced.
  ///         Always fires on a non-empty metadata at creation time and on
  ///         every successful `setVouchMetadata` call.
  /// @param vouchId  Vouch whose metadata was set.
  /// @param metadata New metadata payload (opaque to the contract).
  event VouchMetadataUpdated(uint256 indexed vouchId, string metadata);

  /// @notice The ERC-20 token used for vouching. Must extend ERC20BurnableUpgradeable.
  /// @dev Packed with entryFeeBps + exitFeeBps + maximumVouches into a single slot:
  ///      address (20) + uint16 (2) + uint16 (2) + uint32 (4) = 28 bytes.
  ERC20BurnableUpgradeable public token;

  /// @notice Entry fee in basis points, charged on vouch and increaseVouch.
  uint16 public entryFeeBps;

  /// @notice Exit fee in basis points, charged on unvouch.
  uint16 public exitFeeBps;

  /// @notice Maximum number of active vouches per author. Default: 256.
  uint32 public maximumVouches;

  /// @notice Minimum token amount required to create a vouch.
  uint256 public configuredMinimumVouchAmount;

  /// @notice Maximum token amount accepted on `vouch` / `increaseVouch`.
  ///         Set by the admin via `setMaximumVouchAmount`. A vouch creation
  ///         or top-up whose new total balance would exceed this value
  ///         reverts with `AmountAboveMaximum`. Stored as the absolute
  ///         per-vouch cap (NOT bps) so callers can reason in WHUF units
  ///         directly. Must be non-zero (zero would brick the contract).
  uint256 public configuredMaximumVouchAmount;

  /// @notice Total number of vouches ever created (also the last-used vouchId).
  uint256 public vouchCount;

  /// @notice All vouches by ID. IDs start at 1.
  mapping(uint256 => Vouch) public vouches;

  /// @notice Ordered list of vouch IDs created by an author.
  mapping(address => uint256[]) public vouchIdsByAuthor;

  /// @notice Index of each vouchId within vouchIdsByAuthor[author].
  mapping(address => mapping(uint256 => uint256)) public vouchIdsByAuthorIndex;

  /// @notice Active vouchId for a given (author, targetHash) pair. 0 means none.
  mapping(address => mapping(bytes32 => uint256)) public vouchIdByAuthorForTargetHash;

  /// @notice Opaque per-vouch metadata string. Set on creation via the
  ///         3-arg `vouch` / `vouchWithPermit` overloads or replaced via
  ///         `setVouchMetadata`. Contract treats the payload as opaque;
  ///         off-chain consumers interpret it as JSON.
  mapping(uint256 => string) public vouchMetadata;

  /// @notice Each author's total active vouch balance — the slashable base. Maintained in
  ///         lockstep with vouch / increaseVouch / decreaseVouch / unvouch / slash so a slasher
  ///         can read it O(1) at createSlash. EthosRewards mirrors the same quantity for reward
  ///         streaming, but the slashable copy lives here because VouchV2 owns the vouches.
  mapping(address author => uint256 activeBalance) private _activeBalance;

  /// @dev Storage gap for future upgrades.
  uint256[50] private __gap;

  /// @notice Resolves the current slasher address from the ContractAddressManager.
  /// @return The address registered under the SLASHER name.
  function _slasher() internal view override returns (address) {
    return contractAddressManager.getContractAddressForName(SLASHER);
  }

  /// @dev Resolves the current EthosRewards address from the ContractAddressManager.
  ///      Resolved per-call so the rewards contract can be rotated without an
  ///      upgrade. A zero or non-contract address causes credit/debit to revert,
  ///      which in turn reverts the wrapping vouch operation — the integration
  ///      assumes the registry has ETHOS_REWARDS pointed at a live, allowlisted
  ///      rewards proxy. EthosRewards' own pause therefore halts vouch ops too.
  function _rewards() internal view returns (IEthosRewards) {
    return IEthosRewards(contractAddressManager.getContractAddressForName(ETHOS_REWARDS));
  }

  /**
   * @notice Initializes the contract.
   * @param p                             Access control parameters.
   * @param token_                        ERC-20 token used for vouching.
   * @param entryFeeBps_                  Entry fee in basis points.
   * @param exitFeeBps_                   Exit fee in basis points.
   * @param configuredMinimumVouchAmount_ Minimum token amount per vouch.
   * @param configuredMaximumVouchAmount_ Maximum token amount per vouch (must be ≥ minimum).
   * @param maximumVouches_               Max active vouches per author (0 → default 256).
   * @param initialVouchCount_            Starting value for vouchCount. The first vouch minted
   *                                      gets id `initialVouchCount_ + 1`. Use 0 for a standard
   *                                      deploy; set a non-zero offset when a deploy must avoid
   *                                      id collisions with another vouch contract (e.g. V1).
   */
  function initialize(
    AccessControlInitParams calldata p,
    address token_,
    uint256 entryFeeBps_,
    uint256 exitFeeBps_,
    uint256 configuredMinimumVouchAmount_,
    uint256 configuredMaximumVouchAmount_,
    uint256 maximumVouches_,
    uint256 initialVouchCount_
  ) external initializer {
    if (token_ == address(0)) revert ZeroAddress();
    if (entryFeeBps_ + exitFeeBps_ > MAX_TOTAL_FEES) {
      revert FeeBpsTooHigh(entryFeeBps_ + exitFeeBps_, MAX_TOTAL_FEES);
    }
    // A zero minimum would allow vouch(target, 0) to reserve (author, targetHash) entries
    // for free — no stake, no fee, no transfer — and pollute the active indexes.
    if (configuredMinimumVouchAmount_ == 0) revert AmountBelowMinimum(0, 1);
    // Maximum must be ≥ minimum; otherwise no vouch amount is ever valid.
    if (configuredMaximumVouchAmount_ < configuredMinimumVouchAmount_) {
      revert AmountBelowMinimum(configuredMaximumVouchAmount_, configuredMinimumVouchAmount_);
    }
    if (maximumVouches_ > type(uint32).max) revert MaximumVouchesOutOfRange(maximumVouches_);
    // Probe burn support — burn(0) is a no-op on compliant tokens and reverts on tokens
    // without the selector, catching misconfiguration at deploy time rather than at the
    // first fee burn. (Burn support is not ERC-165 advertised, so we cannot introspect.)
    try ERC20BurnableUpgradeable(token_).burn(0) {}
    catch {
      revert TokenNotBurnable(token_);
    }

    __accessControl_init(p);
    __UUPSUpgradeable_init();
    __ReentrancyGuard_init();
    __SlashFreezable_init();

    token = ERC20BurnableUpgradeable(token_);
    entryFeeBps = SafeCast.toUint16(entryFeeBps_);
    exitFeeBps = SafeCast.toUint16(exitFeeBps_);
    configuredMinimumVouchAmount = configuredMinimumVouchAmount_;
    configuredMaximumVouchAmount = configuredMaximumVouchAmount_;
    maximumVouches = SafeCast.toUint32(maximumVouches_ == 0 ? 256 : maximumVouches_);
    vouchCount = initialVouchCount_;
  }

  /**
   * @notice Creates a new vouch for `target`, locking `amount` tokens (plus entry fee).
   * @param target Arbitrary target string; keccak256 becomes the targetHash.
   * @param amount Net token amount to lock (before fee).
   */
  function vouch(string calldata target, uint256 amount) external whenNotPaused nonReentrant {
    _vouchAs(msg.sender, target, amount, "");
  }

  /**
   * @notice Creates a new vouch for `target` with an attached metadata string.
   *         The metadata payload is opaque to the contract; off-chain consumers
   *         decide how to interpret it (current convention: JSON with batch/review
   *         correlation fields).
   * @param target   Arbitrary target string; keccak256 becomes the targetHash.
   * @param amount   Net token amount to lock (before fee).
   * @param metadata Opaque metadata to attach to the new vouch.
   */
  function vouch(string calldata target, uint256 amount, string calldata metadata) external whenNotPaused nonReentrant {
    _vouchAs(msg.sender, target, amount, metadata);
  }

  /**
   * @notice Creates a new vouch on behalf of `author`, called by a registered
   *         Ethos protocol contract (e.g. EthosReview.reviewAndVouchWithPermit).
   *         The caller must be CAM-registered; WHUF for `amount + entryFee` is
   *         pulled from the caller (`msg.sender`), while the resulting vouch row
   *         is credited to `author`.
   * @dev    Author identity is decoupled from the token source so a composite
   *         contract can hold the WHUF and forward it on the user's behalf
   *         within a single transaction.
   * @param author   Address credited as the vouch author.
   * @param target   Arbitrary target string; keccak256 becomes the targetHash.
   * @param amount   Net token amount to lock (before fee).
   * @param metadata Opaque metadata to attach to the new vouch.
   */
  function vouchFor(address author, string calldata target, uint256 amount, string calldata metadata)
    external
    override
    whenNotPaused
    nonReentrant
  {
    address review = contractAddressManager.getContractAddressForName(ETHOS_REVIEW);
    if (msg.sender != review) {
      revert UnauthorizedComposer(msg.sender);
    }
    if (author == address(0)) revert InvalidAuthor();
    _vouchAs(author, target, amount, metadata);
  }

  /**
   * @notice Creates a new vouch using an EIP-2612 permit for approval, combining approval
   *         and vouch into a single transaction.
   * @dev Wraps permit() in try/catch per OpenZeppelin's recommendation to tolerate
   *      frontrunning (attacker consumes the nonce first; the vouch still proceeds
   *      against the already-applied allowance). Asserts post-catch allowance covers
   *      `amount + fee` and reverts with InsufficientPermitAllowance otherwise, so a
   *      genuine permit failure surfaces explicitly rather than as an opaque
   *      ERC20InsufficientAllowance from the downstream safeTransferFrom.
   * @param target   Arbitrary target string; keccak256 becomes the targetHash.
   * @param amount   Net token amount to lock (before fee).
   * @param deadline Permit signature expiry timestamp.
   * @param v        Recovery byte of the permit signature.
   * @param r        First 32 bytes of the permit signature.
   * @param s        Second 32 bytes of the permit signature.
   */
  function vouchWithPermit(string calldata target, uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s)
    external
    whenNotPaused
    nonReentrant
  {
    uint256 fee = _entryFee(amount);
    uint256 required = amount + fee;
    try IERC20Permit(address(token)).permit(msg.sender, address(this), required, deadline, v, r, s) {}
    catch {
      if (token.allowance(msg.sender, address(this)) < required) {
        revert InsufficientPermitAllowance(msg.sender, required);
      }
    }
    _vouchAs(msg.sender, target, amount, "");
  }

  /**
   * @notice `vouchWithPermit` variant that attaches an opaque metadata string
   *         at creation time. See the metadata-bearing `vouch` overload for the
   *         field semantics.
   * @param target   Arbitrary target string; keccak256 becomes the targetHash.
   * @param amount   Net token amount to lock (before fee).
   * @param metadata Opaque metadata to attach to the new vouch.
   * @param deadline Permit signature expiry timestamp.
   * @param v        Recovery byte of the permit signature.
   * @param r        First 32 bytes of the permit signature.
   * @param s        Second 32 bytes of the permit signature.
   */
  function vouchWithPermit(
    string calldata target,
    uint256 amount,
    string calldata metadata,
    uint256 deadline,
    uint8 v,
    bytes32 r,
    bytes32 s
  ) external whenNotPaused nonReentrant {
    uint256 fee = _entryFee(amount);
    uint256 required = amount + fee;
    try IERC20Permit(address(token)).permit(msg.sender, address(this), required, deadline, v, r, s) {}
    catch {
      if (token.allowance(msg.sender, address(this)) < required) {
        revert InsufficientPermitAllowance(msg.sender, required);
      }
    }
    _vouchAs(msg.sender, target, amount, metadata);
  }

  /**
   * @notice Increases the balance of an existing active vouch.
   * @param vouchId ID of the vouch to increase.
   * @param amount  Additional net token amount to lock (before fee).
   */
  function increaseVouch(uint256 vouchId, uint256 amount) external whenNotPaused nonReentrant {
    _increaseVouch(vouchId, amount);
  }

  /**
   * @notice Increases a vouch balance using an EIP-2612 permit for approval, combining
   *         approval and top-up into a single transaction.
   * @dev Wraps permit() in try/catch per OpenZeppelin's recommendation to tolerate
   *      frontrunning (attacker consumes the nonce first; the top-up still proceeds
   *      against the already-applied allowance). Asserts post-catch allowance covers
   *      `amount + fee` and reverts with InsufficientPermitAllowance otherwise, so a
   *      genuine permit failure surfaces explicitly rather than as an opaque
   *      ERC20InsufficientAllowance from the downstream safeTransferFrom.
   * @param vouchId  ID of the vouch to increase.
   * @param amount   Additional net token amount to lock (before fee).
   * @param deadline Permit signature expiry timestamp.
   * @param v        Recovery byte of the permit signature.
   * @param r        First 32 bytes of the permit signature.
   * @param s        Second 32 bytes of the permit signature.
   */
  function increaseVouchWithPermit(uint256 vouchId, uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s)
    external
    whenNotPaused
    nonReentrant
  {
    uint256 fee = _entryFee(amount);
    uint256 required = amount + fee;
    try IERC20Permit(address(token)).permit(msg.sender, address(this), required, deadline, v, r, s) {}
    catch {
      if (token.allowance(msg.sender, address(this)) < required) {
        revert InsufficientPermitAllowance(msg.sender, required);
      }
    }
    _increaseVouch(vouchId, amount);
  }

  /**
   * @notice Partial withdrawal from an active vouch without archiving it. Charges the
   *         same exit fee as `unvouch`, applied to the withdrawn amount.
   * @dev Freeze-gated for the same reason as `unvouch`: prevents draining around a
   *      pending slash. Reverts if the remaining balance would fall below the minimum,
   *      forcing full exits onto `unvouch` so `VouchDecreased` never emits with
   *      `newBalance == 0` (which indexers would read as a full exit).
   * @param vouchId ID of the vouch to decrease.
   * @param amount  Gross amount to remove. Author receives `amount - exitFee`; fee is burned.
   */
  function decreaseVouch(uint256 vouchId, uint256 amount) external whenNotPaused nonReentrant {
    Vouch storage v = _loadVouch(vouchId);

    if (msg.sender != v.author) revert UnauthorizedVouchAccess(msg.sender, v.author);
    if (v.archived) revert VouchAlreadyArchived(vouchId);
    if (_frozenAccounts[msg.sender]) revert AccountFrozen(msg.sender);
    if (amount == 0) revert ZeroAmount();

    uint256 prevBalance = v.balance;
    if (amount > prevBalance) revert AmountExceedsBalance(amount, prevBalance);

    uint256 newBalance = prevBalance - amount;
    if (newBalance < configuredMinimumVouchAmount) {
      revert RemainingBelowMinimum(newBalance, configuredMinimumVouchAmount);
    }

    uint256 fee = _exitFee(amount);
    uint256 payout = amount - fee;

    v.balance = newBalance;

    _activeBalance[msg.sender] -= amount;
    _rewards().debit(msg.sender, amount);

    token.safeTransfer(msg.sender, payout);
    if (fee > 0) {
      token.burn(fee);
    }

    emit VouchDecreased(vouchId, amount, fee, newBalance);
  }

  /**
   * @notice Replaces an existing vouch's metadata. Author-only. The contract treats the
   *         payload as opaque (off-chain consumers interpret it as JSON).
   * @dev    Active-only: archived vouches reject metadata updates so consumers
   *         can rely on metadata reflecting the live vouch state.
   * @param vouchId  ID of the vouch whose metadata is being replaced.
   * @param metadata New metadata payload.
   */
  function setVouchMetadata(uint256 vouchId, string calldata metadata) external whenNotPaused nonReentrant {
    Vouch storage v = _loadVouch(vouchId);

    if (msg.sender != v.author) revert UnauthorizedVouchAccess(msg.sender, v.author);
    if (v.archived) revert VouchAlreadyArchived(vouchId);

    vouchMetadata[vouchId] = metadata;
    emit VouchMetadataUpdated(vouchId, metadata);
  }

  /**
   * @notice Archives a vouch and returns the balance (minus exit fee) to the author.
   * @param vouchId ID of the vouch to archive.
   */
  function unvouch(uint256 vouchId) external whenNotPaused nonReentrant {
    _unvouch(vouchId, false);
  }

  /**
   * @notice Variant of `unvouch` that also marks the vouch unhealthy, signalling
   *         the relationship ended due to distrust. Archives the vouch and returns
   *         the balance (minus exit fee) to the author. Unhealthy is a one-shot
   *         choice made at unvouch time; there is no post-hoc marking.
   * @param vouchId ID of the vouch to archive and mark unhealthy.
   */
  function unvouchUnhealthy(uint256 vouchId) external whenNotPaused nonReentrant {
    _unvouch(vouchId, true);
  }

  /// @dev Shared unvouch logic. When `unhealthy_` is true, the unhealthy flag is set
  ///      alongside archival — before any token movement — so the combined
  ///      `unvouchUnhealthy` path keeps the CEI ordering the contract enforces on
  ///      every funds-moving path.
  function _unvouch(uint256 vouchId, bool unhealthy_) internal {
    Vouch storage v = _loadVouch(vouchId);

    if (msg.sender != v.author) revert UnauthorizedVouchAccess(msg.sender, v.author);
    if (v.archived) revert VouchAlreadyArchived(vouchId);
    if (_frozenAccounts[msg.sender]) revert AccountFrozen(msg.sender);

    uint256 balance = v.balance;
    bytes32 targetHash = v.targetHash;

    uint256 fee = _exitFee(balance);
    uint256 payout = balance - fee;

    v.archived = true;
    v.balance = 0;
    if (unhealthy_) {
      v.unhealthy = true;
    }
    delete vouchIdByAuthorForTargetHash[msg.sender][targetHash];

    _removeFromAuthorIndex(msg.sender, vouchId);

    if (balance > 0) {
      _activeBalance[msg.sender] -= balance;
      _rewards().debit(msg.sender, balance);
    }

    token.safeTransfer(msg.sender, payout);
    if (fee > 0) {
      token.burn(fee);
    }

    emit Unvouched(vouchId, balance, fee, payout);
    if (unhealthy_) {
      emit MarkedUnhealthy(vouchId, msg.sender, targetHash);
    }
  }

  /// @inheritdoc SlashFreezable
  /// @dev Adds pause gating on top of the SlashFreezable base implementation.
  function freeze(address account) public override(SlashFreezable, IFreezable) whenNotPaused nonReentrant {
    super.freeze(account);
  }

  /// @inheritdoc SlashFreezable
  /// @dev Adds pause gating on top of the SlashFreezable base implementation.
  function unfreeze(address account) public override(SlashFreezable, IFreezable) whenNotPaused nonReentrant {
    super.unfreeze(account);
  }

  /**
   * @notice Slashes `bps` of `account`'s total balance across all active vouches.
   * @dev The slasher owns the slashing policy; this contract only validates that
   *      `bps` is a legal percentage. Tokens are burned via ERC20Burnable.burn. Does
   *      NOT archive zero-balance vouches after slashing. Does NOT gate on frozen
   *      state — the slasher is expected to freeze before calling, but enforcement
   *      is intentionally decoupled so the slasher can act without a prior freeze
   *      if its policy allows.
   * @param account       Address whose vouches are slashed.
   * @param bps           Slash percentage in basis points. Reverts if > BASIS_POINT_SCALE.
   * @return amountApplied Total tokens burned across the account's active vouches.
   */
  function slash(address account, uint256 bps)
    external
    override
    onlySlasher
    whenNotPaused
    nonReentrant
    returns (uint256 amountApplied)
  {
    return _burn(account, bps);
  }

  /// @notice `account`'s total active vouch balance — the slashable base `_burn` applies `bps`
  ///         to, read O(1) from the `_activeBalance` accumulator. The slasher reads it at
  ///         `createSlash` to enforce a bound minimum author balance.
  /// @param account Address whose active vouch balance is returned.
  /// @return Sum of `vouches[id].balance` over `account`'s active vouches.
  function activeBalanceOf(address account) external view returns (uint256) {
    return _activeBalance[account];
  }

  /**
   * @dev Implements ISlashable.slash by burning `bps` of `account`'s total active
   *      vouch balance. Each per-vouch deduction is recorded as a VouchSlashed
   *      event (policy-level wording from the interface), and the aggregate
   *      amount is destroyed via `token.burn` after the loop. Naming the helper
   *      `_burn` makes the on-chain mechanism explicit at the call site while
   *      keeping the slashing semantics on the public ISlashable surface.
   */
  function _burn(address account, uint256 bps) private returns (uint256 amountApplied) {
    if (bps > BASIS_POINT_SCALE) revert InvalidBps(bps);

    uint256[] storage accountVouches = vouchIdsByAuthor[account];
    uint256 len = accountVouches.length;

    for (uint256 i = 0; i < len; i++) {
      uint256 vid = accountVouches[i];
      Vouch storage v = vouches[vid];

      // vouchIdsByAuthor only contains active vouches (swap-pop on unvouch keeps it clean).
      // Zero-balance vouches remain in the index after a 100% slash; skip them.
      uint256 prevBalance = v.balance;
      if (prevBalance == 0) continue;

      uint256 amount = Math.mulDiv(prevBalance, bps, BASIS_POINT_SCALE, Math.Rounding.Ceil);

      if (amount > 0) {
        uint256 newBalance = prevBalance - amount;
        v.balance = newBalance;
        amountApplied += amount;
        emit VouchSlashed(vid, prevBalance, newBalance, amount);
      }
    }

    if (amountApplied > 0) {
      _activeBalance[account] -= amountApplied;
      _rewards().debit(account, amountApplied);
      token.burn(amountApplied);
    }

    emit AccountSlashed(account, bps, amountApplied);
  }

  /**
   * @notice Returns the fee and gross amount for a vouch of `amount`.
   * @param amount Net vouch amount.
   * @return fee   Entry fee charged.
   * @return gross Total tokens pulled from caller (amount + fee).
   */
  function previewVouchFee(uint256 amount) external view override returns (uint256 fee, uint256 gross) {
    fee = _entryFee(amount);
    gross = amount + fee;
  }

  /**
   * @notice Returns the payout and exit fee for unvouching vouchId.
   * @param vouchId Vouch to preview.
   * @return payout Amount the author would receive.
   * @return fee    Exit fee charged.
   */
  function previewUnvouchPayout(uint256 vouchId) external view returns (uint256 payout, uint256 fee) {
    uint256 balance = vouches[vouchId].balance;
    fee = _exitFee(balance);
    payout = balance - fee;
  }

  /**
   * @notice ITargetStatus implementation. Returns whether `targetId` exists as a vouch
   *         and whether it is allowed as a discussion target.
   * @dev Mirrors EthosVouch (V1) semantics: a vouch counts as "existing" once it has
   *      been minted (author != address(0)), and existence implies it is allowed.
   *      Archived (unvouched) entries remain valid discussion targets so that prior
   *      discussion threads stay reachable after the author exits.
   * @param targetId Vouch id.
   * @return exists  Whether the vouch exists.
   * @return allowed Whether the vouch is allowed as a discussion target.
   */
  function targetExistsAndAllowedForId(uint256 targetId) external view returns (bool exists, bool allowed) {
    exists = vouches[targetId].author != address(0);
    allowed = exists;
  }

  /**
   * @notice Sets the entry fee in basis points.
   * @param bps New entry fee. Combined with current exitFeeBps must not exceed MAX_TOTAL_FEES.
   */
  function setEntryFeeBps(uint256 bps) external onlyAdmin whenNotPaused {
    if (bps + exitFeeBps > MAX_TOTAL_FEES) revert FeeBpsTooHigh(bps + exitFeeBps, MAX_TOTAL_FEES);
    emit EntryFeeBpsUpdated(entryFeeBps, bps);
    entryFeeBps = SafeCast.toUint16(bps);
  }

  /**
   * @notice Sets the exit fee in basis points.
   * @param bps New exit fee. Combined with current entryFeeBps must not exceed MAX_TOTAL_FEES.
   */
  function setExitFeeBps(uint256 bps) external onlyAdmin whenNotPaused {
    if (entryFeeBps + bps > MAX_TOTAL_FEES) {
      revert FeeBpsTooHigh(entryFeeBps + bps, MAX_TOTAL_FEES);
    }
    emit ExitFeeBpsUpdated(exitFeeBps, bps);
    exitFeeBps = SafeCast.toUint16(bps);
  }

  /**
   * @notice Sets the minimum token amount required to create a vouch. Must be non-zero —
   *         a zero minimum would let callers reserve (author, targetHash) entries for free.
   * @param amount New minimum amount.
   */
  function setMinimumVouchAmount(uint256 amount) external onlyAdmin whenNotPaused {
    if (amount == 0) revert AmountBelowMinimum(0, 1);
    if (amount > configuredMaximumVouchAmount) {
      revert AmountAboveMaximum(amount, configuredMaximumVouchAmount);
    }
    emit MinimumVouchAmountUpdated(configuredMinimumVouchAmount, amount);
    configuredMinimumVouchAmount = amount;
  }

  /**
   * @notice Sets the maximum token amount accepted on `vouch` / `increaseVouch`.
   *         Must be ≥ the current minimum so the configured window is non-empty.
   * @param amount New maximum amount.
   */
  function setMaximumVouchAmount(uint256 amount) external onlyAdmin whenNotPaused {
    if (amount < configuredMinimumVouchAmount) {
      revert AmountBelowMinimum(amount, configuredMinimumVouchAmount);
    }
    emit MaximumVouchAmountUpdated(configuredMaximumVouchAmount, amount);
    configuredMaximumVouchAmount = amount;
  }

  /**
   * @notice Sets the maximum number of active vouches per author.
   * @param max New maximum. Must be greater than zero.
   */
  function setMaximumVouches(uint256 max) external onlyAdmin whenNotPaused {
    if (max == 0) revert AmountBelowMinimum(0, 1);
    if (max > type(uint32).max) revert MaximumVouchesOutOfRange(max);
    emit MaximumVouchesUpdated(maximumVouches, max);
    maximumVouches = SafeCast.toUint32(max);
  }

  /// @inheritdoc UUPSUpgradeable
  /// @notice Restricts upgrade authorization to the owner. Reverts if newImplementation is zero.
  /// @param newImplementation Address of the new implementation contract.
  function _authorizeUpgrade(address newImplementation)
    internal
    override
    onlyOwner
    onlyNonZeroAddress(newImplementation)
  {}

  /// @dev Shared vouch creation logic. Author-credit references use the
  ///      `author` parameter; the token source for `_checkTransferIn`
  ///      stays on `msg.sender` (= the user for direct calls, = the
  ///      registered composer contract for `vouchFor`). Composer must
  ///      pre-approve VouchV2 for `gross = amount + entryFee` before
  ///      invoking `vouchFor`.
  ///
  ///      `metadata` is stored only when non-empty, so the empty-metadata
  ///      paths never write a useless storage slot. `metadata` is `memory`
  ///      so the 2-arg overloads can pass the empty literal while the
  ///      3-arg overloads pass calldata that implicitly converts.
  function _vouchAs(address author, string calldata target, uint256 amount, string memory metadata) internal {
    if (amount < configuredMinimumVouchAmount) {
      revert AmountBelowMinimum(amount, configuredMinimumVouchAmount);
    }
    if (amount > configuredMaximumVouchAmount) {
      revert AmountAboveMaximum(amount, configuredMaximumVouchAmount);
    }

    bytes32 targetHash = keccak256(bytes(target));

    if (vouchIdByAuthorForTargetHash[author][targetHash] != 0) {
      revert AlreadyVouched(author, targetHash);
    }

    if (vouchIdsByAuthor[author].length >= maximumVouches) {
      revert MaxVouchesExceeded(author, maximumVouches);
    }

    uint256 fee = _entryFee(amount);
    uint256 gross = amount + fee;

    uint256 vouchId = ++vouchCount;

    vouches[vouchId] =
      Vouch({author: author, archived: false, unhealthy: false, targetHash: targetHash, balance: amount});

    vouchIdsByAuthorIndex[author][vouchId] = vouchIdsByAuthor[author].length;
    vouchIdsByAuthor[author].push(vouchId);

    vouchIdByAuthorForTargetHash[author][targetHash] = vouchId;

    _activeBalance[author] += amount;
    _rewards().credit(author, amount);

    if (bytes(metadata).length > 0) {
      vouchMetadata[vouchId] = metadata;
      emit VouchMetadataUpdated(vouchId, metadata);
    }

    _checkTransferIn(gross);
    if (fee > 0) {
      token.burn(fee);
    }

    emit Vouched(author, targetHash, vouchId, target, amount, fee, metadata);
  }

  /// @dev Shared increaseVouch logic.
  function _increaseVouch(uint256 vouchId, uint256 amount) internal {
    Vouch storage v = _loadVouch(vouchId);

    if (msg.sender != v.author) revert UnauthorizedVouchAccess(msg.sender, v.author);
    if (v.archived) revert VouchAlreadyArchived(vouchId);
    if (amount == 0) revert ZeroAmount();

    uint256 fee = _entryFee(amount);
    uint256 gross = amount + fee;

    uint256 newBalance = v.balance + amount;
    if (newBalance < configuredMinimumVouchAmount) {
      revert AmountBelowMinimum(newBalance, configuredMinimumVouchAmount);
    }
    if (newBalance > configuredMaximumVouchAmount) {
      revert AmountAboveMaximum(newBalance, configuredMaximumVouchAmount);
    }
    v.balance = newBalance;

    if (amount > 0) {
      _activeBalance[msg.sender] += amount;
      _rewards().credit(msg.sender, amount);
    }

    _checkTransferIn(gross);
    if (fee > 0) {
      token.burn(fee);
    }

    emit VouchIncreased(vouchId, amount, fee, newBalance);
  }

  /// @dev Checks that exactly `gross` tokens are received (fee-on-transfer guard), then pulls them.
  function _checkTransferIn(uint256 gross) internal {
    uint256 before = token.balanceOf(address(this));
    token.safeTransferFrom(msg.sender, address(this), gross);
    uint256 delta = token.balanceOf(address(this)) - before;
    if (delta != gross) revert UnexpectedTokenBehavior(gross, delta);
  }

  /// @dev Loads a minted vouch or reverts VouchNotFound. Gates on `author != address(0)`,
  ///      not `vouchId <= vouchCount`, so hole ids below a nonzero initialVouchCount offset
  ///      (in range but never minted) don't surface as UnauthorizedVouchAccess.
  function _loadVouch(uint256 vouchId) internal view returns (Vouch storage v) {
    v = vouches[vouchId];
    if (v.author == address(0)) revert VouchNotFound(vouchId);
  }

  /// @dev Computes the entry fee for `amount`, rounding up.
  function _entryFee(uint256 amount) internal view returns (uint256) {
    return Math.mulDiv(amount, entryFeeBps, BASIS_POINT_SCALE, Math.Rounding.Ceil);
  }

  /// @dev Computes the exit fee for `balance`, rounding up.
  function _exitFee(uint256 balance) internal view returns (uint256) {
    return Math.mulDiv(balance, exitFeeBps, BASIS_POINT_SCALE, Math.Rounding.Ceil);
  }

  /// @dev Removes `vouchId` from `vouchIdsByAuthor[author]` using swap-pop.
  function _removeFromAuthorIndex(address author, uint256 vouchId) internal {
    uint256[] storage arr = vouchIdsByAuthor[author];
    uint256 idx = vouchIdsByAuthorIndex[author][vouchId];
    uint256 last = arr.length - 1;

    if (idx != last) {
      uint256 movedId = arr[last];
      arr[idx] = movedId;
      vouchIdsByAuthorIndex[author][movedId] = idx;
    }

    arr.pop();
    delete vouchIdsByAuthorIndex[author][vouchId];
  }
}
