// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

import {AccessControlV2} from "./utils/AccessControlV2.sol";
import {ETHOS_VOUCH_V2} from "./utils/Constants.sol";
import {BPS_DENOMINATOR, SECONDS_PER_YEAR, WAD} from "./utils/MathConstants.sol";
import {
  EmissionRateTooHigh,
  InsufficientCommittedBalance,
  InsufficientRewardBalance,
  NoRewardsToClaim,
  UnauthorizedAccruingCaller,
  ZeroAmount
} from "./errors/RewardsErrors.sol";

/**
 * @title EthosRewards
 * @author Ethos Network
 * @notice UUPS-upgradeable contract that streams ERC-20 rewards from a sealed
 *         pool to users in proportion to their committed balance in the
 *         registered accruing contract (EthosVouchV2, resolved per-call from
 *         ContractAddressManager under ETHOS_VOUCH_V2). Uses a Synthetix-style
 *         rewards accumulator with a dynamic rate that decays against the
 *         still-undistributed portion of the pool.
 *
 * @dev Accumulator math:
 *
 *        available         = accountedRewardBalance - totalAccruedNotPaid
 *        rewardPerToken()  = rewardPerTokenStored + min(rawIncrement, capIncrement)
 *          rawIncrement    = (block.timestamp - lastUpdateTime) * available * emissionRateBps * 1e18
 *                            / (totalCommitted * BPS_DENOMINATOR * SECONDS_PER_YEAR)
 *          capIncrement    = available * 1e18 / totalCommitted
 *
 *        earned(u) = committedBalance[u] * (rewardPerToken() - userRewardPerTokenPaid[u]) / 1e18
 *                  + rewards[u]
 *
 *      The `updateReward(account)` modifier snapshots the global accumulator
 *      and (for non-zero accounts) the user's pending rewards before the
 *      wrapped function executes. Every credit / debit / claim call passes
 *      through it.
 *
 *      Solvency: emissions are capped to the accounted pool, not the live token
 *      balance. After every update, `accountedRewardBalance >=
 *      totalAccruedNotPaid`; every claim decrements both.
 *
 *      Trust boundary: the accruing contract registered under ETHOS_VOUCH_V2
 *      in ContractAddressManager is trusted to call credit/debit with amounts
 *      matching real token movements into and out of its own balances. The
 *      contract holds reward tokens only — it never custodies committed tokens.
 *      Authorization is identity-checked per call against the registry;
 *      rotating the registered address (or upgrading EthosRewards to read a
 *      different name) is the only way to add or change accruing contracts.
 *
 *      Funding model: raw ERC-20 transfers are ignored until an admin syncs the
 *      reward balance. Sync checkpoints the old accounted pool first, so newly
 *      transferred funds do not accrue retroactively.
 *
 *      Pause: `credit`, `debit`, and `claim` are pause-gated; the
 *      accumulator clock is not. Users see full accrual on unpause.
 *      `pause()` is NOT an emissions kill switch — accrual continues against
 *      `available` for the entire pause window. Use `setEmissionRate(0)` to
 *      halt emissions surgically. Pausing this contract also reverts every
 *      `credit`/`debit` call from the registered accruing contract, which in
 *      turn reverts user-facing operations on that contract (vouches). Pause
 *      is therefore only safe as part of a coordinated stack-wide halt (e.g.
 *      `InteractionControl.pauseAll`), not as a surgical lever on this
 *      contract alone.
 * @custom:security-contact security@ethos.network
 */
contract EthosRewards is AccessControlV2, UUPSUpgradeable, ReentrancyGuardUpgradeable {
  using SafeERC20 for IERC20;

  // --- Constants ---

  /// @notice Maximum permitted `emissionRateBps` (100% of `available` per year).
  uint256 public constant MAX_EMISSION_RATE_BPS = 10_000;

  // --- Events ---

  /// @notice Emitted when the registered accruing contract increments a user's committed balance.
  /// @param accruingContract    The accruing contract that called credit.
  /// @param user                The user whose committed balance was incremented.
  /// @param amount              The amount credited.
  /// @param newCommittedBalance The user's committed balance after the credit.
  event Credited(address indexed accruingContract, address indexed user, uint256 amount, uint256 newCommittedBalance);

  /// @notice Emitted when the registered accruing contract decrements a user's committed balance.
  /// @param accruingContract    The accruing contract that called debit.
  /// @param user                The user whose committed balance was decremented.
  /// @param amount              The amount debited.
  /// @param newCommittedBalance The user's committed balance after the debit.
  event Debited(address indexed accruingContract, address indexed user, uint256 amount, uint256 newCommittedBalance);

  /// @notice Emitted when a user claims their accumulated rewards.
  /// @param user   The user that claimed.
  /// @param amount The amount of reward tokens transferred.
  event RewardClaimed(address indexed user, uint256 amount);

  /// @notice Emitted when an admin synchronizes reward accounting to the live token balance.
  /// @param admin                     The admin that synchronized the balance.
  /// @param previousAccountedBalance  The accounted reward balance before synchronization.
  /// @param currentBalance            The live reward-token balance admitted into accounting.
  event RewardBalanceSynced(address indexed admin, uint256 previousAccountedBalance, uint256 currentBalance);

  /// @notice Emitted when the emission rate is changed.
  /// @param prev Previous emissionRateBps value.
  /// @param next New emissionRateBps value.
  event EmissionRateUpdated(uint256 prev, uint256 next);

  // --- Storage ---

  /// @notice The ERC-20 used for both reward payouts and as the committed asset.
  /// @dev Packed slot: rewardToken (20) + emissionRateBps (2) + lastUpdateTime (6) = 28 bytes.
  IERC20 public rewardToken;

  /// @notice Pool-decay coefficient in basis points per year. The instantaneous
  ///         rate is `available * emissionRateBps / (BPS_DENOMINATOR * SECONDS_PER_YEAR)`,
  ///         where `available = accountedRewardBalance - totalAccruedNotPaid`.
  ///         Bounded above by MAX_EMISSION_RATE_BPS (fits in uint16).
  /// @dev    NOT user APR. The per-user APR is
  ///         `(available / totalCommitted) * (emissionRateBps / 10_000)`,
  ///         so the user-facing rate scales with the pool-to-committed ratio
  ///         — see `currentRewardRateBps` for the live effective rate.
  uint16 public emissionRateBps;

  /// @notice Timestamp of the most recent accumulator update. uint48 covers
  ///         dates ~9M years past the unix epoch.
  uint48 public lastUpdateTime;

  /// @notice Accumulator: cumulative rewards per unit of committed balance,
  ///         WAD-scaled. Monotonic non-decreasing.
  uint256 public rewardPerTokenStored;

  /// @notice Sum of `committedBalance[u]` across all users.
  uint256 public totalCommitted;

  /// @notice Cumulative rewards marked into the accumulator that have not yet
  ///         been claimed.
  uint256 public totalAccruedNotPaid;

  /// @notice Reward-token balance admitted into emission accounting.
  uint256 public accountedRewardBalance;

  /// @notice Per-user snapshot of `rewardPerTokenStored` at the time their
  ///         pending rewards were last settled.
  mapping(address user => uint256) public userRewardPerTokenPaid;

  /// @notice Per-user pending claimable rewards, denominated in reward token wei.
  mapping(address user => uint256) public rewards;

  /// @notice Per-user committed balance in the registered accruing contract.
  mapping(address user => uint256) public committedBalance;

  /// @dev Storage gap for future upgrades.
  uint256[50] private __gap;

  // --- Modifiers ---

  /// @dev Restricts a function to the address registered under ETHOS_VOUCH_V2 in
  ///      ContractAddressManager at call time. Resolved per-call so the
  ///      authorized accruing contract can be rotated by re-registering in
  ///      CAM, without an upgrade or admin call on this contract.
  modifier onlyAccruingContract() {
    address authorized = contractAddressManager.getContractAddressForName(ETHOS_VOUCH_V2);
    if (msg.sender != authorized || authorized == address(0)) {
      revert UnauthorizedAccruingCaller(msg.sender, authorized);
    }
    _;
  }

  /// @dev Snapshots the global accumulator and (when account != 0) the user's
  ///      pending rewards before the wrapped function executes. Also runs the
  ///      `totalAccruedNotPaid` bookkeeping that bounds cumulative emission.
  modifier updateReward(address account) {
    uint256 oldRpt = rewardPerTokenStored;
    uint256 newRpt = rewardPerToken();
    rewardPerTokenStored = newRpt;
    lastUpdateTime = SafeCast.toUint48(block.timestamp);
    if (newRpt > oldRpt) {
      // `totalAccruedNotPaid` is incremented using ceiling division so that
      // the running total is always >= the sum of what every user can claim.
      //
      // The asymmetry: each per-interval global increment uses ceil, while
      // each per-user `earned()` uses a single floor over the aggregate
      // accumulator delta. Across multiple intervals a sole holder's
      // earned() can therefore exceed the sum of the floor-rounded per-interval
      // increments. Ceiling the global increment inverts that relationship:
      // sum_intervals(ceil(rptDelta * totalCommitted / WAD))
      //   >= ceil(sum(...)) >= floor(sum(...)) >= earned(u)
      // so `totalAccruedNotPaid >= earned(u)` for every u and claim()'s
      // checked subtraction `totalAccruedNotPaid -= reward` can never underflow.
      //
      // Solvency in the other direction (balance >= totalAccruedNotPaid) is
      // preserved: `increment` is capped at maxIncrement = floor(available *
      // WAD / totalCommitted), so ceil(increment * totalCommitted / WAD) <=
      // available, and totalAccruedNotPaid never grows beyond the current
      // balance.
      //
      // The per-interval ceil adds at most 1 wei of dust per update. That dust
      // accumulates in the contract balance and is never claimable; future
      // emissions decay against a marginally smaller `available`.
      totalAccruedNotPaid += Math.mulDiv(newRpt - oldRpt, totalCommitted, WAD, Math.Rounding.Ceil);
    }
    if (account != address(0)) {
      rewards[account] = earned(account);
      userRewardPerTokenPaid[account] = newRpt;
    }
    _;
  }

  // --- Initialization ---

  /**
   * @notice Initializes the contract.
   * @param p                Access control initialization parameters.
   * @param token_           ERC-20 used as both reward currency and committed asset.
   * @param emissionRateBps_ Initial emission rate in basis points per year. Must not exceed MAX_EMISSION_RATE_BPS.
   */
  function initialize(AccessControlInitParams calldata p, address token_, uint256 emissionRateBps_)
    external
    initializer
  {
    if (token_ == address(0)) revert ZeroAddress();
    if (emissionRateBps_ > MAX_EMISSION_RATE_BPS) {
      revert EmissionRateTooHigh(emissionRateBps_, MAX_EMISSION_RATE_BPS);
    }

    __accessControl_init(p);
    __UUPSUpgradeable_init();
    __ReentrancyGuard_init();

    rewardToken = IERC20(token_);
    emissionRateBps = SafeCast.toUint16(emissionRateBps_);
    lastUpdateTime = SafeCast.toUint48(block.timestamp);
    emit EmissionRateUpdated(0, emissionRateBps_);
  }

  // --- Accruing contract integration ---

  /**
   * @notice Increments `user`'s committed balance by `amount`.
   * @dev Only callable by the contract registered under ETHOS_VOUCH_V2 in
   *      ContractAddressManager; tracks accounting only, no token movement.
   * @param user   The end user whose committed balance is being incremented.
   * @param amount The amount to credit. Must be non-zero.
   */
  function credit(address user, uint256 amount)
    external
    onlyAccruingContract
    onlyNonZeroAddress(user)
    whenNotPaused
    updateReward(user)
  {
    if (amount == 0) revert ZeroAmount();
    uint256 newBalance = committedBalance[user] + amount;
    committedBalance[user] = newBalance;
    totalCommitted += amount;
    emit Credited(msg.sender, user, amount, newBalance);
  }

  /**
   * @notice Decrements `user`'s committed balance by `amount`.
   * @dev Only callable by the contract registered under ETHOS_VOUCH_V2 in
   *      ContractAddressManager. Recommended ordering: settle the balance via
   *      `debit` before releasing the underlying token. The EthosRewards
   *      accumulator is reentrancy-safe regardless — every mutating path runs
   *      through `updateReward`, which snapshots state cleanly. Ordering is
   *      an accruing-contract-internal hygiene concern, not an EthosRewards
   *      safety property.
   * @param user   The end user whose committed balance is being decremented.
   * @param amount The amount to debit. Must be non-zero and ≤ committedBalance[user].
   */
  function debit(address user, uint256 amount)
    external
    onlyAccruingContract
    onlyNonZeroAddress(user)
    whenNotPaused
    updateReward(user)
  {
    if (amount == 0) revert ZeroAmount();
    uint256 prev = committedBalance[user];
    if (amount > prev) revert InsufficientCommittedBalance(user, amount, prev);
    uint256 newBalance = prev - amount;
    committedBalance[user] = newBalance;
    totalCommitted -= amount;
    emit Debited(msg.sender, user, amount, newBalance);
  }

  /**
   * @notice Transfers all of the caller's accumulated rewards to the caller.
   *         Reverts if the caller has no pending rewards.
   */
  function claim() external whenNotPaused nonReentrant updateReward(msg.sender) {
    uint256 reward = rewards[msg.sender];
    if (reward == 0) revert NoRewardsToClaim();
    rewards[msg.sender] = 0;
    // Clamp defensively: the ceiling-rounded global counter should always be
    // >= reward, but a future regression can never introduce a panic revert.
    totalAccruedNotPaid -= Math.min(reward, totalAccruedNotPaid);
    accountedRewardBalance -= Math.min(reward, accountedRewardBalance);
    rewardToken.safeTransfer(msg.sender, reward);
    emit RewardClaimed(msg.sender, reward);
  }

  // --- Admin ---

  /// @notice Synchronizes reward accounting to the current reward-token balance.
  /// @dev Sync first checkpoints the old accounted pool.
  function syncRewardBalance() external onlyAdmin whenNotPaused updateReward(address(0)) {
    uint256 currentBalance = rewardToken.balanceOf(address(this));
    if (currentBalance < totalAccruedNotPaid) {
      revert InsufficientRewardBalance(currentBalance, totalAccruedNotPaid);
    }

    uint256 previousAccountedBalance = accountedRewardBalance;
    accountedRewardBalance = currentBalance;

    emit RewardBalanceSynced(msg.sender, previousAccountedBalance, currentBalance);
  }

  /**
   * @notice Sets the emission rate.
   * @dev Wrapped in `updateReward(address(0))` so accrual integrates against
   *      the old rate up to the change boundary.
   * @param newEmissionRateBps New emission rate in basis points per year. Must not exceed MAX_EMISSION_RATE_BPS.
   */
  function setEmissionRate(uint256 newEmissionRateBps) external onlyAdmin updateReward(address(0)) {
    if (newEmissionRateBps > MAX_EMISSION_RATE_BPS) {
      revert EmissionRateTooHigh(newEmissionRateBps, MAX_EMISSION_RATE_BPS);
    }
    emit EmissionRateUpdated(emissionRateBps, newEmissionRateBps);
    emissionRateBps = SafeCast.toUint16(newEmissionRateBps);
  }

  // --- Views ---

  /**
   * @notice Returns the global rewards-per-committed-token accumulator at the
   *         current block. WAD-scaled.
   */
  function rewardPerToken() public view returns (uint256) {
    if (totalCommitted == 0) return rewardPerTokenStored;
    uint256 dt = block.timestamp - lastUpdateTime;
    if (dt == 0 || emissionRateBps == 0) return rewardPerTokenStored;
    uint256 available = _availableRewardBalance();
    if (available == 0) return rewardPerTokenStored;
    uint256 increment =
      Math.mulDiv(dt * available, uint256(emissionRateBps) * WAD, totalCommitted * BPS_DENOMINATOR * SECONDS_PER_YEAR);
    uint256 maxIncrement = Math.mulDiv(available, WAD, totalCommitted);
    if (increment > maxIncrement) increment = maxIncrement;
    return rewardPerTokenStored + increment;
  }

  /// @notice Returns `account`'s pending claimable rewards as of the current block.
  /// @param account The account to query.
  function earned(address account) public view returns (uint256) {
    return
      Math.mulDiv(committedBalance[account], rewardPerToken() - userRewardPerTokenPaid[account], WAD) + rewards[account];
  }

  /**
   * @notice Returns the instantaneous reward rate in basis points:
   *         `(available * emissionRateBps) / totalCommitted`. Returns 0 when
   *         nothing is committed or the pool is exhausted.
   * @dev Accounts for pending global accrual since `lastUpdateTime`; not an
   *      enforced target. NOT bounded by `MAX_EMISSION_RATE_BPS` — when
   *      `available > totalCommitted`, this value exceeds 10_000. It reflects
   *      per-token effective APR, not the pool-decay coefficient
   *      `emissionRateBps`.
   */
  function currentRewardRateBps() external view returns (uint256) {
    if (totalCommitted == 0) return 0;
    uint256 accruedNotPaid = totalAccruedNotPaid;
    uint256 currentRewardPerToken = rewardPerToken();
    if (currentRewardPerToken > rewardPerTokenStored) {
      accruedNotPaid += Math.mulDiv(currentRewardPerToken - rewardPerTokenStored, totalCommitted, WAD, Math.Rounding.Ceil);
    }
    if (accountedRewardBalance <= accruedNotPaid) return 0;
    uint256 available = accountedRewardBalance - accruedNotPaid;
    return Math.mulDiv(available, emissionRateBps, totalCommitted);
  }

  function _availableRewardBalance() internal view returns (uint256) {
    if (accountedRewardBalance <= totalAccruedNotPaid) return 0;
    return accountedRewardBalance - totalAccruedNotPaid;
  }

  // --- UUPS ---

  /// @inheritdoc UUPSUpgradeable
  /// @notice Restricts upgrade authorization to the owner. Reverts if newImplementation is zero.
  /// @param newImplementation Address of the new implementation contract.
  function _authorizeUpgrade(address newImplementation)
    internal
    override
    onlyOwner
    onlyNonZeroAddress(newImplementation)
  {}
}
