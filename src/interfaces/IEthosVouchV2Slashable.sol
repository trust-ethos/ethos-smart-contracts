// SPDX-License-Identifier: MIT

// Disjunction pragma: consumed by EthosSlash (0.8.26) and EthosRewards (0.8.33).
pragma solidity 0.8.26 || 0.8.33;

/**
 * @title IEthosVouchV2Slashable
 * @notice Consumer-side interface for the SLASHER-role command surface on EthosVouchV2,
 *         plus the ungated `activeBalanceOf` view.
 * @dev The commands (freeze / unfreeze / slash) are callable only by the SLASHER role registered
 *      in ContractAddressManager (enforced by EthosVouchV2.onlySlasher); `activeBalanceOf` is a
 *      plain view with no role gate.
 * @custom:security-contact security@ethos.network
 */
interface IEthosVouchV2Slashable {
  /// @notice Marks an account as frozen, blocking `unvouch` and `decreaseVouch`.
  /// @dev Idempotent.
  /// @param account Address to freeze.
  function freeze(address account) external;

  /// @notice Clears the frozen flag on an account.
  /// @dev Idempotent.
  /// @param account Address to unfreeze.
  function unfreeze(address account) external;

  /// @notice Burns `bps` basis points of every active vouch authored by `account`.
  /// @dev Iterates the account's full active-vouch list in one call. Gas scales linearly
  ///      with vouch count; callers chunk their own fanout, not per-account slashes.
  /// @param account       Address whose vouches are slashed.
  /// @param bps           Slash percentage in basis points. Reverts if > 10_000.
  /// @return amountApplied Total tokens burned across the account's active vouches.
  function slash(address account, uint256 bps) external returns (uint256 amountApplied);

  /// @notice An author's total active vouch balance — the same quantity `slash` burns a
  ///         percentage of. Unlike the rest of this interface it is a view, not a SLASHER-gated
  ///         command, so any caller may read it.
  /// @dev Used by the slasher to enforce a minimum author balance at `createSlash` execution time.
  /// @param account Address whose active vouch balance is returned.
  /// @return Total active vouch balance authored by `account`.
  function activeBalanceOf(address account) external view returns (uint256);
}
