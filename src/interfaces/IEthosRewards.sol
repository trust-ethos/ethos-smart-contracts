// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

/// @title IEthosRewards
/// @notice Minimal interface exposed by EthosRewards to allowlisted accruing
///         contracts. Accruing contracts call `credit` when a user's committed
///         balance grows and `debit` when it shrinks; both revert on any
///         precondition failure (paused, not allowlisted, zero address, zero
///         amount, or insufficient committed balance on debit).
interface IEthosRewards {
  /// @notice Increments `user`'s aggregate committed balance by `amount`.
  /// @param user   The end user whose committed balance is being incremented.
  /// @param amount The amount to credit. Must be non-zero.
  function credit(address user, uint256 amount) external;

  /// @notice Decrements `user`'s aggregate committed balance by `amount`.
  /// @param user   The end user whose committed balance is being decremented.
  /// @param amount The amount to debit. Must be non-zero and ≤ committedBalance[user].
  function debit(address user, uint256 amount) external;
}
