// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

/// @title IFreezable
/// @notice Minimal interface for contracts that support freezing accounts under slasher control.
///         Freezing is a coordination primitive — it restricts user-initiated actions that could
///         defeat an in-flight slash (e.g. unvouching, unattesting, disconnecting wallets) while
///         the slashing process completes. The concrete semantics of what freezing blocks are
///         owned by the implementing contract.
interface IFreezable {
  /// @notice Emitted when an account's frozen state changes.
  /// @param account   Address whose frozen state changed.
  /// @param isFrozen  True if the account is now frozen, false if unfrozen.
  event Frozen(address indexed account, bool isFrozen);

  /// @notice Freezes `account`. Only callable by the registered slasher.
  /// @param account Address to freeze.
  function freeze(address account) external;

  /// @notice Unfreezes `account`. Only callable by the registered slasher.
  /// @param account Address to unfreeze.
  function unfreeze(address account) external;

  /// @notice Returns whether `account` is currently frozen.
  /// @param account Address to query.
  /// @return True if frozen, false otherwise.
  function isFrozen(address account) external view returns (bool);
}
