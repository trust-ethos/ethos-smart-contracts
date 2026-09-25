// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

/// @title IWhuffieLockList
/// @notice Read surface EthosWhuffie uses to decide whether an account's outbound transfers are locked.
interface IWhuffieLockList {
  /// @notice Whether the account's outbound WHUF transfers are locked until listing.
  /// @param account Address to check.
  /// @return True if the account is on the list.
  function isLocked(address account) external view returns (bool);
}
