// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

/// @notice Thrown when the caller is not the registered slasher.
/// @param caller  The address that attempted the call.
/// @param slasher The address of the registered slasher.
error NotSlasher(address caller, address slasher);

/// @notice Thrown when a frozen account attempts a restricted action.
/// @param account The frozen account address.
error AccountFrozen(address account);
