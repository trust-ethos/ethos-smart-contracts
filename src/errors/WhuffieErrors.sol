// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

/// @notice Thrown when batch array lengths do not match.
/// @param recipientsLength Length of the recipients array.
/// @param amountsLength Length of the amounts array.
error ArrayLengthMismatch(uint256 recipientsLength, uint256 amountsLength);

/// @notice Thrown when a required address is zero.
error ZeroAddress();

/// @notice Thrown when a transfer is attempted before transfers are unlocked,
///         the sender is on the lock list, and no exemption applies.
/// @param from Sender of the disallowed transfer.
/// @param to Recipient of the disallowed transfer.
error TransfersLocked(address from, address to);

/// @notice Thrown when unlockTransfers is called after transfers are already unlocked.
error TransfersAlreadyUnlocked();
