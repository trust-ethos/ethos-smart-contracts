// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

/// @notice Thrown when the caller is not the pending owner.
/// @param caller The address that attempted to accept ownership.
/// @param pendingOwner The address that is allowed to accept.
error NotPendingOwner(address caller, address pendingOwner);

/// @notice Thrown when the caller is not the InteractionControl contract.
/// @param caller The address that attempted the call.
error NotInteractionControl(address caller);

/// @notice Thrown when renounceRole is called (disabled to prevent bricking).
error RenounceNotAllowed();
