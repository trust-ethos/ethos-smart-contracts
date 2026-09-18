// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

/// @notice Thrown when a signature has expired.
/// @param deadline The deadline that was exceeded.
/// @param currentTime The current block timestamp.
error SignatureExpired(uint256 deadline, uint256 currentTime);
