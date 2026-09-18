// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

/// @notice Thrown when a non-market address attempts a mint or burn.
error OnlyMarket();

/// @notice Thrown when a transfer targets the zero address.
error TransferToZeroAddress();

/// @notice Thrown when a transfer targets the market contract.
error TransferToMarket();
