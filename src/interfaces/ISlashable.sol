// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {IFreezable} from "./IFreezable.sol";

/// @title ISlashable
/// @notice Interface for contracts that can be slashed by the registered slasher.
///         Extends IFreezable — every slashable contract must also support freezing,
///         since freezing is the coordination primitive that protects an in-flight
///         slash from being defeated by the account.
interface ISlashable is IFreezable {
  /// @notice Slashes `bps` of `account`'s total stake in this contract.
  /// @dev Implementers decide how to apply the slash (burn, redistribute, etc.) and
  ///      over what positions. `bps` is validated against BASIS_POINT_SCALE (10_000)
  ///      by the implementer. Freezing does NOT gate slashing — the slasher may slash
  ///      a non-frozen account, though typical flow freezes first.
  /// @param account       Address whose stake is slashed.
  /// @param bps           Slash percentage in basis points. Implementers revert if > 10_000.
  /// @return amountApplied Total amount deducted across the account's positions, in
  ///                       the implementing contract's unit of account (token base units
  ///                       for EthosVouchV2). Zero if the account had no stake.
  function slash(address account, uint256 bps) external returns (uint256 amountApplied);
}
