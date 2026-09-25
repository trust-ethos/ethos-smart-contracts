// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {IWhuffieLockList} from "./interfaces/IWhuffieLockList.sol";

/// @title WhuffieLockList
/// @author Ethos Network
/// @notice The set of accounts whose outbound WHUF transfers stay locked until listing.
///         The owner (the Ethos owner Safe) can add accounts; there is no removal path by design.
/// @dev Not upgradeable.
/// @custom:security-contact security@ethos.network
contract WhuffieLockList is IWhuffieLockList, Ownable {
  // --- Events ---

  /// @notice Emitted for each account added to the list, including ones already listed.
  /// @param account Address whose outbound transfers are locked until listing.
  event AccountLocked(address indexed account);

  // --- Storage ---

  /// @inheritdoc IWhuffieLockList
  mapping(address account => bool locked) public isLocked;

  // --- Constructor ---

  /// @notice Deploys an empty list.
  /// @param owner_ Address allowed to add accounts.
  constructor(address owner_) Ownable(owner_) {}

  // --- List administration ---

  /// @notice Adds accounts to the list. Call repeatedly to load the list in batches.
  /// @dev Keep batches at or under 500: each new account is a cold SSTORE (~22k gas) and Base
  ///      caps a transaction at 16,777,216 gas.
  /// @param accounts Addresses whose outbound transfers are locked until listing.
  function lock(address[] calldata accounts) external onlyOwner {
    for (uint256 i = 0; i < accounts.length; i++) {
      isLocked[accounts[i]] = true;
      emit AccountLocked(accounts[i]);
    }
  }
}
