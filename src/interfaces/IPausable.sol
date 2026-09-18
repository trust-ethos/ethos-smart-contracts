// SPDX-License-Identifier: MIT
pragma solidity 0.8.26 || 0.8.33;

/*
 * @dev Interface for IPausable Smart Contract.
 */

interface IPausable {
  function paused() external view returns (bool);

  function pause() external;

  function unpause() external;
}
