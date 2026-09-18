// SPDX-License-Identifier: MIT

pragma solidity 0.8.26 || 0.8.33;

interface IEthosVouchV2 {
  function vouchFor(address author, string calldata target, uint256 amount, string calldata metadata) external;

  function previewVouchFee(uint256 amount) external view returns (uint256 fee, uint256 gross);
}
