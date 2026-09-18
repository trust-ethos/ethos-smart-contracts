// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

/// @notice Caller is not the EthosVouchV2 contract registered in
///         ContractAddressManager under ETHOS_VOUCH_V2.
/// @param caller     The unauthorized caller.
/// @param authorized The currently registered ETHOS_VOUCH_V2 address (may be zero
///                   if no contract is registered).
error UnauthorizedAccruingCaller(address caller, address authorized);

/// @notice A debit would reduce the user's committed balance below zero.
/// @param user      The user whose balance was checked.
/// @param requested The debit amount that was requested.
/// @param available The user's current committed balance.
error InsufficientCommittedBalance(address user, uint256 requested, uint256 available);

/// @notice The caller has no pending rewards to claim.
error NoRewardsToClaim();

/// @notice An emission rate exceeds the soft sanity cap.
/// @param provided The requested emission rate in basis points.
/// @param maximum  MAX_EMISSION_RATE_BPS.
error EmissionRateTooHigh(uint256 provided, uint256 maximum);

/// @notice The contract's live reward-token balance cannot cover already-accrued rewards.
/// @param currentBalance The current reward-token balance held by the contract.
/// @param accruedRewards Rewards already accrued and not yet claimed.
error InsufficientRewardBalance(uint256 currentBalance, uint256 accruedRewards);

/// @notice A credit or debit was called with a zero amount.
error ZeroAmount();
