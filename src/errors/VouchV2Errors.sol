// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

/// @notice Thrown when an author already has an active vouch for the given target.
/// @param author The author address.
/// @param targetHash The keccak256 hash of the target string.
error AlreadyVouched(address author, bytes32 targetHash);

/// @notice Thrown when attempting to unvouch an already-archived vouch.
/// @param vouchId The ID of the archived vouch.
error VouchAlreadyArchived(uint256 vouchId);

/// @notice Thrown when the caller is not the author of the vouch.
/// @param caller The address that attempted the call.
/// @param expected The address of the vouch author.
error UnauthorizedVouchAccess(address caller, address expected);

/// @notice Thrown when an author's active vouch count is at the maximum.
/// @param author The author address.
/// @param maximum The configured maximum number of vouches.
error MaxVouchesExceeded(address author, uint256 maximum);

/// @notice Thrown when the provided amount is below the configured minimum.
/// @param provided The amount provided by the caller.
/// @param minimum The configured minimum vouch amount.
error AmountBelowMinimum(uint256 provided, uint256 minimum);

/// @notice Thrown when a vouch creation or increase would push the per-vouch
///         balance above the configured maximum.
/// @param provided The balance the call would produce (gross of fee, net of stake).
/// @param maximum  The configured maximum vouch amount.
error AmountAboveMaximum(uint256 provided, uint256 maximum);

/// @notice Thrown when the combined fee bps would exceed the maximum allowed.
/// @param bps The bps value that would be set.
/// @param max The maximum allowed combined bps.
error FeeBpsTooHigh(uint256 bps, uint256 max);

/// @notice Thrown when a fee-on-transfer token is detected via balance delta check.
/// @param expected The expected post-transfer balance delta.
/// @param actual The actual post-transfer balance delta.
error UnexpectedTokenBehavior(uint256 expected, uint256 actual);

/// @notice Thrown when the vouch ID does not exist.
/// @param vouchId The vouch ID that was not found.
error VouchNotFound(uint256 vouchId);

/// @notice Thrown at initialize when the token does not expose ERC20Burnable.burn.
/// @param token The ERC-20 token that failed the burn(0) probe.
error TokenNotBurnable(address token);

/// @notice Thrown when a basis-point value exceeds BASIS_POINT_SCALE (10_000).
/// @param bps The rejected basis-point value.
error InvalidBps(uint256 bps);

/// @notice Thrown when maximumVouches would exceed the supported uint32 range.
/// @param provided The rejected value.
error MaximumVouchesOutOfRange(uint256 provided);

/// @notice Thrown when a non-zero amount was required but zero was provided.
error ZeroAmount();

/// @notice Thrown when a decrease would withdraw more than the vouch's current balance.
/// @param requested The amount the caller asked to remove.
/// @param balance   The current vouch balance.
error AmountExceedsBalance(uint256 requested, uint256 balance);

/// @notice Thrown when a decrease would leave the remaining balance below the
///         configured minimum. Forces full exits onto `unvouch`.
/// @param remaining The balance that would remain after the decrease.
/// @param minimum   The configured minimum vouch amount.
error RemainingBelowMinimum(uint256 remaining, uint256 minimum);

/// @notice Thrown when neither the permit nor any pre-existing allowance covers
///         `amount + entry fee` in vouchWithPermit / increaseVouchWithPermit.
/// @param owner    The would-be permit owner.
/// @param required The allowance required (amount + entry fee).
error InsufficientPermitAllowance(address owner, uint256 required);

/// @notice Thrown by `vouchFor` when the caller is not registered in the
///         ContractAddressManager as an Ethos protocol contract.
/// @param caller The address that attempted the call.
error UnauthorizedComposer(address caller);

/// @notice Thrown by `vouchFor` when the supplied author is the zero address.
error InvalidAuthor();
