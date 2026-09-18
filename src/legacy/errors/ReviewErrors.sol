// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

error WrongPaymentAmount(address paymentToken, uint256 amount);
error WrongPaymentToken(address paymentToken);
error UnexpectedTokenBehavior(uint256 expected, uint256 actual);
error InsufficientPermitAllowance(address owner, uint256 required);
error TokenNotBurnable(address token);
error InvalidReviewDetails(string message);
error SelfReview(address subject);
error ReviewNotFound(uint256 reviewId);
error ReviewIsArchived(uint256 reviewId);
error ReviewNotArchived(uint256 reviewId);
error MustCreateAttestationFirst();
error UnauthorizedEdit(uint256 reviewId);

/// @notice Thrown when EthosVouchV2 is not registered in ContractAddressManager.
error VouchV2NotRegistered();

/// @notice Thrown when the permit's signed value does not equal the actual on-chain
///         total (reviewFee + vouchAmount + vouchEntryFee) at submit time.
/// @param permitted The value the caller signed in the permit.
/// @param actual    The actual total computed from current on-chain fees.
error PermitValueMismatch(uint256 permitted, uint256 actual);

/// @notice Thrown by `reviewAndVouchWithPermit` when `vouchAmount` is zero.
///         Composite means both legs; standalone reviews must use `addReview`
///         or `addReviewWithPermit`.
error ZeroVouchAmount();

/// @notice Thrown by `reviewAndVouchWithPermit` when the review score is not Positive.
error VouchRequiresPositiveReview();
