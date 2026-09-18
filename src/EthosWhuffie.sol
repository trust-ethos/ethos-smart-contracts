// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {
  ERC20BurnableUpgradeable
} from "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20BurnableUpgradeable.sol";
import {
  ERC20CappedUpgradeable
} from "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20CappedUpgradeable.sol";
import {
  ERC20PermitUpgradeable
} from "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

import {IContractAddressManager} from "./interfaces/IContractAddressManager.sol";
import {ArrayLengthMismatch, TransfersAlreadyUnlocked, TransfersLocked, ZeroAddress} from "./errors/WhuffieErrors.sol";
import {ETHOS_REVIEW, ETHOS_VOUCH_V2} from "./utils/Constants.sol";

/// @title EthosWhuffie
/// @author Ethos Network
/// @notice Capped ERC-20 currency token for Ethos v2.
///         Ships in a transfer-locked state: holders cannot transfer until the owner
///         calls unlockTransfers exactly once. While locked, mints and burns still flow,
///         and transfers touching EthosVouchV2 or pulled by EthosReview into itself
///         (any fee-charging entrypoint) are permitted through
///         ContractAddressManager-resolved exemptions.
/// @custom:security-contact security@ethos.network
contract EthosWhuffie is
  ERC20Upgradeable,
  ERC20CappedUpgradeable,
  ERC20BurnableUpgradeable,
  ERC20PermitUpgradeable,
  PausableUpgradeable,
  Ownable2StepUpgradeable,
  UUPSUpgradeable
{
  // --- Constants ---

  /// @notice Contract version for reinitializer tracking.
  uint256 public constant VERSION = 1;

  /// @notice ERC-20 display name and EIP-712 permit domain name.
  string public constant TOKEN_NAME = "Whuffie";

  /// @notice ERC-20 display symbol.
  string public constant TOKEN_SYMBOL = "WHUF";

  // --- Events ---

  /// @notice Emitted once when the owner permanently unlocks transfers.
  /// @param owner     The owner that unlocked transfers.
  /// @param timestamp The block timestamp at which transfers were unlocked.
  event TransfersUnlocked(address indexed owner, uint256 timestamp);

  // --- Storage ---

  /// @notice Registry used to resolve launch-lock transfer exemptions.
  IContractAddressManager public contractAddressManager;

  /// @notice True once the owner has permanently unlocked transfers. Cannot revert to false.
  bool public transfersUnlocked;

  /// @dev Storage gap for future upgrades.
  uint256[50] private __gap;

  // --- Constructor ---

  /// @dev Disables initializers on the implementation contract.
  constructor() {
    _disableInitializers();
  }

  // --- Initialization ---

  /// @notice Initializes the WHUF token.
  /// @param owner_ Address that can mint, pause, unpause, and authorize upgrades.
  /// @param contractAddressManager_ Registry used to resolve locked-transfer exemptions.
  /// @param cap_ Maximum total WHUF supply in base units.
  function initialize(address owner_, address contractAddressManager_, uint256 cap_) external initializer {
    if (contractAddressManager_ == address(0)) revert ZeroAddress();

    __ERC20_init(TOKEN_NAME, TOKEN_SYMBOL);
    __ERC20Capped_init(cap_);
    __ERC20Burnable_init();
    __ERC20Permit_init(TOKEN_NAME);
    __Pausable_init();
    __Ownable_init(owner_);
    __Ownable2Step_init();
    __UUPSUpgradeable_init();

    contractAddressManager = IContractAddressManager(contractAddressManager_);
  }

  // --- Minting ---

  /// @notice Mints WHUF to an account.
  /// @param recipient Address to receive minted WHUF.
  /// @param amount Amount to mint in base units.
  function mint(address recipient, uint256 amount) external onlyOwner {
    _mint(recipient, amount);
  }

  /// @notice Mints WHUF to multiple accounts.
  /// @param recipients Addresses to receive minted WHUF.
  /// @param amounts Amounts to mint in base units.
  function mintBatch(address[] calldata recipients, uint256[] calldata amounts) external onlyOwner {
    if (recipients.length != amounts.length) {
      revert ArrayLengthMismatch(recipients.length, amounts.length);
    }

    for (uint256 i = 0; i < recipients.length; i++) {
      _mint(recipients[i], amounts[i]);
    }
  }

  // --- Pausable ---

  /// @notice Pauses transfers, minting, and burning.
  function pause() external onlyOwner {
    _pause();
  }

  /// @notice Unpauses transfers, minting, and burning.
  function unpause() external onlyOwner {
    _unpause();
  }

  // --- Transfer lock administration ---

  /// @notice Permanently unlocks transfers. Callable exactly once by the owner.
  /// @dev Intentionally takes no arguments and accepts no schedule. The contract is
  ///      locked until the owner explicitly turns transfers on, removing schedule
  ///      misconfiguration risk. There is no relock path.
  function unlockTransfers() external onlyOwner {
    if (transfersUnlocked) revert TransfersAlreadyUnlocked();
    transfersUnlocked = true;
    emit TransfersUnlocked(_msgSender(), block.timestamp);
  }

  // --- Pause, lock, and cap enforcement ---

  /// @dev Centralizes pause and transfer-lock on every balance change: mints, burns,
  ///      and transfers all flow through _update, so gating here covers OZ's
  ///      ERC20Burnable (burn/burnFrom) and plain transfers without per-function
  ///      modifiers. While transfersUnlocked is false, only mints (from == 0), burns
  ///      (to == 0), transfers where EthosVouchV2 is the sender or recipient, and
  ///      EthosReview fee pulls into itself (any entrypoint, standalone or composite —
  ///      indistinguishable at this layer) are permitted. Missing CAM registrations
  ///      resolve to address(0), which does not exempt ordinary transfers.
  function _update(address from, address to, uint256 value)
    internal
    override(ERC20Upgradeable, ERC20CappedUpgradeable)
    whenNotPaused
  {
    if (!transfersUnlocked && from != address(0) && to != address(0)) {
      address vouch = contractAddressManager.getContractAddressForName(ETHOS_VOUCH_V2);
      address review = contractAddressManager.getContractAddressForName(ETHOS_REVIEW);
      bool isVouchTransfer = from == vouch || to == vouch;
      bool isReviewFeePull = to == review && _msgSender() == review;
      if (!isVouchTransfer && !isReviewFeePull) revert TransfersLocked(from, to);
    }

    super._update(from, to, value);
  }

  // --- UUPS ---

  /// @notice Authorizes upgrade to a new implementation.
  function _authorizeUpgrade(address) internal override onlyOwner {}
}
