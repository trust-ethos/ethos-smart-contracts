// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {
  AccessControlEnumerableUpgradeable
} from "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlEnumerableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

import {IContractAddressManager} from "../interfaces/IContractAddressManager.sol";
import {IPausable} from "../interfaces/IPausable.sol";
import {NotPendingOwner, NotInteractionControl, RenounceNotAllowed} from "../errors/AccessControlV2Errors.sol";
import {SignatureControl} from "./SignatureControl.sol";
import {ETHOS_INTERACTION_CONTROL} from "./Constants.sol";

/**
 * @title AccessControlV2
 * @author Ethos Network
 * @notice Role-based access control with 2-step ownership transfer for Ethos v2 contracts.
 * @dev DEFAULT_ADMIN_ROLE is intentionally never granted — this prevents external
 *      grantRole/revokeRole calls from bypassing the 2-step ownership transfer.
 *      WARNING: NOT storage-compatible with v1 AccessControl.
 * @custom:security-contact security@ethos.network
 */
abstract contract AccessControlV2 is
  IPausable,
  PausableUpgradeable,
  AccessControlEnumerableUpgradeable,
  SignatureControl
{
  // --- Constants ---

  /// @notice Role identifier for the contract owner.
  bytes32 public constant OWNER_ROLE = keccak256("OWNER_ROLE");
  /// @notice Role identifier for contract administrators.
  bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

  // --- Events ---

  /// @notice Emitted when a two-step ownership transfer is initiated.
  /// @param previousOwner Current owner starting the transfer.
  /// @param newOwner Proposed new owner.
  event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
  /// @notice Emitted when an ownership transfer is accepted by the new owner.
  /// @param previousOwner Former owner.
  /// @param newOwner New owner.
  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
  /// @notice Emitted when a pending ownership transfer is cancelled.
  /// @param cancelledOwner Address whose pending transfer was cancelled.
  event OwnershipTransferCancelled(address indexed cancelledOwner);
  /// @notice Emitted when the contract address manager is updated.
  /// @param newAddress New contract address manager.
  event ContractAddressManagerUpdated(address indexed newAddress);
  /// @notice Emitted when the expected signer for signature verification is updated.
  /// @param newSigner New expected signer address.
  event ExpectedSignerUpdated(address indexed newSigner);
  /// @notice Emitted when the signature verifier contract is updated.
  /// @param newVerifier New signature verifier address.
  event SignatureVerifierUpdated(address indexed newVerifier);

  // --- Storage ---

  /// @notice Registry for resolving sibling contract addresses.
  IContractAddressManager public contractAddressManager;
  /// @notice Address of the pending owner during a two-step transfer.
  address public pendingOwner;

  uint256[50] private __gap;

  // --- Modifiers ---

  modifier onlyOwner() {
    _checkRole(OWNER_ROLE);
    _;
  }

  modifier onlyAdmin() {
    _checkRole(ADMIN_ROLE);
    _;
  }

  modifier onlyInteractionControl() {
    address interactionsControlAddr = contractAddressManager.getContractAddressForName(ETHOS_INTERACTION_CONTROL);

    if (interactionsControlAddr != msg.sender) {
      revert NotInteractionControl(msg.sender);
    }

    _;
  }

  // --- Constructor ---

  /**
   * @dev Disables initializers on the implementation contract to prevent
   *      direct initialization (only proxy initialization is allowed).
   */
  constructor() {
    _disableInitializers();
  }

  // --- Initialization ---

  /// @notice Parameters for AccessControlV2 initialization.
  struct AccessControlInitParams {
    address owner;
    address admin;
    address expectedSigner;
    address signatureVerifier;
    address contractAddressManager;
  }

  /**
   * @notice Initializes access control, signature verification, and contract address manager.
   * @param p Initialization parameters.
   */
  // solhint-disable-next-line func-name-mixedcase
  function __accessControl_init(AccessControlInitParams calldata p) internal onlyInitializing {
    if (p.owner == address(0) || p.admin == address(0) || p.contractAddressManager == address(0)) {
      revert ZeroAddress();
    }

    __signatureControl_init(p.expectedSigner, p.signatureVerifier);

    contractAddressManager = IContractAddressManager(p.contractAddressManager);

    _grantRole(OWNER_ROLE, p.owner);
    _grantRole(ADMIN_ROLE, p.admin);
  }

  // --- 2-step ownership transfer ---

  /**
   * @notice Initiates a 2-step ownership transfer, or cancels a pending one
   *         by passing address(0). The new owner must call acceptOwnership.
   * @param newOwner Address of the proposed new owner, or address(0) to cancel.
   */
  function transferOwnership(address newOwner) external onlyOwner {
    address previousPending = pendingOwner;
    if (previousPending != address(0)) {
      emit OwnershipTransferCancelled(previousPending);
    }
    pendingOwner = newOwner;
    if (newOwner != address(0)) {
      emit OwnershipTransferStarted(msg.sender, newOwner);
    }
  }

  /**
   * @notice Completes the 2-step ownership transfer. Must be called by the
   *         address previously set via transferOwnership.
   * @dev Assumes exactly one OWNER_ROLE member (enforced by DEFAULT_ADMIN_ROLE
   *      being unassigned, preventing external grantRole on OWNER_ROLE).
   */
  function acceptOwnership() external {
    if (msg.sender != pendingOwner) {
      revert NotPendingOwner(msg.sender, pendingOwner);
    }
    address previousOwner = getRoleMember(OWNER_ROLE, 0);
    _revokeRole(OWNER_ROLE, previousOwner);
    _grantRole(OWNER_ROLE, msg.sender);
    pendingOwner = address(0);
    emit OwnershipTransferred(previousOwner, msg.sender);
  }

  // --- Admin management ---

  /**
   * @notice Adds an admin address.
   * @param admin Admin address to be added.
   */
  function addAdmin(address admin) external onlyOwner onlyNonZeroAddress(admin) {
    _grantRole(ADMIN_ROLE, admin);
  }

  /**
   * @notice Removes an admin address.
   * @param admin Admin address to be removed.
   */
  function removeAdmin(address admin) external onlyOwner onlyNonZeroAddress(admin) {
    _revokeRole(ADMIN_ROLE, admin);
  }

  // --- Contract address management ---

  /**
   * @notice Updates the ContractAddressManager reference.
   * @param contractAddressesAddr New ContractAddressManager address.
   */
  function updateContractAddressManager(address contractAddressesAddr)
    external
    onlyOwner
    onlyNonZeroAddress(contractAddressesAddr)
  {
    contractAddressManager = IContractAddressManager(contractAddressesAddr);
    emit ContractAddressManagerUpdated(contractAddressesAddr);
  }

  // --- Signature verification ---

  /**
   * @notice Updates the expected signer for signature verification.
   * @param signer New signer address.
   */
  function updateExpectedSigner(address signer) external onlyOwner onlyNonZeroAddress(signer) {
    _updateExpectedSigner(signer);
    emit ExpectedSignerUpdated(signer);
  }

  /**
   * @notice Updates the signature verifier contract address.
   * @param signatureVerifierAddr New SignatureVerifier address.
   */
  function updateSignatureVerifier(address signatureVerifierAddr)
    external
    onlyOwner
    onlyNonZeroAddress(signatureVerifierAddr)
  {
    _updateSignatureVerifier(signatureVerifierAddr);
    emit SignatureVerifierUpdated(signatureVerifierAddr);
  }

  // --- Role management override ---

  /**
   * @notice Disabled. Prevents accidental bricking by self-removal of OWNER_ROLE.
   * @dev Always reverts. Use transferOwnership/acceptOwnership for ownership changes,
   *      and removeAdmin for admin removal.
   */
  function renounceRole(bytes32, address) public virtual override(AccessControlUpgradeable, IAccessControl) {
    revert RenounceNotAllowed();
  }

  // --- Pausable ---

  /// @notice Pauses the contract. Only callable by the InteractionControl contract.
  function pause() external onlyInteractionControl {
    super._pause();
  }

  /// @notice Unpauses the contract. Only callable by the InteractionControl contract.
  function unpause() external onlyInteractionControl {
    super._unpause();
  }

  /// @inheritdoc IPausable
  function paused() public view override(IPausable, PausableUpgradeable) returns (bool) {
    return super.paused();
  }
}
