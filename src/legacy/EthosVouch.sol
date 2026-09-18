// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ITargetStatus} from "../interfaces/ITargetStatus.sol";
import {IEthosProfile} from "../interfaces/IEthosProfile.sol";
import {ETHOS_PROFILE} from "../utils/Constants.sol";
import {AccessControl} from "../utils/AccessControl.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {ProfileNotFoundForAddress} from "./errors/ProfileErrors.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @notice Represents a trust relationship between profiles backed by staked ETH, where one profile (author)
 * vouches for another profile (subject). The stake amount represents the magnitude of trust, making
 * credibility a function of stake value rather than number of vouchers.
 *
 * Core Philosophy:
 * - Long-standing mutually beneficial relationships are the best indicators of trust
 * - Penalties should be proportional; not all infractions warrant complete reputation loss
 * - Financial stakes force intentional trust allocation decisions
 * - Credibility is based on stake value, not popularity (e.g., 1 vouch of 10,000Ξ = 10,000 vouches of 1Ξ)
 * - Mutual vouching (3,3) magnifies credibility and rewards for both parties
 *
 * Requirements:
 * - Author must have a valid profile
 * - Subject must have a valid profile or be a mock profile created via address/attestation review
 * - Vouch amount must meet minimum configured amount (>= 0.0001 ETH)
 * - Author cannot exceed maximum allowed vouches (max 256)
 * - Subject cannot exceed maximum allowed vouches
 * - Author cannot vouch for the same subject multiple times
 * - Author cannot vouch for an archived profile
 *
 * Features:
 * - Supports vouching by profile ID or address
 * - Allows increasing vouch amount
 * - Supports unvouching (withdrawal) with a limited time period for marking as unhealthy
 * - Handles fee distribution (protocol, donation, vouchers pool)
 * - Manages rewards/incentives for vouchers
 * - Supports slashing up to 10% of total stake for validated unethical behavior
 *
 * Fee Structure:
 * - Protocol Fee: Sent to protocol treasury for operational costs
 * - Donation Fee: Direct reward to subject profile, claimable via rewards system
 * - Vouchers Pool Fee: Distributed proportionally among existing vouchers
 * - Exit Fee: Charged on withdrawals, sent to protocol treasury
 *
 * Slashing Mechanism:
 * - Only another Ethos contract is authorized to handle slashing
 * - Maximum slash is 10% of total staked amount
 * - Only way staked funds can be withdrawn without explicit owner approval
 * - Intended to be rare - negative reviews/unvouching preferred first
 * - Context: https://whitepaper.ethos.network/ethos-mechanisms/slash
 *
 * Access Control:
 * - Only vouch author can unvouch or mark unhealthy
 * - Only authorized slasher contract can slash vouches (up to 10% of author's total stake)
 * - Only admin can configure fees and limits
 *
 * Important Notes:
 * - Subject does not control the staked funds (cannot withdraw/spend/reallocate)
 * - Unvouching requires full withdrawal of staked amount
 * - Vouches that end due to distrust can be marked as "unhealthy" within a limited time period
 *
 * @notice See https://whitepaper.ethos.network/ethos-mechanisms/vouch for original design
 */
contract EthosVouch is AccessControl, UUPSUpgradeable, ITargetStatus, ReentrancyGuard {
  /**
   * @dev Constructor that disables initializers when the implementation contract is deployed.
   * This prevents the implementation contract from being initialized, which is important for
   * security since the implementation contract should never be used directly, only through
   * delegatecall from the proxy.
   */
  constructor() {
    _disableInitializers();
  }

  using Math for uint256;

  /**
   * @dev Tracks timestamps for key vouch activities
   * @param vouchedAt Timestamp when the vouch was created
   * @param unvouchedAt Timestamp when the vouch was withdrawn
   * @param unhealthyAt Timestamp when the vouch was marked unhealthy
   */
  struct ActivityCheckpoints {
    uint256 vouchedAt;
    uint256 unvouchedAt;
    uint256 unhealthyAt;
  }

  /**
   * @dev Represents a single vouch relationship between two profiles
   * @param archived Whether the vouch has been withdrawn
   * @param unhealthy Whether the vouch was marked as unhealthy after withdrawal
   * @param authorProfileId Profile ID of the vouching party
   * @param authorAddress Address of the vouching party
   * @param vouchId Unique identifier for this vouch
   * @param subjectProfileId Profile ID being vouched for
   * @param balance Current staked amount in wei
   * @param comment Optional text comment about the vouch
   * @param metadata Additional structured metadata about the vouch
   * @param activityCheckpoints Timestamps for key vouch activities
   */
  struct Vouch {
    bool archived;
    bool unhealthy;
    uint256 authorProfileId;
    address authorAddress;
    uint256 vouchId;
    uint256 subjectProfileId;
    uint256 balance;
    string comment;
    string metadata;
    ActivityCheckpoints activityCheckpoints;
  }

  // --- Constants ---
  uint256 private constant ABSOLUTE_MINIMUM_VOUCH_AMOUNT = 0.0001 ether;
  // 1000 basis points = 10% max fees
  uint256 public constant MAX_TOTAL_FEES = 1000;
  uint256 public constant BASIS_POINT_SCALE = 10000;
  // 1000 basis points = 10% max slash
  uint256 public constant MAX_SLASH_PERCENTAGE = 1000;

  // --- State Variables ---
  /// @notice Minimum amount that must be staked for a vouch in wei
  uint256 public configuredMinimumVouchAmount;
  /// @notice Total number of vouches ever created
  uint256 public vouchCount;
  /// @notice Time period after unvouching during which a vouch can be marked unhealthy
  uint256 public unhealthyResponsePeriod;
  /// @notice Maximum number of vouches allowed per profile
  uint256 public maximumVouches;
  /// @notice Address where protocol fees are sent
  address public protocolFeeAddress;
  /// @notice Protocol fee in basis points (100 = 1%) charged on entry
  uint256 public entryProtocolFeeBasisPoints;
  /// @notice Donation fee in basis points charged on entry
  uint256 public entryDonationFeeBasisPoints;
  /// @notice Fee in basis points distributed to existing vouchers on entry
  uint256 public entryVouchersPoolFeeBasisPoints;
  /// @notice Fee in basis points charged on exit/withdrawal
  uint256 public exitFeeBasisPoints;

  // --- Mappings ---
  /**
   * @notice Maps vouch IDs to their full vouch data
   */
  mapping(uint256 => Vouch) public vouches;

  /**
   * @notice Maps author profile IDs to their list of vouch IDs
   * @dev authorProfileId => vouchIds
   */
  mapping(uint256 => uint256[]) public vouchIdsByAuthor;

  /**
   * @notice Maps author profile IDs and vouch IDs to their index in the vouchIdsByAuthor array
   * @dev authorProfileId => vouchId => vouchIdsByAuthor index
   */
  mapping(uint256 => mapping(uint256 => uint256)) public vouchIdsByAuthorIndex;

  /**
   * @notice Maps subject profile IDs to the list of vouch IDs vouching for them
   * @dev subjectProfileId => vouchIds
   */
  mapping(uint256 => uint256[]) public vouchIdsForSubjectProfileId;

  /**
   * @notice Maps subject profile IDs and vouch IDs to their index in the vouchIdsForSubjectProfileId array
   * @dev authorProfileId => subjectProfileId => vouchId
   */
  mapping(uint256 => mapping(uint256 => uint256)) public vouchIdsForSubjectProfileIdIndex;

  /**
   * @notice Maps author profile IDs and subject profile IDs to their active vouch ID
   * @dev authorProfileId => subjectProfileId => vouchId (active vouches between author and subject)
   */
  mapping(uint256 => mapping(uint256 => uint256)) public vouchIdByAuthorForSubjectProfileId;

  /**
   * @notice Maps profile IDs to their rewards balance in ETH
   * @dev Balances are Eth only; no ERC20 support. Maps Ethos profile IDs to their rewards balances.
   */
  mapping(uint256 => uint256) public rewardsByProfileId;
  /**
   * @notice Maps attestation hashes to their rewards balance
   * Only used when vouching for mock profiles
   */
  mapping(bytes32 => uint256) public rewardsByAttestationHash;
  /**
   * @notice Maps address to their rewards balance
   * Only used when vouching for mock profiles
   */
  mapping(address => uint256) public rewardsByAddress;

  /*
   * @notice Maps author profile IDs to their frozen status, preventing withdrawals before slashing
   * @dev authorProfileId => isFrozen
   */
  mapping(uint256 => bool) public frozenAuthors;

  /*
   * @notice Maps vouch IDs to their attestation hash, tracking which vouches were created by attestation
     note: once an attestation is claimed, vouches are then associated with the claiming profile
   * @dev vouchId => attestationHash
   */
  mapping(uint256 => bytes32) public vouchAttestationHash;

  // Add storage gap as the last storage variable
  // This allows us to add new storage variables in future upgrades
  // by reducing the size of this gap
  // NOTE: gap reduced by 1 to allow for the addition of the new vouchAttestationHash mapping
  uint256[49] private __gap;

  // --- Error Codes ---
  error InvalidEthosProfileForVouch(uint256 ethosProfileId);
  error AlreadyVouched(uint256 author, uint256 voucheeEthosProfileId);
  error SelfVouch(uint256 author, uint256 voucheeEthosProfileId);
  error VouchNotFound(uint256 vouchId);
  error NotAuthorForVouch(uint256 vouchId, uint256 user);
  error WrongSubjectProfileIdForVouch(uint256 vouchId, uint256 subjectProfileId);
  error CannotMarkVouchAsUnhealthy(uint256 vouchId);
  error AlreadyUnvouched(uint256 vouchId);
  error InvalidFeeMultiplier(uint256 newFee);
  error MinimumVouchAmount(uint256 amount);
  error AddressNotVouchAuthor(uint256 vouchId, address caller, address author);
  error MaximumVouchesExceeded(uint256 vouches, string message);
  error FeesExceedMaximum(uint256 totalFees, uint256 maxFees);
  error FeeTransferFailed(string message);
  error InsufficientRewardsBalance();
  error InsufficientProtocolFeeBalance();
  error InvalidSlashPercentage();
  error InvalidFeeProtocolAddress();
  error NotSlasher();
  error InvalidAttestationHash(bytes32 attestationHash);
  error PendingSlash(uint256 vouchId, uint256 authorProfileId);
  error InvalidSender();

  // --- Events ---
  event Vouched(
    uint256 indexed vouchId,
    uint256 indexed authorProfileId,
    uint256 indexed subjectProfileId,
    address subjectAddress,
    bytes32 attestationHash,
    uint256 amountStaked,
    uint256 amountDeposited
  );

  event VouchIncreased(
    uint256 indexed vouchId,
    uint256 indexed authorProfileId,
    uint256 indexed subjectProfileId,
    address subjectAddress,
    bytes32 attestationHash,
    uint256 amountStaked,
    uint256 amountDeposited
  );

  event Unvouched(
    uint256 indexed vouchId, uint256 indexed authorProfileId, uint256 indexed subjectProfileId, uint256 amountWithdrawn
  );

  event MarkedUnhealthy(uint256 indexed vouchId, uint256 indexed authorProfileId, uint256 indexed subjectProfileId);
  event ProtocolFeeAddressUpdated(address newFeeProtocolAddress);
  event EntryProtocolFeeBasisPointsUpdated(uint256 newProtocolFeeBasisPoints);
  event EntryDonationFeeBasisPointsUpdated(uint256 newDonationFeeBasisPoints);
  event EntryVouchersPoolFeeBasisPointsUpdated(uint256 newVouchersPoolFeeBasisPoints);
  event ExitFeeBasisPointsUpdated(uint256 newExitFeeBasisPoints);
  event DepositedToRewards(uint256 indexed recipientProfileId, uint256 amount);
  event WithdrawnFromRewards(uint256 indexed accountProfileId, uint256 amount);
  event Slashed(uint256 indexed authorProfileId, uint256 slashBasisPoints, uint256 totalSlashed);
  event Frozen(uint256 indexed authorProfileId, bool isFrozen);
  event AttestationVouchMappingUpdated(
    bytes32 indexed attestationHash, uint256 indexed formerProfileId, uint256 indexed newProfileId
  );

  /**
   * @notice Modifier to restrict access to slasher contract only
   */
  modifier onlySlasher() {
    address slasher = contractAddressManager.getContractAddressForName("SLASHER");
    if (msg.sender != slasher) revert NotSlasher();
    _;
  }
  /**
   * @notice Modifier to restrict access to Ethos Profile contract only
   */
  modifier isEthosProfile() {
    if (msg.sender != contractAddressManager.getContractAddressForName("ETHOS_PROFILE")) {
      revert InvalidSender();
    }
    _;
  }

  /**
   * @dev initializer in place of constructor.
   * @param _owner Owner address.
   * @param _admin Admin address.
   * @param _expectedSigner ExpectedSigner address.
   * @param _signatureVerifier SignatureVerifier address.
   * @param _contractAddressManagerAddr ContractAddressManager address.
   */
  function initialize(
    address _owner,
    address _admin,
    address _expectedSigner,
    address _signatureVerifier,
    address _contractAddressManagerAddr,
    address _feeProtocolAddress,
    uint256 _entryProtocolFeeBasisPoints,
    uint256 _entryDonationFeeBasisPoints,
    uint256 _entryVouchersPoolFeeBasisPoints,
    uint256 _exitFeeBasisPoints
  ) external initializer {
    __accessControl_init(_owner, _admin, _expectedSigner, _signatureVerifier, _contractAddressManagerAddr);

    __UUPSUpgradeable_init();
    if (_feeProtocolAddress == address(0)) revert InvalidFeeProtocolAddress();
    protocolFeeAddress = _feeProtocolAddress;
    entryProtocolFeeBasisPoints = _entryProtocolFeeBasisPoints;
    entryDonationFeeBasisPoints = _entryDonationFeeBasisPoints;
    entryVouchersPoolFeeBasisPoints = _entryVouchersPoolFeeBasisPoints;
    exitFeeBasisPoints = _exitFeeBasisPoints;
    configuredMinimumVouchAmount = ABSOLUTE_MINIMUM_VOUCH_AMOUNT;
    maximumVouches = 256;
    unhealthyResponsePeriod = 24 hours;
  }

  /**
   * @notice restricts upgrading to owner
   * @param newImplementation address of new implementation contract
   */
  function _authorizeUpgrade(address newImplementation)
    internal
    override
    onlyOwner
    onlyNonZeroAddress(newImplementation)
  {
    // Intentionally left blank to ensure onlyOwner and zeroCheck modifiers run
  }

  // --- Vouch Functions ---

  /**
   * @notice Vouches by address, allowing vouches for addresses that have not yet joined Ethos (mock profiles)
   * @param subjectAddress The address to vouch for
   * @param comment Optional text comment about the vouch
   * @param metadata Additional structured metadata about the vouch
   */
  function vouchByAddress(address subjectAddress, string calldata comment, string calldata metadata)
    public
    payable
    onlyNonZeroAddress(subjectAddress)
    whenNotPaused
    nonReentrant
  {
    (bool verified, bool archived, bool mock, uint256 subjectProfileId) =
      _ethosProfile().profileStatusByAddress(subjectAddress);

    // you may not vouch for archived profiles
    if (archived) revert InvalidEthosProfileForVouch(subjectProfileId);
    // if verified, use the standard vouchByProfileId
    if (verified) {
      _vouchByProfileIdCommon(subjectProfileId, comment, metadata);
      return;
    }
    // use vouchByAddress or vouchByAttestationHash for mock profiles
    if (!mock) revert InvalidEthosProfileForVouch(subjectProfileId);

    _vouchCommon(subjectProfileId, comment, metadata, bytes32(0), subjectAddress);
  }

  /**
   * @notice Vouches by attestation hash, allowing vouches for social accounts that have not yet joined Ethos (mock profiles)
   * @param attestationHash The attestation hash identifying the subject to vouch for
   * @param comment Optional text comment about the vouch
   * @param metadata Additional structured metadata about the vouch
   */
  function vouchByAttestation(bytes32 attestationHash, string calldata comment, string calldata metadata)
    public
    payable
    whenNotPaused
    nonReentrant
  {
    uint256 attestationProfileId = _ethosProfile().profileIdByAttestation(attestationHash);
    // submitted hash must match the mock profile attestation hash
    (bool verified, bool archived, bool mock) = _ethosProfile().profileStatusById(attestationProfileId);

    // you may not vouch for archived profiles
    if (archived) revert InvalidEthosProfileForVouch(attestationProfileId);
    // this function is only for mock profiles
    if (verified) {
      _vouchByProfileIdCommon(attestationProfileId, comment, metadata);
      return;
    }
    // use vouchByAddress or vouchByAttestationHash for verified profiles
    if (!mock) revert InvalidEthosProfileForVouch(attestationProfileId);

    _vouchCommon(attestationProfileId, comment, metadata, attestationHash, address(0));
  }

  /**
   * @notice Vouches by profile ID, allowing vouches for existing Ethos profiles
   * @param subjectProfileId The profile ID to vouch for
   * @param comment Optional text comment about the vouch
   * @param metadata Additional structured metadata about the vouch
   */
  function vouchByProfileId(uint256 subjectProfileId, string calldata comment, string calldata metadata)
    external
    payable
    whenNotPaused
    nonReentrant
  {
    _vouchByProfileIdCommon(subjectProfileId, comment, metadata);
  }

  function _vouchByProfileIdCommon(uint256 subjectProfileId, string calldata comment, string calldata metadata)
    internal
  {
    (bool verified, bool archived, bool mock) = _ethosProfile().profileStatusById(subjectProfileId);

    // this function is only for verified profiles
    if (!verified) revert InvalidEthosProfileForVouch(subjectProfileId);
    // you may not vouch for archived profiles
    if (archived) revert InvalidEthosProfileForVouch(subjectProfileId);
    // use vouchByAddress or vouchByAttestationHash for mock profiles
    if (mock) revert InvalidEthosProfileForVouch(subjectProfileId);

    _vouchCommon(subjectProfileId, comment, metadata, bytes32(0), address(0));
  }

  function _vouchCommon(
    uint256 subjectProfileId,
    string calldata comment,
    string calldata metadata,
    bytes32 attestationHash,
    address subjectAddress
  ) internal {
    uint256 authorProfileId = _ethosProfile().verifiedProfileIdForAddress(msg.sender);

    // pls no vouch for yourself
    if (authorProfileId == subjectProfileId) {
      revert SelfVouch(authorProfileId, subjectProfileId);
    }

    // users can't exceed the maximum number of vouches
    if (vouchIdsByAuthor[authorProfileId].length >= maximumVouches) {
      revert MaximumVouchesExceeded(vouchIdsByAuthor[authorProfileId].length, "Exceeds author vouch limit");
    }

    // validate subject profile
    if (subjectProfileId == 0) revert InvalidEthosProfileForVouch(subjectProfileId);

    // one vouch per profile per author
    _vouchShouldNotExistFor(authorProfileId, subjectProfileId);

    // don't exceed maximum vouches per subject profile
    if (vouchIdsForSubjectProfileId[subjectProfileId].length >= maximumVouches) {
      revert MaximumVouchesExceeded(vouchIdsForSubjectProfileId[subjectProfileId].length, "Exceeds subject vouch limit");
    }

    // must meet the minimum vouch amount
    if (msg.value < configuredMinimumVouchAmount) {
      revert MinimumVouchAmount(configuredMinimumVouchAmount);
    }

    (uint256 toDeposit,) = applyEntryFees(msg.value, subjectProfileId, authorProfileId, attestationHash, subjectAddress);

    // store vouch details
    uint256 count = vouchCount;
    vouchIdsByAuthor[authorProfileId].push(count);
    vouchIdsByAuthorIndex[authorProfileId][count] = vouchIdsByAuthor[authorProfileId].length - 1;
    vouchIdsForSubjectProfileId[subjectProfileId].push(count);
    vouchIdsForSubjectProfileIdIndex[subjectProfileId][count] = vouchIdsForSubjectProfileId[subjectProfileId].length - 1;

    vouchIdByAuthorForSubjectProfileId[authorProfileId][subjectProfileId] = count;
    vouches[count] = Vouch({
      archived: false,
      unhealthy: false,
      authorProfileId: authorProfileId,
      authorAddress: msg.sender,
      vouchId: count,
      balance: toDeposit,
      subjectProfileId: subjectProfileId,
      comment: comment,
      metadata: metadata,
      activityCheckpoints: ActivityCheckpoints({vouchedAt: block.timestamp, unvouchedAt: 0, unhealthyAt: 0})
    });

    // Store attestation hash if this vouch was created by attestation
    if (attestationHash != bytes32(0)) {
      vouchAttestationHash[count] = attestationHash;
    }

    emit Vouched(count, authorProfileId, subjectProfileId, subjectAddress, attestationHash, msg.value, toDeposit);
    vouchCount++;
  }

  /**
   * @notice Increases the staked amount for an existing vouch
   * @param vouchId The ID of the vouch to increase
   * @param attestationHash Optional mock profile attestation hash (use bytes32(0) if not needed)
   * @param subjectAddress Optional mock profile address (use address(0) if not needed)
   * @dev For verified profiles, both attestationHash and subjectAddress should be empty
   * @dev For mock profiles, either attestationHash OR subjectAddress must match the original vouch
   */
  function increaseVouch(uint256 vouchId, bytes32 attestationHash, address subjectAddress) public payable nonReentrant {
    // vouch increases much also meet the minimum vouch amount
    if (msg.value < configuredMinimumVouchAmount) {
      revert MinimumVouchAmount(configuredMinimumVouchAmount);
    }
    // get the profile id of the author
    uint256 authorProfileId = _ethosProfile().verifiedProfileIdForAddress(msg.sender);
    _vouchShouldBelongToAuthor(vouchId, authorProfileId);
    // make sure this vouch is active; not unvouched
    _vouchShouldBePossibleUnvouch(vouchId);

    uint256 subjectProfileId = vouches[vouchId].subjectProfileId;

    // If the subject profile is a mock profile, require a subject address or attestation hash
    (,, bool mock) = _ethosProfile().profileStatusById(subjectProfileId);
    if (mock && (subjectAddress == address(0) && attestationHash == bytes32(0))) {
      revert InvalidEthosProfileForVouch(subjectProfileId);
    }

    // Validate that either attestationHash or subjectAddress matches the vouch
    if (attestationHash != bytes32(0)) {
      uint256 attestationProfileId = _ethosProfile().profileIdByAttestation(attestationHash);
      if (attestationProfileId != subjectProfileId) {
        revert InvalidEthosProfileForVouch(attestationProfileId);
      }
    }

    if (subjectAddress != address(0)) {
      uint256 addressProfileId = _ethosProfile().profileIdByAddress(subjectAddress);
      if (addressProfileId != subjectProfileId) {
        revert InvalidEthosProfileForVouch(addressProfileId);
      }
    }

    (uint256 toDeposit,) = applyEntryFees(msg.value, subjectProfileId, authorProfileId, attestationHash, subjectAddress);
    vouches[vouchId].balance += toDeposit;

    emit VouchIncreased(
      vouchId, authorProfileId, subjectProfileId, subjectAddress, attestationHash, msg.value, toDeposit
    );
  }

  // --- Unvouch Functions ---

  /**
   * @notice Withdraws a vouch, returning staked funds to the author minus exit fees
   * @param vouchId The ID of the vouch to withdraw
   */
  function unvouch(uint256 vouchId) public whenNotPaused nonReentrant {
    Vouch storage v = vouches[vouchId];
    _vouchShouldExist(vouchId);
    _vouchShouldBePossibleUnvouch(vouchId);

    // Prevent withdrawals if the author's profile is frozen
    if (frozenAuthors[v.authorProfileId]) revert PendingSlash(vouchId, v.authorProfileId);

    // because it's $$$, you can only withdraw/unvouch to the same address you used to vouch
    // however, we don't care about the status of the address's profile; funds are always attached
    // to an address, not a profile
    if (vouches[vouchId].authorAddress != msg.sender) {
      revert AddressNotVouchAuthor(vouchId, msg.sender, vouches[vouchId].authorAddress);
    }

    v.archived = true;
    // solhint-disable-next-line not-rely-on-time
    v.activityCheckpoints.unvouchedAt = block.timestamp;
    // remove the vouch from the tracking arrays and index mappings
    _removeVouchFromArrays(v);

    // apply fees and determine how much is left to send back to the author
    (uint256 toWithdraw,) = applyExitFees(v.balance);
    // set the balance to 0 and save back to storage
    v.balance = 0;
    // send the funds to the author
    // note: it sends it to the same address that vouched; not the one that called unvouch
    (bool success,) = payable(v.authorAddress).call{value: toWithdraw}("");
    if (!success) {
      revert FeeTransferFailed("Failed to send ETH to author");
    }

    emit Unvouched(v.vouchId, v.authorProfileId, v.subjectProfileId, toWithdraw);
  }

  /**
   * @dev Convenience function that combines unvouch and mark unhealthy to avoid multiple transactions.
   * @param vouchId Vouch Id.
   */
  function unvouchUnhealthy(uint256 vouchId) external whenNotPaused {
    unvouch(vouchId);
    markUnhealthy(vouchId);
  }

  /**
   * @dev Marks vouch as unhealthy.
   * @param vouchId Vouch Id.
   */
  function markUnhealthy(uint256 vouchId) public whenNotPaused {
    Vouch storage v = vouches[vouchId];
    uint256 profileId = _ethosProfile().verifiedProfileIdForAddress(msg.sender);

    _vouchShouldExist(vouchId);
    _vouchShouldBePossibleUnhealthy(vouchId);
    _vouchShouldBelongToAuthor(vouchId, profileId);
    v.unhealthy = true;
    // solhint-disable-next-line not-rely-on-time
    v.activityCheckpoints.unhealthyAt = block.timestamp;

    emit MarkedUnhealthy(v.vouchId, v.authorProfileId, v.subjectProfileId);
  }

  // --- Slash Functions ---

  /**
   * @notice Freezes all vouches from a specific author, preventing withdrawals until unfrozen or slashed
   * @dev Only callable by the authorized slasher contract
   * @param authorProfileId The profile ID whose vouches will be frozen
   * This is a protective measure to prevent withdrawal of funds during investigation before the slashing process is complete
   */
  function freeze(uint256 authorProfileId) external onlySlasher whenNotPaused nonReentrant {
    frozenAuthors[authorProfileId] = true;
    emit Frozen(authorProfileId, true);
  }

  /**
   * @notice Unfreezes an author's vouches, allowing withdrawals again
   * @dev Only callable by the authorized slasher contract
   * @param authorProfileId The profile ID whose vouches will be unfrozen
   */
  function unfreeze(uint256 authorProfileId) external onlySlasher whenNotPaused nonReentrant {
    frozenAuthors[authorProfileId] = false;
    emit Frozen(authorProfileId, false);
  }

  /**
   * @notice Reduces all vouch balances for a given author by a percentage
   * @param authorProfileId The profile ID whose vouches will be slashed
   * @param slashBasisPoints The percentage to slash in basis points (100 = 1%)
   * @return totalSlashed The total amount slashed across all vouches
   */
  function slash(uint256 authorProfileId, uint256 slashBasisPoints)
    external
    onlySlasher
    whenNotPaused
    nonReentrant
    returns (uint256)
  {
    if (slashBasisPoints > MAX_SLASH_PERCENTAGE) {
      revert InvalidSlashPercentage();
    }

    uint256 totalSlashed;
    uint256[] storage vouchIds = vouchIdsByAuthor[authorProfileId];

    for (uint256 i = 0; i < vouchIds.length; i++) {
      Vouch storage vouch = vouches[vouchIds[i]];
      // Only slash active vouches
      if (!vouch.archived) {
        uint256 slashAmount = vouch.balance.mulDiv(slashBasisPoints, BASIS_POINT_SCALE, Math.Rounding.Floor);
        if (slashAmount > 0) {
          vouch.balance -= slashAmount;
          totalSlashed += slashAmount;
        }
      }
    }

    if (totalSlashed > 0) {
      // Send slashed funds to protocol fee address
      (bool success,) = protocolFeeAddress.call{value: totalSlashed}("");
      if (!success) revert FeeTransferFailed("Slash transfer failed");
    }

    emit Slashed(authorProfileId, slashBasisPoints, totalSlashed);
    return totalSlashed;
  }

  // --- Fee Management ---

  /**
   * @notice Updates the protocol fee percentage charged on entry
   * @dev Only callable by admin
   * @param _newEntryProtocolFeeBasisPoints New fee in basis points (100 = 1%)
   * @custom:throws {FeesExceedMaximum} If new total fees would exceed maximum
   * @custom:emits EntryProtocolFeeBasisPointsUpdated
   */
  function setEntryProtocolFeeBasisPoints(uint256 _newEntryProtocolFeeBasisPoints) external onlyAdmin {
    checkFeeExceedsMaximum(entryProtocolFeeBasisPoints, _newEntryProtocolFeeBasisPoints);
    entryProtocolFeeBasisPoints = _newEntryProtocolFeeBasisPoints;
    emit EntryProtocolFeeBasisPointsUpdated(_newEntryProtocolFeeBasisPoints);
  }

  /**
   * @notice Updates the donation fee percentage charged on entry
   * @dev Only callable by admin
   * @param _newEntryDonationFeeBasisPoints New fee in basis points (100 = 1%)
   * @custom:throws {FeesExceedMaximum} If new total fees would exceed maximum
   * @custom:emits EntryDonationFeeBasisPointsUpdated
   */
  function setEntryDonationFeeBasisPoints(uint256 _newEntryDonationFeeBasisPoints) external onlyAdmin {
    checkFeeExceedsMaximum(entryDonationFeeBasisPoints, _newEntryDonationFeeBasisPoints);
    entryDonationFeeBasisPoints = _newEntryDonationFeeBasisPoints;
    emit EntryDonationFeeBasisPointsUpdated(_newEntryDonationFeeBasisPoints);
  }

  /**
   * @notice Updates the vouchers pool fee percentage charged on entry
   * @dev Only callable by admin
   * @param _newEntryVouchersPoolFeeBasisPoints New fee in basis points (100 = 1%)
   * @custom:throws {FeesExceedMaximum} If new total fees would exceed maximum
   * @custom:emits EntryVouchersPoolFeeBasisPointsUpdated
   */
  function setEntryVouchersPoolFeeBasisPoints(uint256 _newEntryVouchersPoolFeeBasisPoints) external onlyAdmin {
    checkFeeExceedsMaximum(entryVouchersPoolFeeBasisPoints, _newEntryVouchersPoolFeeBasisPoints);
    entryVouchersPoolFeeBasisPoints = _newEntryVouchersPoolFeeBasisPoints;
    emit EntryVouchersPoolFeeBasisPointsUpdated(_newEntryVouchersPoolFeeBasisPoints);
  }

  /**
   * @notice Updates the exit fee percentage charged on withdrawals
   * @dev Only callable by admin
   * @param _newExitFeeBasisPoints New fee in basis points (100 = 1%)
   * @custom:throws {FeesExceedMaximum} If new total fees would exceed maximum
   * @custom:emits ExitFeeBasisPointsUpdated
   */
  function setExitFeeBasisPoints(uint256 _newExitFeeBasisPoints) external onlyAdmin {
    checkFeeExceedsMaximum(exitFeeBasisPoints, _newExitFeeBasisPoints);
    exitFeeBasisPoints = _newExitFeeBasisPoints;
    emit ExitFeeBasisPointsUpdated(_newExitFeeBasisPoints);
  }

  /**
   * @notice Updates the address where protocol fees are sent
   * @dev Only callable by owner
   * @param _protocolFeeAddress New fee recipient address
   * @custom:throws {InvalidFeeProtocolAddress} If address is zero
   * @custom:emits ProtocolFeeAddressUpdated
   */
  function setProtocolFeeAddress(address _protocolFeeAddress) external onlyOwner {
    if (_protocolFeeAddress == address(0)) revert InvalidFeeProtocolAddress();
    protocolFeeAddress = _protocolFeeAddress;
    emit ProtocolFeeAddressUpdated(protocolFeeAddress);
  }

  // --- Configuration Functions ---

  /**
   * @dev Sets the minimum vouch amount.
   * @param amount New minimum vouch amount in wei.
   */
  function setMinimumVouchAmount(uint256 amount) external onlyAdmin whenNotPaused {
    if (amount < ABSOLUTE_MINIMUM_VOUCH_AMOUNT) {
      revert MinimumVouchAmount(ABSOLUTE_MINIMUM_VOUCH_AMOUNT);
    }
    configuredMinimumVouchAmount = amount;
  }

  /**
   * @notice Updates the maximum number of vouches allowed
   * @dev Only callable by admin when contract is not paused
   * @param maximumVouches_ The new maximum number of vouches
   */
  function updateMaximumVouches(uint256 maximumVouches_) external onlyAdmin whenNotPaused {
    if (maximumVouches_ > 256) {
      revert MaximumVouchesExceeded(maximumVouches_, "Maximum vouches cannot exceed 256");
    }
    maximumVouches = maximumVouches_;
  }

  /**
   * @dev Updates time period for unhealthy response.
   * @param unhealthyResponsePeriodDuration Time period.
   */
  function updateUnhealthyResponsePeriod(uint256 unhealthyResponsePeriodDuration) external onlyAdmin whenNotPaused {
    unhealthyResponsePeriod = unhealthyResponsePeriodDuration;
  }

  // --- Reward Functions ---

  /**
   * @notice Claims accumulated rewards for a verified Ethos profile
   * @dev Combines rewards from both profile ID and address-based rewards
   */
  function claimRewards() external whenNotPaused nonReentrant {
    (bool verified,, bool mock, uint256 callerProfileId) = _ethosProfile().profileStatusByAddress(msg.sender);

    // Only check that this is a real profile (not mock) and was verified at some point
    if (!verified || mock) revert ProfileNotFoundForAddress(msg.sender);

    // claim rewards by profile id
    uint256 amount = rewardsByProfileId[callerProfileId];

    // claim rewards by address
    uint256 addressRewards = rewardsByAddress[msg.sender];
    amount += addressRewards;

    if (amount == 0) revert InsufficientRewardsBalance();

    rewardsByProfileId[callerProfileId] = 0;
    rewardsByAddress[msg.sender] = 0;
    (bool success,) = msg.sender.call{value: amount}("");
    if (!success) revert FeeTransferFailed("Rewards claim failed");

    emit WithdrawnFromRewards(callerProfileId, amount);
  }

  /**
   * @notice Claims accumulated rewards for a profile using their attestation hash
   * @dev Only for verified profiles that registered the attestation hash
   * @param attestationHash The attestation hash used to identify the rewards
   */
  function claimRewardsByAttestation(bytes32 attestationHash) external whenNotPaused nonReentrant {
    (bool verified,, bool mock, uint256 callerProfileId) = _ethosProfile().profileStatusByAddress(msg.sender);
    if (!verified) revert ProfileNotFoundForAddress(msg.sender);
    if (mock) revert ProfileNotFoundForAddress(msg.sender);

    // ensure this hash belongs to the caller
    if (_ethosProfile().profileIdByAttestation(attestationHash) != callerProfileId) {
      revert InvalidAttestationHash(attestationHash);
    }

    uint256 amount = rewardsByAttestationHash[attestationHash];
    if (amount == 0) revert InsufficientRewardsBalance();

    rewardsByAttestationHash[attestationHash] = 0;
    (bool success,) = msg.sender.call{value: amount}("");
    if (!success) revert FeeTransferFailed("Rewards claim failed");

    emit WithdrawnFromRewards(callerProfileId, amount);
  }

  function _depositRewards(uint256 amount, uint256 recipientProfileId, bytes32 attestationHash, address subjectAddress)
    internal
  {
    if (attestationHash != bytes32(0)) {
      rewardsByAttestationHash[attestationHash] += amount;
    } else if (subjectAddress != address(0)) {
      rewardsByAddress[subjectAddress] += amount;
    } else {
      rewardsByProfileId[recipientProfileId] += amount;
    }
    emit DepositedToRewards(recipientProfileId, amount);
  }

  function _previousVouchersBalance(uint256 subjectProfileId, uint256 excludeAuthorId)
    internal
    view
    returns (uint256 totalBalance)
  {
    uint256[] storage vouchIds = vouchIdsForSubjectProfileId[subjectProfileId];
    uint256 totalVouches = vouchIds.length;

    // Calculate total balance of all active vouches except author's
    for (uint256 i = 0; i < totalVouches; i++) {
      Vouch storage vouch = vouches[vouchIds[i]];
      // Only include active (not archived) vouches from other authors
      if (!vouch.archived && vouch.authorProfileId != excludeAuthorId) {
        totalBalance += vouch.balance;
      }
    }
  }

  function _rewardPreviousVouchers(
    uint256 amountToDistribute,
    uint256 previousVouchersBalance,
    uint256 subjectProfileId,
    uint256 excludeAuthorId,
    bytes32 attestationHash,
    address subjectAddress
  ) internal {
    uint256[] storage vouchIds = vouchIdsForSubjectProfileId[subjectProfileId];
    uint256 totalVouches = vouchIds.length;
    // Distribute rewards proportionally
    uint256 remainingRewards = amountToDistribute;
    for (uint256 i = 0; i < totalVouches && remainingRewards > 0; i++) {
      Vouch storage vouch = vouches[vouchIds[i]];
      if (!vouch.archived && vouch.authorProfileId != excludeAuthorId) {
        // Calculate this vouch's share of the rewards
        uint256 reward = amountToDistribute.mulDiv(vouch.balance, previousVouchersBalance, Math.Rounding.Floor);
        // Avoid rewarding the author more than the amount they vouched
        // this prevents vouchers from vouching everyone for dust, just to try to get the total real vouch rewards
        reward = Math.min(reward, vouch.balance);

        if (reward > 0) {
          vouch.balance += reward;
          remainingRewards -= reward;
        }
      }
    }

    // Send any remaining rewards to the subject reward escrow
    if (remainingRewards > 0) {
      _depositRewards(remainingRewards, subjectProfileId, attestationHash, subjectAddress);
    }
  }

  // --- View Functions ---

  // ITargetStatus implementation
  /**
   * @dev Checks if target exists and is allowed to be used.
   * @param targetId Vouch id.
   * @return exists Whether target exists.
   * @return allowed Whether target is allowed to be used.
   */
  function targetExistsAndAllowedForId(uint256 targetId) external view returns (bool exists, bool allowed) {
    Vouch storage vouch = vouches[targetId];

    exists = vouch.activityCheckpoints.vouchedAt > 0;
    allowed = exists;
  }

  /**
   * @dev Gets a verified vouch by author for vouchee profile Id.
   * @param author Author profileId.
   * @param subjectProfileId Subject profile Id.
   * @return Vouch.
   */
  function verifiedVouchByAuthorForSubjectProfileId(uint256 author, uint256 subjectProfileId)
    public
    view
    returns (Vouch memory)
  {
    uint256 id = vouchIdByAuthorForSubjectProfileId[author][subjectProfileId];

    _vouchShouldBelongToAuthor(id, author);

    if (vouches[id].subjectProfileId != subjectProfileId) {
      revert WrongSubjectProfileIdForVouch(id, subjectProfileId);
    }

    return vouches[id];
  }

  /**
   * @dev Gets a verified vouch by author for subject address.
   * @param author author profileId.
   * @param subjectAddress subject address.
   * @return Vouch.
   */
  function verifiedVouchByAuthorForSubjectAddress(uint256 author, address subjectAddress)
    external
    view
    returns (Vouch memory)
  {
    uint256 profileId = _ethosProfile().verifiedProfileIdForAddress(subjectAddress);

    return verifiedVouchByAuthorForSubjectProfileId(author, profileId);
  }

  /**
   * @dev Checks whether vouch exists for author and subject profile Id.
   * @param author Author profileId.
   * @param subjectProfileId Vouchee profile Id.
   * @return Whether vouch exists.
   */
  function vouchExistsFor(uint256 author, uint256 subjectProfileId) public view returns (bool) {
    uint256 id = vouchIdByAuthorForSubjectProfileId[author][subjectProfileId];
    Vouch storage v = vouches[id];

    return
      v.authorProfileId == author && v.subjectProfileId == subjectProfileId && v.activityCheckpoints.unvouchedAt == 0;
  }

  // --- Internal Helper Functions ---

  /**
   * @notice Fails if vouch does not belong to Author.
   * @dev Checks if vouch belongs to author.
   * @param vouchId Vouch Id.
   * @param author author profileId.
   */
  function _vouchShouldBelongToAuthor(uint256 vouchId, uint256 author) private view {
    if (vouches[vouchId].authorProfileId != author) {
      revert NotAuthorForVouch(vouchId, author);
    }
  }

  /**
   * @notice Fails if vouch does not exist.
   * @dev Checks if vouch exists.
   * @param vouchId Vouch Id.
   */
  function _vouchShouldExist(uint256 vouchId) private view {
    if (vouches[vouchId].activityCheckpoints.vouchedAt == 0) {
      revert VouchNotFound(vouchId);
    }
  }

  /**
   * @notice Fails if vouch should not exist.
   * @dev Checks if vouch does not exist.
   * @param author Author profileId.
   * @param subjectProfileId Subject profile Id.
   */
  function _vouchShouldNotExistFor(uint256 author, uint256 subjectProfileId) private view {
    if (vouchExistsFor(author, subjectProfileId)) {
      revert AlreadyVouched(author, subjectProfileId);
    }
  }

  /**
   * @notice Fails if vouch cannot be set as unhealthy.
   * @dev Checks if vouch can be set as unhealthy.
   * @param vouchId Vouch Id.
   */
  function _vouchShouldBePossibleUnhealthy(uint256 vouchId) private view {
    Vouch storage v = vouches[vouchId];
    bool stillHasTime = block.timestamp <= v.activityCheckpoints.unvouchedAt + unhealthyResponsePeriod;

    if (!v.archived || v.unhealthy || !stillHasTime) {
      revert CannotMarkVouchAsUnhealthy(vouchId);
    }
  }

  /**
   * @notice Fails if vouch cannot be unvouched.
   * @dev Checks if vouch can be unvouched.
   * @param vouchId Vouch Id.
   */
  function _vouchShouldBePossibleUnvouch(uint256 vouchId) private view {
    Vouch storage v = vouches[vouchId];

    if (v.archived) {
      revert AlreadyUnvouched(vouchId);
    }
  }

  /**
   * @dev Sends protocol fees to the designated fee address
   * @param amount Amount of ETH to send
   * @custom:throws {FeeTransferFailed} If the ETH transfer fails
   */
  function _depositProtocolFee(uint256 amount) internal {
    (bool success,) = protocolFeeAddress.call{value: amount}("");
    if (!success) revert FeeTransferFailed("Protocol fee deposit failed");
  }

  /**
   * @dev Removes an element from an array by swapping with the last element and popping
   * @param index The index of the element to remove
   * @param arr The array to modify
   */
  function _removeFromArray(uint256 index, uint256[] storage arr) private {
    // If this isn't the last element, swap it with the last one
    if (arr.length > 0 && index < arr.length - 1) {
      arr[index] = arr[arr.length - 1];
    }
    // Pop the last element (now duplicated)
    if (arr.length > 0) {
      arr.pop();
    }
  }

  /**
   * @dev Updates the index mapping when swapping elements during removal
   * @param index The index where the element is being removed
   * @param arr The array containing the elements
   * @param profileId The profile ID for the index mapping
   * @param indexMapping The mapping to update
   */
  function _updateIndexMappingForSwap(
    uint256 index,
    uint256[] storage arr,
    uint256 profileId,
    mapping(uint256 => mapping(uint256 => uint256)) storage indexMapping
  ) private {
    if (arr.length > 0 && index < arr.length - 1) {
      uint256 lastId = arr[arr.length - 1];
      indexMapping[profileId][lastId] = index;
    }
  }

  function applyEntryFees(
    uint256 amount,
    uint256 subjectProfileId,
    uint256 authorProfileId,
    bytes32 attestationHash,
    address subjectAddress
  ) internal returns (uint256 toDeposit, uint256 totalFees) {
    uint256 previousVouchersBalance = _previousVouchersBalance(subjectProfileId, authorProfileId);
    // Sum all entry fees to calculate a max fee to be split across each fee type
    uint256 totalFeesBasisPoints = entryProtocolFeeBasisPoints + entryDonationFeeBasisPoints;
    if (previousVouchersBalance > 0) totalFeesBasisPoints += entryVouchersPoolFeeBasisPoints;
    if (totalFeesBasisPoints == 0) return (amount, 0);

    // Calculate deposit amount
    toDeposit = amount.mulDiv(BASIS_POINT_SCALE, (BASIS_POINT_SCALE + totalFeesBasisPoints), Math.Rounding.Floor);

    // Calculate total fees as the remainder
    totalFees = amount - toDeposit;

    // Distribute total fees proportionally
    uint256 protocolFee = totalFees.mulDiv(entryProtocolFeeBasisPoints, totalFeesBasisPoints, Math.Rounding.Floor);
    uint256 donationFee = totalFees.mulDiv(entryDonationFeeBasisPoints, totalFeesBasisPoints, Math.Rounding.Floor);
    uint256 vouchersPoolFee = totalFees - protocolFee - donationFee;

    // Distribute each fee portion to its respective destination
    if (protocolFee > 0) _depositProtocolFee(protocolFee);

    if (donationFee > 0) {
      _depositRewards(donationFee, subjectProfileId, attestationHash, subjectAddress);
    }

    if (vouchersPoolFee > 0) {
      _rewardPreviousVouchers(
        vouchersPoolFee, previousVouchersBalance, subjectProfileId, authorProfileId, attestationHash, subjectAddress
      );
    }

    // vouchersPoolFee is dynamic and may be less than initially allocated
    // so we need to recalculate totalFees to ensure the correct amount is deposited
    totalFees = protocolFee + donationFee + vouchersPoolFee;
    toDeposit = amount - totalFees;
  }

  function applyExitFees(uint256 amount) internal returns (uint256 toDeposit, uint256 totalFees) {
    // Exit transactions only have a single protocol fee
    totalFees = calcFee(amount, exitFeeBasisPoints);
    if (totalFees > 0) _depositProtocolFee(totalFees);
    toDeposit = amount - totalFees;
  }

  /**
   * @notice Calculates the fee amount based on total and basis points
   * @dev Calculates fee "backwards" from total amount to ensure deposit + fee = total.
   *
   * @param total The total amount sent by user
   * @param feeBasisPoints The fee percentage in basis points (100 = 1%)
   * @return fee The calculated fee amount
   */
  function calcFee(uint256 total, uint256 feeBasisPoints) internal pure returns (uint256 fee) {
    /*
     * Formula derivation:
     * 1. total = deposit + fee
     * 2. fee = deposit * (feeBasisPoints/10000)
     * 3. total = deposit + deposit * (feeBasisPoints/10000)
     * 4. total = deposit * (1 + feeBasisPoints/10000)
     * 5. deposit = total / (1 + feeBasisPoints/10000)
     * 6. fee = total - deposit
     * 7. fee = total - (total * 10000 / (10000 + feeBasisPoints))
     */
    return total - (total.mulDiv(BASIS_POINT_SCALE, (BASIS_POINT_SCALE + feeBasisPoints), Math.Rounding.Floor));
  }

  /* @notice Checks if the new fee would cause the total fees to exceed the maximum allowed
   * @dev This function is called before updating any fee to ensure the total doesn't exceed MAX_TOTAL_FEES
   * @param currentFee The current value of the fee being updated
   * @param newFee The proposed new value for the fee
   */
  function checkFeeExceedsMaximum(uint256 currentFee, uint256 newFee) internal view {
    uint256 totalFees = entryProtocolFeeBasisPoints + exitFeeBasisPoints + entryDonationFeeBasisPoints
      + entryVouchersPoolFeeBasisPoints + newFee - currentFee;
    if (totalFees > MAX_TOTAL_FEES) revert FeesExceedMaximum(totalFees, MAX_TOTAL_FEES);
  }

  /**
   * @notice Removes a vouch from both author and subject arrays and updates mappings
   * @param v The vouch struct containing author and subject profile IDs
   */
  function _removeVouchFromArrays(Vouch storage v) private {
    // Remove from author's array
    uint256 authorIndex = vouchIdsByAuthorIndex[v.authorProfileId][v.vouchId];
    uint256[] storage authorVouches = vouchIdsByAuthor[v.authorProfileId];

    _updateIndexMappingForSwap(authorIndex, authorVouches, v.authorProfileId, vouchIdsByAuthorIndex);
    _removeFromArray(authorIndex, authorVouches);
    delete vouchIdsByAuthorIndex[v.authorProfileId][v.vouchId];

    // Remove from subject's array
    uint256 subjectIndex = vouchIdsForSubjectProfileIdIndex[v.subjectProfileId][v.vouchId];
    uint256[] storage subjectVouches = vouchIdsForSubjectProfileId[v.subjectProfileId];

    _updateIndexMappingForSwap(subjectIndex, subjectVouches, v.subjectProfileId, vouchIdsForSubjectProfileIdIndex);
    _removeFromArray(subjectIndex, subjectVouches);
    delete vouchIdsForSubjectProfileIdIndex[v.subjectProfileId][v.vouchId];

    // the author->subject mapping is only for active vouches; remove it
    delete vouchIdByAuthorForSubjectProfileId[v.authorProfileId][v.subjectProfileId];
  }

  function _ethosProfile() internal view returns (IEthosProfile) {
    return IEthosProfile(contractAddressManager.getContractAddressForName(ETHOS_PROFILE));
  }

  /**
   * @notice Updates vouch mappings when an attestation is claimed by a profile
   * @dev Only callable by EthosProfile contract
   * @param attestationHash The hash of the attestation being claimed
   * @param nextProfileId The profile ID that claimed the attestation
   */
  function handleAttestationClaim(bytes32 attestationHash, uint256 nextProfileId)
    external
    isEthosProfile
    whenNotPaused
  {
    uint256 formerProfileId = _ethosProfile().profileIdByAttestation(attestationHash);
    if (formerProfileId == 0) return; // no previous vouches

    uint256[] storage oldVouchIds = vouchIdsForSubjectProfileId[formerProfileId];
    // add to any existing vouches for the upcoming profile
    uint256[] storage newVouchIds = vouchIdsForSubjectProfileId[nextProfileId];

    // transfer to new profile
    uint256[] memory vouchIdsToRemove = new uint256[](oldVouchIds.length);
    for (uint256 i = 0; i < oldVouchIds.length; i++) {
      uint256 vouchId = oldVouchIds[i];
      vouchIdsToRemove[i] = vouchId;
      Vouch storage vouch = vouches[vouchId];
      // Only transfer if this vouch was created by this attestation
      if (!vouch.archived && vouchAttestationHash[vouchId] == attestationHash) {
        // Update the vouch's subject profile ID
        vouch.subjectProfileId = nextProfileId;

        // Update the author->subject mapping
        vouchIdByAuthorForSubjectProfileId[vouch.authorProfileId][nextProfileId] = vouchId;
        delete vouchIdByAuthorForSubjectProfileId[vouch.authorProfileId][formerProfileId];

        // Add to new profile's vouch list and update index
        // Note: this can exceed the 256 vouch limit
        newVouchIds.push(vouchId);
        vouchIdsForSubjectProfileIdIndex[nextProfileId][vouchId] = newVouchIds.length - 1;

        // once an attestation is claimed, vouches are then associated with the claiming profile
        // so we no longer track them by the attestation hash
        delete vouchAttestationHash[vouchId];
      }
    }
    // Remove from old profile's vouch list
    for (uint256 i = 0; i < vouchIdsToRemove.length; i++) {
      uint256 vouchId = vouchIdsToRemove[i];
      uint256 oldIndex = vouchIdsForSubjectProfileIdIndex[formerProfileId][vouchId];
      _updateIndexMappingForSwap(oldIndex, oldVouchIds, formerProfileId, vouchIdsForSubjectProfileIdIndex);
      _removeFromArray(oldIndex, oldVouchIds);
    }

    emit AttestationVouchMappingUpdated(attestationHash, formerProfileId, nextProfileId);
  }
}
