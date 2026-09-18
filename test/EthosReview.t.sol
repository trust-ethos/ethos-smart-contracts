// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Burnable} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ITargetStatus} from "../src/interfaces/ITargetStatus.sol";
import {ContractAddressManager} from "../src/utils/ContractAddressManager.sol";
import {InteractionControl} from "../src/utils/InteractionControl.sol";
import {AccessControl} from "../src/utils/AccessControl.sol";
import {SignatureControl} from "../src/utils/SignatureControl.sol";
import {SignatureVerifier} from "../src/legacy/SignatureVerifier.sol";
import {Common} from "../src/legacy/Common.sol";
import {EthosReview} from "../src/legacy/EthosReview.sol";
import {AttestationDetails} from "../src/utils/Structs.sol";
import {IEthosProfile} from "../src/interfaces/IEthosProfile.sol";
import {
  ETHOS_ATTESTATION,
  ETHOS_INTERACTION_CONTROL,
  ETHOS_PROFILE,
  ETHOS_REVIEW,
  ETHOS_VOUCH_V2,
  ETHOS_WHUFFIE
} from "../src/utils/Constants.sol";
import {
  InsufficientPermitAllowance,
  PermitValueMismatch,
  TokenNotBurnable,
  UnexpectedTokenBehavior,
  VouchV2NotRegistered,
  WrongPaymentAmount,
  VouchRequiresPositiveReview,
  WrongPaymentToken,
  ZeroVouchAmount
} from "../src/legacy/errors/ReviewErrors.sol";
import {IEthosVouchV2} from "../src/interfaces/IEthosVouchV2.sol";

contract MockReviewAttestation {
  function getServiceAndAccountHash(string calldata service, string calldata account) external pure returns (bytes32) {
    if (bytes(service).length == 0 || bytes(account).length == 0) {
      revert("MockReviewAttestation: empty service/account");
    }
    return keccak256(abi.encode(service, account));
  }
}

error ProfileNotFoundForAddress(address addr);

contract MockReviewProfile is IEthosProfile {
  uint256 internal _nextProfileId = 1;

  mapping(uint256 profileId => Profile profile) internal _profiles;
  mapping(uint256 profileId => bool mock) internal _isMockProfile;
  mapping(address user => uint256 profileId) public profileIdByAddress;
  mapping(bytes32 attestationHash => uint256 profileId) public profileIdByAttestation;
  mapping(uint256 profile => mapping(address invitee => uint256 invitedAt)) public sentAt;

  function initialize(address owner) external {
    _createProfile(owner, false);
  }

  function mintProfile(address user) external returns (uint256 profileId) {
    profileId = _createProfile(user, false);
  }

  function profileExistsAndArchivedForId(uint256 profileId) external view returns (bool exists, bool archived) {
    exists = _profiles[profileId].createdAt != 0;
    archived = _profiles[profileId].archived;
  }

  function addressBelongsToProfile(address addr, uint256 profileId) external view returns (bool) {
    return profileIdByAddress[addr] == profileId;
  }

  function verifiedProfileIdForAddress(address addr) external view returns (uint256) {
    uint256 profileId = profileIdByAddress[addr];
    if (profileId == 0) revert ProfileNotFoundForAddress(addr);
    return profileId;
  }

  function profileStatusById(uint256 profileId) external view returns (bool verified, bool archived, bool mock) {
    Profile storage profile = _profiles[profileId];
    verified = profile.createdAt != 0;
    archived = profile.archived;
    mock = _isMockProfile[profileId];
  }

  function profileStatusByAddress(address addr)
    external
    view
    returns (bool verified, bool archived, bool mock, uint256 profileId)
  {
    profileId = profileIdByAddress[addr];
    Profile storage profile = _profiles[profileId];
    verified = profile.createdAt != 0;
    archived = profile.archived;
    mock = _isMockProfile[profileId];
  }

  function incrementProfileCount(bool isAttestation, address subject, bytes32 attestation)
    external
    returns (uint256 profileId)
  {
    profileId = _createProfile(address(0), true);
    if (isAttestation) {
      profileIdByAttestation[attestation] = profileId;
    } else {
      profileIdByAddress[subject] = profileId;
      _profiles[profileId].addresses.push(subject);
    }
  }

  function assignExistingProfileToAttestation(bytes32 attestation, uint256 profileId) external {
    profileIdByAttestation[attestation] = profileId;
  }

  function getProfile(uint256 profileId) external view returns (Profile memory profile) {
    profile = _profiles[profileId];
  }

  function addressesForProfile(uint256 profileId) external view returns (address[] memory) {
    return _profiles[profileId].addresses;
  }

  function inviteAddress(address invitee) external {
    sentAt[profileIdByAddress[msg.sender]][invitee] = block.timestamp;
  }

  function createProfile(uint256) external {
    _createProfile(msg.sender, false);
  }

  function _createProfile(address user, bool mock) internal returns (uint256 profileId) {
    if (user != address(0) && profileIdByAddress[user] != 0) {
      return profileIdByAddress[user];
    }

    profileId = _nextProfileId++;
    Profile storage profile = _profiles[profileId];
    profile.profileId = profileId;
    profile.createdAt = block.timestamp == 0 ? 1 : block.timestamp;
    profile.inviteInfo.invitedBy = 1;
    _isMockProfile[profileId] = mock;

    if (user != address(0)) {
      profileIdByAddress[user] = profileId;
      profile.addresses.push(user);
    }
  }
}

/// @dev Minimal in-test stand-in for EthosVouchV2 — implements only the
///      `IEthosVouchV2` surface that EthosReview consumes. Pulls `amount +
///      entryFee` from msg.sender (mirrors VouchV2._checkTransferIn semantics)
///      and burns the fee. Exposes recorded calldata so tests can assert
///      that the composite forwarded the right author / target / amount.
contract MockVouchV2 is IEthosVouchV2 {
  ERC20Burnable public immutable token;
  uint256 public entryFeeBps;
  bool public revertOnVouchFor;

  struct LastCall {
    address caller;
    address author;
    string target;
    uint256 amount;
    string metadata;
  }

  LastCall public last;
  uint256 public callCount;

  constructor(ERC20Burnable token_, uint256 entryFeeBps_) {
    token = token_;
    entryFeeBps = entryFeeBps_;
  }

  function setRevertOnVouchFor(bool v) external {
    revertOnVouchFor = v;
  }

  function previewVouchFee(uint256 amount) external view returns (uint256 fee, uint256 gross) {
    // Match VouchV2's mulDiv-with-Ceil for parity with previewVouchFee in prod.
    fee = (amount * entryFeeBps + 10_000 - 1) / 10_000;
    gross = amount + fee;
  }

  function vouchFor(address author, string calldata target, uint256 amount, string calldata metadata) external {
    if (revertOnVouchFor) revert("MockVouchV2: configured revert");
    uint256 fee = (amount * entryFeeBps + 10_000 - 1) / 10_000;
    uint256 gross = amount + fee;

    last = LastCall({caller: msg.sender, author: author, target: target, amount: amount, metadata: metadata});
    callCount++;

    // Match real VouchV2: pull `gross` from msg.sender and burn the fee.
    require(token.transferFrom(msg.sender, address(this), gross), "MockVouchV2: pull failed");
    if (fee > 0) token.burn(fee);
  }
}

contract MockWhuffie is ERC20, ERC20Burnable, ERC20Permit {
  constructor() ERC20("Whuffie", "WHUF") ERC20Permit("Whuffie") {}

  function mint(address to, uint256 amount) external {
    _mint(to, amount);
  }
}

contract MockNonBurnableWhuffie is ERC20 {
  constructor() ERC20("Whuffie", "WHUF") {}

  function mint(address to, uint256 amount) external {
    _mint(to, amount);
  }
}

contract MockFeeOnTransferWhuffie is MockWhuffie {
  function _update(address from, address to, uint256 value) internal override {
    if (from != address(0) && to != address(0) && value > 0) {
      super._update(from, to, value - 1);
      super._update(from, address(0), 1);
      return;
    }

    super._update(from, to, value);
  }
}

contract EthosReviewV1UpgradeHarness is AccessControl, Common, ITargetStatus, UUPSUpgradeable {
  enum Score {
    Negative,
    Neutral,
    Positive
  }

  enum ReviewsBy {
    Author,
    Subject,
    AttestationHash
  }

  struct Review {
    bool archived;
    Score score;
    address author;
    address subject;
    uint256 reviewId;
    uint256 createdAt;
    string comment;
    string metadata;
    AttestationDetails attestationDetails;
  }

  struct PaymentToken {
    bool allowed;
    uint256 price;
  }

  uint256 public reviewCount;

  mapping(address => PaymentToken) public reviewPrice;
  mapping(uint256 => Review) public reviews;
  mapping(address => uint256[]) public reviewIdsByAuthorAddress;
  mapping(address => uint256[]) public reviewIdsBySubjectAddress;
  mapping(bytes32 => uint256[]) public reviewIdsByAttestationHash;

  uint256[50] private __gap;

  constructor() {
    _disableInitializers();
  }

  function initialize(
    address owner,
    address admin,
    address expectedSigner,
    address signatureVerifier,
    address contractAddressManagerAddr
  ) external initializer {
    __accessControl_init(owner, admin, expectedSigner, signatureVerifier, contractAddressManagerAddr);

    reviewPrice[address(0)] = PaymentToken({allowed: true, price: 0});
    __UUPSUpgradeable_init();
  }

  function seedReview(
    uint256 reviewId,
    Score score,
    address author,
    address subject,
    uint256 createdAt,
    string calldata comment,
    string calldata metadata,
    AttestationDetails calldata attestationDetails,
    bytes32 attestationHash
  ) external {
    reviews[reviewId] = Review({
      archived: false,
      score: score,
      author: author,
      subject: subject,
      reviewId: reviewId,
      createdAt: createdAt,
      comment: comment,
      metadata: metadata,
      attestationDetails: attestationDetails
    });

    reviewIdsByAuthorAddress[author].push(reviewId);
    if (subject != address(0)) {
      reviewIdsBySubjectAddress[subject].push(reviewId);
    } else {
      reviewIdsByAttestationHash[attestationHash].push(reviewId);
    }

    reviewCount = reviewId + 1;
  }

  function setReviewPriceHarness(bool allowed, address paymentToken, uint256 price) external {
    reviewPrice[paymentToken] = PaymentToken({allowed: allowed, price: price});
  }

  function targetExistsAndAllowedForId(uint256 targetId) public view returns (bool exists, bool allowed) {
    Review storage review = reviews[targetId];

    exists = review.createdAt > 0;
    allowed = exists;
  }

  function _authorizeUpgrade(address newImplementation)
    internal
    override
    onlyOwner
    onlyNonZeroAddress(newImplementation)
  {}
}

contract EthosReviewTest is Test {
  ContractAddressManager internal _cam;
  SignatureVerifier internal _sigVerifier;
  InteractionControl internal _ic;
  MockReviewProfile internal _profile;
  MockReviewAttestation internal _attestation;
  EthosReview internal _review;
  MockWhuffie internal _whuffie;

  address internal _owner = address(0x1);
  address internal _admin = address(0x2);
  uint256 internal _signerPrivateKey = 0xA11CE;
  address internal _signer;
  address internal _author = address(0xA17430);
  address internal _subject = address(0x50B1EC7);

  uint256 internal constant OWNER_PROFILE_ID = 1;
  uint256 internal constant PERMIT_AUTHOR_PRIVATE_KEY = 0xBEEFCAFE;
  bytes32 internal constant PERMIT_TYPEHASH =
    keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

  event ReviewFeeBurned(address indexed author, address indexed paymentToken, uint256 amount);

  function setUp() public {
    _deployReviewStack();
    _mintProfile(_author);
  }

  function test_addReview_withNonZeroWhuffieCost_burnsFee() public {
    uint256 price = 5e18;
    _setReviewPrice(address(_whuffie), price);

    _whuffie.mint(_author, 100e18);

    uint256 authorBalanceBefore = _whuffie.balanceOf(_author);
    uint256 ownerBalanceBefore = _whuffie.balanceOf(_owner);
    uint256 adminBalanceBefore = _whuffie.balanceOf(_admin);
    uint256 totalSupplyBefore = _whuffie.totalSupply();

    vm.prank(_author);
    _whuffie.approve(address(_review), price);

    vm.expectEmit(true, true, false, true, address(_review));
    emit ReviewFeeBurned(_author, address(_whuffie), price);

    vm.prank(_author);
    _review.addReview(EthosReview.Score.Positive, _subject, address(_whuffie), "solid", "{}", _emptyAttestation());

    assertEq(_review.reviewCount(), 1);
    assertEq(_whuffie.balanceOf(_author), authorBalanceBefore - price);
    assertEq(_whuffie.balanceOf(address(_review)), 0);
    assertEq(_whuffie.balanceOf(_owner), ownerBalanceBefore);
    assertEq(_whuffie.balanceOf(_admin), adminBalanceBefore);
    assertEq(_whuffie.totalSupply(), totalSupplyBefore - price);
  }

  function test_addReviewWithPermit_usesPermitThenBurnsFee() public {
    address author = vm.addr(PERMIT_AUTHOR_PRIVATE_KEY);
    _mintProfile(author);

    uint256 price = 5e18;
    _setReviewPrice(address(_whuffie), price);

    _whuffie.mint(author, 100e18);

    uint256 deadline = block.timestamp + 1 hours;
    (uint8 v, bytes32 r, bytes32 s) = _signPermit(author, PERMIT_AUTHOR_PRIVATE_KEY, address(_review), price, deadline);

    uint256 nonceBefore = _whuffie.nonces(author);
    uint256 totalSupplyBefore = _whuffie.totalSupply();

    vm.prank(author);
    _review.addReviewWithPermit(
      EthosReview.Score.Positive, _subject, address(_whuffie), "permit", "{}", _emptyAttestation(), deadline, v, r, s
    );

    assertEq(_review.reviewCount(), 1);
    assertEq(_whuffie.balanceOf(author), 100e18 - price);
    assertEq(_whuffie.balanceOf(address(_review)), 0);
    assertEq(_whuffie.totalSupply(), totalSupplyBefore - price);
    assertEq(_whuffie.nonces(author), nonceBefore + 1);
    assertEq(_whuffie.allowance(author, address(_review)), 0);
  }

  function test_addReviewWithPermit_fallsBackToPreApprovalIfPermitFails() public {
    uint256 price = 5e18;
    _setReviewPrice(address(_whuffie), price);

    _whuffie.mint(_author, 100e18);

    vm.prank(_author);
    _whuffie.approve(address(_review), price);

    uint256 nonceBefore = _whuffie.nonces(_author);
    uint256 totalSupplyBefore = _whuffie.totalSupply();

    vm.prank(_author);
    _review.addReviewWithPermit(
      EthosReview.Score.Positive,
      _subject,
      address(_whuffie),
      "preapproved",
      "{}",
      _emptyAttestation(),
      0,
      0,
      bytes32(0),
      bytes32(0)
    );

    assertEq(_review.reviewCount(), 1);
    assertEq(_whuffie.balanceOf(address(_review)), 0);
    assertEq(_whuffie.totalSupply(), totalSupplyBefore - price);
    assertEq(_whuffie.nonces(_author), nonceBefore);
  }

  function test_addReviewWithPermit_revertsWithInsufficientPermitAllowance() public {
    uint256 price = 5e18;
    _setReviewPrice(address(_whuffie), price);

    _whuffie.mint(_author, 100e18);

    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSelector(InsufficientPermitAllowance.selector, _author, price));
    _review.addReviewWithPermit(
      EthosReview.Score.Positive,
      _subject,
      address(_whuffie),
      "bad permit",
      "{}",
      _emptyAttestation(),
      0,
      0,
      bytes32(0),
      bytes32(0)
    );
  }

  function test_addReviewWithPermit_withDefaultZeroCostSucceedsWithDeadPermit() public {
    uint256 nonceBefore = _whuffie.nonces(_author);
    uint256 totalSupplyBefore = _whuffie.totalSupply();

    vm.prank(_author);
    _review.addReviewWithPermit(
      EthosReview.Score.Neutral,
      _subject,
      address(0),
      "zero permit",
      "{}",
      _emptyAttestation(),
      0,
      0,
      bytes32(0),
      bytes32(0)
    );

    assertEq(_review.reviewCount(), 1);
    assertEq(_whuffie.balanceOf(address(_review)), 0);
    assertEq(_whuffie.balanceOf(_author), 0);
    assertEq(_whuffie.totalSupply(), totalSupplyBefore);
    assertEq(_whuffie.nonces(_author), nonceBefore);
  }

  function test_addReviewWithPermit_revertsOnEthValueEvenWhenZeroCost() public {
    vm.deal(_author, 1 ether);

    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSelector(WrongPaymentAmount.selector, address(0), 1 wei));
    _review.addReviewWithPermit{value: 1 wei}(
      EthosReview.Score.Positive,
      _subject,
      address(0),
      "paid native",
      "{}",
      _emptyAttestation(),
      0,
      0,
      bytes32(0),
      bytes32(0)
    );
  }

  function test_addReview_withDefaultZeroCost_succeedsWithoutTokenMovement() public {
    uint256 totalSupplyBefore = _whuffie.totalSupply();

    vm.prank(_author);
    _review.addReview(EthosReview.Score.Neutral, _subject, address(0), "neutral", "{}", _emptyAttestation());

    assertEq(_review.reviewCount(), 1);
    assertEq(_whuffie.balanceOf(address(_review)), 0);
    assertEq(_whuffie.balanceOf(_author), 0);
    assertEq(_whuffie.totalSupply(), totalSupplyBefore);
  }

  function test_addReview_revertsOnEthValueEvenWhenZeroCost() public {
    vm.deal(_author, 1 ether);

    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSelector(WrongPaymentAmount.selector, address(0), 1 wei));
    _review.addReview{value: 1 wei}(
      EthosReview.Score.Positive, _subject, address(0), "paid native", "{}", _emptyAttestation()
    );
  }

  function test_setReviewPrice_revertsForNonZeroNativeCost() public {
    vm.prank(_admin);
    vm.expectRevert(abi.encodeWithSelector(WrongPaymentToken.selector, address(0)));
    _review.setReviewPrice(true, address(0), 1 wei);
  }

  function test_setReviewPrice_revertsForNonWhuffieToken() public {
    MockWhuffie otherToken = new MockWhuffie();

    vm.prank(_admin);
    vm.expectRevert(abi.encodeWithSelector(WrongPaymentToken.selector, address(otherToken)));
    _review.setReviewPrice(true, address(otherToken), 1e18);
  }

  function test_setReviewPrice_revertsForNonBurnableWhuffie() public {
    MockNonBurnableWhuffie nonBurnable = new MockNonBurnableWhuffie();
    _setWhuffieAddress(address(nonBurnable));

    vm.prank(_admin);
    vm.expectRevert(abi.encodeWithSelector(TokenNotBurnable.selector, address(nonBurnable)));
    _review.setReviewPrice(true, address(nonBurnable), 1e18);
  }

  function test_addReview_revertsForUnexpectedTokenBehavior() public {
    MockFeeOnTransferWhuffie feeToken = new MockFeeOnTransferWhuffie();
    _setWhuffieAddress(address(feeToken));

    uint256 price = 5e18;
    vm.prank(_admin);
    _review.setReviewPrice(true, address(feeToken), price);

    feeToken.mint(_author, 100e18);

    vm.prank(_author);
    feeToken.approve(address(_review), price);

    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSelector(UnexpectedTokenBehavior.selector, price, price - 1));
    _review.addReview(
      EthosReview.Score.Positive, _subject, address(feeToken), "fee transfer", "{}", _emptyAttestation()
    );
  }

  function test_withdrawFundsSelector_revertsAfterUpgrade() public {
    (bool ok,) = address(_review).call(abi.encodeWithSignature("withdrawFunds(address)", address(_whuffie)));

    assertFalse(ok);
  }

  function test_upgradeFromPreviousImplementation_preservesStateAndEnablesBurns() public {
    EthosReviewV1UpgradeHarness legacyReview =
      EthosReviewV1UpgradeHarness(_deployProxy(address(new EthosReviewV1UpgradeHarness())));
    legacyReview.initialize(_owner, _admin, _signer, address(_sigVerifier), address(_cam));
    _setReviewAddress(address(legacyReview));

    uint256 seededReviewId = 7;
    uint256 seededCreatedAt = 123_456;
    AttestationDetails memory attestation = _emptyAttestation();
    legacyReview.seedReview(
      seededReviewId,
      EthosReviewV1UpgradeHarness.Score.Negative,
      _author,
      _subject,
      seededCreatedAt,
      "old comment",
      '{"old":true}',
      attestation,
      bytes32(0)
    );
    legacyReview.setReviewPriceHarness(true, address(0), 0);

    EthosReview newImplementation = new EthosReview();
    vm.prank(_owner);
    legacyReview.upgradeToAndCall(address(newImplementation), "");

    EthosReview upgradedReview = EthosReview(address(legacyReview));

    assertEq(upgradedReview.reviewCount(), seededReviewId + 1);
    assertEq(upgradedReview.reviewIdsByAuthorAddress(_author, 0), seededReviewId);
    assertEq(upgradedReview.reviewIdsBySubjectAddress(_subject, 0), seededReviewId);

    (bool exists, bool allowed) = upgradedReview.targetExistsAndAllowedForId(seededReviewId);
    assertTrue(exists);
    assertTrue(allowed);

    (
      bool archived,
      EthosReview.Score score,
      address author,
      address subject,
      uint256 reviewId,
      uint256 createdAt,
      string memory comment,
      string memory metadata,
      AttestationDetails memory storedAttestation
    ) = upgradedReview.reviews(seededReviewId);

    assertFalse(archived);
    assertEq(uint256(score), uint256(EthosReview.Score.Negative));
    assertEq(author, _author);
    assertEq(subject, _subject);
    assertEq(reviewId, seededReviewId);
    assertEq(createdAt, seededCreatedAt);
    assertEq(comment, "old comment");
    assertEq(metadata, '{"old":true}');
    assertEq(storedAttestation.account, "");
    assertEq(storedAttestation.service, "");

    uint256 price = 3e18;
    vm.prank(_admin);
    upgradedReview.setReviewPrice(true, address(_whuffie), price);

    _whuffie.mint(_author, 100e18);
    vm.prank(_author);
    _whuffie.approve(address(upgradedReview), price);

    uint256 totalSupplyBefore = _whuffie.totalSupply();

    vm.prank(_author);
    upgradedReview.addReview(
      EthosReview.Score.Positive, address(0xB0B), address(_whuffie), "new burn", "{}", _emptyAttestation()
    );

    assertEq(upgradedReview.reviewCount(), seededReviewId + 2);
    assertEq(_whuffie.balanceOf(address(upgradedReview)), 0);
    assertEq(_whuffie.totalSupply(), totalSupplyBefore - price);

    (bool ok,) = address(upgradedReview).call(abi.encodeWithSignature("withdrawFunds(address)", address(_whuffie)));
    assertFalse(ok);
  }

  function test_upgradeFromPreviousImplementation_newImplementationEnforcesUpgradeAuthorization() public {
    EthosReviewV1UpgradeHarness legacyReview =
      EthosReviewV1UpgradeHarness(_deployProxy(address(new EthosReviewV1UpgradeHarness())));
    legacyReview.initialize(_owner, _admin, _signer, address(_sigVerifier), address(_cam));

    EthosReview newImplementation = new EthosReview();
    vm.prank(_owner);
    legacyReview.upgradeToAndCall(address(newImplementation), "");

    EthosReview upgradedReview = EthosReview(address(legacyReview));
    EthosReview nextImplementation = new EthosReview();

    vm.expectRevert(
      abi.encodeWithSelector(
        IAccessControl.AccessControlUnauthorizedAccount.selector, _admin, upgradedReview.OWNER_ROLE()
      )
    );
    vm.prank(_admin);
    upgradedReview.upgradeToAndCall(address(nextImplementation), "");

    vm.expectRevert(SignatureControl.ZeroAddress.selector);
    vm.prank(_owner);
    upgradedReview.upgradeToAndCall(address(0), "");
  }

  function _deployReviewStack() internal {
    _signer = vm.addr(_signerPrivateKey);

    _cam = new ContractAddressManager();
    _sigVerifier = new SignatureVerifier();
    _attestation = new MockReviewAttestation();
    _ic = new InteractionControl(address(this), address(_cam));
    _whuffie = new MockWhuffie();

    _profile = new MockReviewProfile();
    _profile.initialize(_owner);

    _review = EthosReview(_deployProxy(address(new EthosReview())));
    _review.initialize(_owner, _admin, _signer, address(_sigVerifier), address(_cam));

    _registerAddresses(address(_whuffie));
  }

  function _registerAddresses(address whuffie) internal {
    address[] memory addrs = new address[](5);
    string[] memory names = new string[](5);
    addrs[0] = address(_profile);
    names[0] = ETHOS_PROFILE;
    addrs[1] = address(_attestation);
    names[1] = ETHOS_ATTESTATION;
    addrs[2] = address(_ic);
    names[2] = ETHOS_INTERACTION_CONTROL;
    addrs[3] = address(_review);
    names[3] = ETHOS_REVIEW;
    addrs[4] = whuffie;
    names[4] = ETHOS_WHUFFIE;
    _cam.updateContractAddressesForNames(addrs, names);

    string[] memory controlled = new string[](1);
    controlled[0] = ETHOS_REVIEW;
    _ic.addControlledContractNames(controlled);
  }

  function _setWhuffieAddress(address whuffie) internal {
    address[] memory addrs = new address[](1);
    string[] memory names = new string[](1);
    addrs[0] = whuffie;
    names[0] = ETHOS_WHUFFIE;
    _cam.updateContractAddressesForNames(addrs, names);
  }

  function _setReviewAddress(address review) internal {
    address[] memory addrs = new address[](1);
    string[] memory names = new string[](1);
    addrs[0] = review;
    names[0] = ETHOS_REVIEW;
    _cam.updateContractAddressesForNames(addrs, names);
  }

  function _deployProxy(address impl) internal returns (address) {
    return address(new ERC1967Proxy(impl, ""));
  }

  function _mintProfile(address user) internal returns (uint256) {
    _profile.mintProfile(user);
    return _profile.verifiedProfileIdForAddress(user);
  }

  function _setReviewPrice(address paymentToken, uint256 price) internal {
    vm.prank(_admin);
    _review.setReviewPrice(true, paymentToken, price);
  }

  function _signPermit(address owner_, uint256 ownerPk, address spender, uint256 value, uint256 deadline)
    internal
    view
    returns (uint8 v, bytes32 r, bytes32 s)
  {
    bytes32 structHash =
      keccak256(abi.encode(PERMIT_TYPEHASH, owner_, spender, value, _whuffie.nonces(owner_), deadline));
    bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), _whuffie.DOMAIN_SEPARATOR(), structHash));

    (v, r, s) = vm.sign(ownerPk, digest);
  }

  function _emptyAttestation() internal pure returns (AttestationDetails memory) {
    return AttestationDetails({account: "", service: ""});
  }

  // ---------------------------------------------------------------------------
  // reviewAndVouchWithPermit (composite path)
  // ---------------------------------------------------------------------------

  uint256 internal constant _COMPOSITE_VOUCH_AMOUNT = 10e18;
  uint256 internal constant _COMPOSITE_VOUCH_FEE_BPS = 100; // 1%
  uint256 internal constant _COMPOSITE_REVIEW_PRICE = 5e18;
  string internal constant _DEFAULT_VOUCH_USERKEY = "address:0x000000000000000000000000000000000050b1ec7";

  function _registerVouchV2(address vouchV2) internal {
    address[] memory addrs = new address[](1);
    string[] memory names = new string[](1);
    addrs[0] = vouchV2;
    names[0] = ETHOS_VOUCH_V2;
    _cam.updateContractAddressesForNames(addrs, names);
  }

  function _deployMockVouchV2(uint256 entryFeeBps) internal returns (MockVouchV2) {
    return new MockVouchV2(ERC20Burnable(address(_whuffie)), entryFeeBps);
  }

  function _setupComposite(uint256 reviewPrice, uint256 vouchEntryFeeBps)
    internal
    returns (MockVouchV2 vouchV2, address author, uint256 authorKey)
  {
    authorKey = PERMIT_AUTHOR_PRIVATE_KEY;
    author = vm.addr(authorKey);
    _mintProfile(author);
    vouchV2 = _deployMockVouchV2(vouchEntryFeeBps);
    _registerVouchV2(address(vouchV2));
    if (reviewPrice > 0) _setReviewPrice(address(_whuffie), reviewPrice);
  }

  function _compositePermit(address author, uint256 authorKey, uint256 value, uint256 deadline)
    internal
    view
    returns (EthosReview.PermitArgs memory permit)
  {
    (uint8 v, bytes32 r, bytes32 s) = _signPermit(author, authorKey, address(_review), value, deadline);
    permit = EthosReview.PermitArgs({value: value, deadline: deadline, v: v, r: r, s: s});
  }

  /// @dev Invokes `reviewAndVouchWithPermit` against the current `_review`
  ///      with sensible defaults so tests stay compact under the new
  ///      10-arg signature. Pass `subject = address(0)` together with a
  ///      non-empty `attestation` for the service-attestation path.
  function _callComposite(
    address author,
    EthosReview.Score score,
    address subject,
    AttestationDetails memory attestation,
    string memory vouchUserkey,
    uint256 vouchAmount,
    string memory vouchMetadata,
    address paymentToken,
    EthosReview.PermitArgs memory permit
  ) internal {
    vm.prank(author);
    _review.reviewAndVouchWithPermit(
      score,
      subject,
      attestation,
      vouchUserkey,
      vouchAmount,
      vouchMetadata,
      paymentToken,
      "review-comment",
      "{}",
      permit
    );
  }

  function test_reviewAndVouchWithPermit_happyPath_writesReviewAndCallsVouchFor() public {
    (MockVouchV2 vouchV2, address author, uint256 authorKey) =
      _setupComposite(_COMPOSITE_REVIEW_PRICE, _COMPOSITE_VOUCH_FEE_BPS);
    uint256 vouchAmount = _COMPOSITE_VOUCH_AMOUNT;
    uint256 vouchFee = (vouchAmount * _COMPOSITE_VOUCH_FEE_BPS + 9999) / 10_000;
    uint256 vouchGross = vouchAmount + vouchFee;
    uint256 total = _COMPOSITE_REVIEW_PRICE + vouchGross;

    _whuffie.mint(author, total + 100e18);
    uint256 supplyBefore = _whuffie.totalSupply();
    uint256 authorBalBefore = _whuffie.balanceOf(author);
    uint256 reviewBalBefore = _whuffie.balanceOf(address(_review));
    uint256 vouchV2BalBefore = _whuffie.balanceOf(address(vouchV2));

    EthosReview.PermitArgs memory permit = _compositePermit(author, authorKey, total, block.timestamp + 1 hours);

    vm.expectEmit(true, true, false, true, address(_review));
    emit ReviewFeeBurned(author, address(_whuffie), _COMPOSITE_REVIEW_PRICE);

    _callComposite(
      author,
      EthosReview.Score.Positive,
      _subject,
      _emptyAttestation(),
      _DEFAULT_VOUCH_USERKEY,
      vouchAmount,
      "",
      address(_whuffie),
      permit
    );

    // Review row written.
    assertEq(_review.reviewCount(), 1);

    // VouchV2 stub called once with the right calldata.
    assertEq(vouchV2.callCount(), 1);
    (address caller, address authorArg, string memory target, uint256 amountArg, string memory metaArg) = vouchV2.last();
    assertEq(caller, address(_review));
    assertEq(authorArg, author);
    assertEq(amountArg, vouchAmount);
    assertEq(bytes(metaArg).length, 0);

    // Composite forwarded the caller's userkey VERBATIM — no on-chain
    // canonicalization. Equivalent TS-side encoders own canonical form.
    assertEq(target, _DEFAULT_VOUCH_USERKEY);

    // Balance accounting: author paid total; reviewFee burned; vouchV2 holds vouchAmount; vouch fee also burned.
    assertEq(authorBalBefore - _whuffie.balanceOf(author), total);
    assertEq(_whuffie.balanceOf(address(_review)), reviewBalBefore);
    assertEq(_whuffie.balanceOf(address(vouchV2)) - vouchV2BalBefore, vouchAmount);
    assertEq(supplyBefore - _whuffie.totalSupply(), _COMPOSITE_REVIEW_PRICE + vouchFee);

    // No residual allowance from Review to VouchV2 — forceApprove(0) sweep at end.
    assertEq(_whuffie.allowance(address(_review), address(vouchV2)), 0);
    // No residual allowance from author to Review either.
    assertEq(_whuffie.allowance(author, address(_review)), 0);
  }

  function test_reviewAndVouchWithPermit_forwardsVouchUserkeyVerbatim() public {
    (MockVouchV2 vouchV2, address author, uint256 authorKey) = _setupComposite(0, _COMPOSITE_VOUCH_FEE_BPS);
    uint256 vouchFee = (_COMPOSITE_VOUCH_AMOUNT * _COMPOSITE_VOUCH_FEE_BPS + 9999) / 10_000;
    uint256 total = _COMPOSITE_VOUCH_AMOUNT + vouchFee;
    _whuffie.mint(author, total);

    // Weird-but-legal userkey: mixed case, non-canonical prefix. Contract is
    // opaque — passes through unchanged. If a frontend hands us garbage, that
    // garbage hits VouchV2's targetHash mapping; same trust posture as
    // standalone VouchV2.vouch(target, ...).
    string memory weirdUserkey = "address:0xABCDEF0123456789abcdef0123456789ABCDEF01";

    EthosReview.PermitArgs memory permit = _compositePermit(author, authorKey, total, block.timestamp + 1 hours);

    _callComposite(
      author,
      EthosReview.Score.Positive,
      _subject,
      _emptyAttestation(),
      weirdUserkey,
      _COMPOSITE_VOUCH_AMOUNT,
      "",
      address(_whuffie),
      permit
    );

    (,, string memory target,,) = vouchV2.last();
    assertEq(target, weirdUserkey);
  }

  function test_reviewAndVouchWithPermit_passesVouchMetadata() public {
    (MockVouchV2 vouchV2, address author, uint256 authorKey) = _setupComposite(0, _COMPOSITE_VOUCH_FEE_BPS);
    uint256 vouchFee = (_COMPOSITE_VOUCH_AMOUNT * _COMPOSITE_VOUCH_FEE_BPS + 9999) / 10_000;
    uint256 total = _COMPOSITE_VOUCH_AMOUNT + vouchFee;
    _whuffie.mint(author, total);

    string memory vouchMeta = "{\"client\":\"ethos-web\",\"tag\":1}";

    EthosReview.PermitArgs memory permit = _compositePermit(author, authorKey, total, block.timestamp + 1 hours);

    _callComposite(
      author,
      EthosReview.Score.Positive,
      _subject,
      _emptyAttestation(),
      _DEFAULT_VOUCH_USERKEY,
      _COMPOSITE_VOUCH_AMOUNT,
      vouchMeta,
      address(_whuffie),
      permit
    );

    (,,,, string memory metaArg) = vouchV2.last();
    assertEq(metaArg, vouchMeta);
  }

  function test_reviewAndVouchWithPermit_serviceAttestation_writesReviewRowOnly() public {
    (MockVouchV2 vouchV2, address author, uint256 authorKey) = _setupComposite(0, _COMPOSITE_VOUCH_FEE_BPS);
    uint256 vouchFee = (_COMPOSITE_VOUCH_AMOUNT * _COMPOSITE_VOUCH_FEE_BPS + 9999) / 10_000;
    uint256 total = _COMPOSITE_VOUCH_AMOUNT + vouchFee;
    _whuffie.mint(author, total);

    AttestationDetails memory attestation = AttestationDetails({account: "CaseSensitive", service: "X.com"});
    // Caller provides their own userkey — contract does NOT derive one from
    // attestationDetails. This asserts the decoupling.
    string memory callerUserkey = "service:x.com:CaseSensitive";

    EthosReview.PermitArgs memory permit = _compositePermit(author, authorKey, total, block.timestamp + 1 hours);

    _callComposite(
      author,
      EthosReview.Score.Positive,
      address(0),
      attestation,
      callerUserkey,
      _COMPOSITE_VOUCH_AMOUNT,
      "",
      address(_whuffie),
      permit
    );

    // Review row used the typed attestation path (verified by reviewCount + indexes).
    assertEq(_review.reviewCount(), 1);

    // Vouch leg received the caller's userkey untouched — no service-string
    // lowercasing, no on-chain derivation.
    (,, string memory target,,) = vouchV2.last();
    assertEq(target, callerUserkey);
  }

  function test_reviewAndVouchWithPermit_revertsOnZeroVouchAmount() public {
    (, address author, uint256 authorKey) = _setupComposite(_COMPOSITE_REVIEW_PRICE, _COMPOSITE_VOUCH_FEE_BPS);
    EthosReview.PermitArgs memory permit = _compositePermit(author, authorKey, 1, block.timestamp + 1 hours);

    vm.expectRevert(ZeroVouchAmount.selector);
    _callComposite(
      author,
      EthosReview.Score.Positive,
      _subject,
      _emptyAttestation(),
      _DEFAULT_VOUCH_USERKEY,
      0,
      "",
      address(_whuffie),
      permit
    );
  }

  function test_reviewAndVouchWithPermit_revertsOnNegativeReview() public {
    (, address author, uint256 authorKey) = _setupComposite(_COMPOSITE_REVIEW_PRICE, _COMPOSITE_VOUCH_FEE_BPS);
    EthosReview.PermitArgs memory permit = _compositePermit(author, authorKey, 1, block.timestamp + 1 hours);

    vm.expectRevert(VouchRequiresPositiveReview.selector);
    _callComposite(
      author,
      EthosReview.Score.Negative,
      _subject,
      _emptyAttestation(),
      _DEFAULT_VOUCH_USERKEY,
      _COMPOSITE_VOUCH_AMOUNT,
      "",
      address(_whuffie),
      permit
    );
  }

  function test_reviewAndVouchWithPermit_revertsOnNeutralReview() public {
    (, address author, uint256 authorKey) = _setupComposite(_COMPOSITE_REVIEW_PRICE, _COMPOSITE_VOUCH_FEE_BPS);
    EthosReview.PermitArgs memory permit = _compositePermit(author, authorKey, 1, block.timestamp + 1 hours);

    vm.expectRevert(VouchRequiresPositiveReview.selector);
    _callComposite(
      author,
      EthosReview.Score.Neutral,
      _subject,
      _emptyAttestation(),
      _DEFAULT_VOUCH_USERKEY,
      _COMPOSITE_VOUCH_AMOUNT,
      "",
      address(_whuffie),
      permit
    );
  }

  function test_reviewAndVouchWithPermit_revertsOnWrongPaymentToken() public {
    (, address author, uint256 authorKey) = _setupComposite(_COMPOSITE_REVIEW_PRICE, _COMPOSITE_VOUCH_FEE_BPS);
    EthosReview.PermitArgs memory permit = _compositePermit(author, authorKey, 1, block.timestamp + 1 hours);

    vm.expectRevert(abi.encodeWithSelector(WrongPaymentToken.selector, address(0xBEEF)));
    _callComposite(
      author,
      EthosReview.Score.Positive,
      _subject,
      _emptyAttestation(),
      _DEFAULT_VOUCH_USERKEY,
      _COMPOSITE_VOUCH_AMOUNT,
      "",
      address(0xBEEF),
      permit
    );
  }

  function test_reviewAndVouchWithPermit_revertsWhenVouchV2NotRegistered() public {
    // Setup but DON'T register VouchV2 in CAM.
    address author = vm.addr(PERMIT_AUTHOR_PRIVATE_KEY);
    _mintProfile(author);
    _setReviewPrice(address(_whuffie), _COMPOSITE_REVIEW_PRICE);
    EthosReview.PermitArgs memory permit =
      _compositePermit(author, PERMIT_AUTHOR_PRIVATE_KEY, 1, block.timestamp + 1 hours);

    vm.expectRevert(VouchV2NotRegistered.selector);
    _callComposite(
      author,
      EthosReview.Score.Positive,
      _subject,
      _emptyAttestation(),
      _DEFAULT_VOUCH_USERKEY,
      _COMPOSITE_VOUCH_AMOUNT,
      "",
      address(_whuffie),
      permit
    );
  }

  function test_reviewAndVouchWithPermit_revertsOnPermitValueTooLow() public {
    (, address author, uint256 authorKey) = _setupComposite(_COMPOSITE_REVIEW_PRICE, _COMPOSITE_VOUCH_FEE_BPS);
    uint256 vouchFee = (_COMPOSITE_VOUCH_AMOUNT * _COMPOSITE_VOUCH_FEE_BPS + 9999) / 10_000;
    uint256 actualTotal = _COMPOSITE_REVIEW_PRICE + _COMPOSITE_VOUCH_AMOUNT + vouchFee;
    uint256 signedLow = actualTotal - 1;

    EthosReview.PermitArgs memory permit = _compositePermit(author, authorKey, signedLow, block.timestamp + 1 hours);

    vm.expectRevert(abi.encodeWithSelector(PermitValueMismatch.selector, signedLow, actualTotal));
    _callComposite(
      author,
      EthosReview.Score.Positive,
      _subject,
      _emptyAttestation(),
      _DEFAULT_VOUCH_USERKEY,
      _COMPOSITE_VOUCH_AMOUNT,
      "",
      address(_whuffie),
      permit
    );
  }

  function test_reviewAndVouchWithPermit_revertsOnPermitValueTooHigh() public {
    (, address author, uint256 authorKey) = _setupComposite(_COMPOSITE_REVIEW_PRICE, _COMPOSITE_VOUCH_FEE_BPS);
    uint256 vouchFee = (_COMPOSITE_VOUCH_AMOUNT * _COMPOSITE_VOUCH_FEE_BPS + 9999) / 10_000;
    uint256 actualTotal = _COMPOSITE_REVIEW_PRICE + _COMPOSITE_VOUCH_AMOUNT + vouchFee;
    uint256 signedHigh = actualTotal + 1;

    EthosReview.PermitArgs memory permit = _compositePermit(author, authorKey, signedHigh, block.timestamp + 1 hours);

    vm.expectRevert(abi.encodeWithSelector(PermitValueMismatch.selector, signedHigh, actualTotal));
    _callComposite(
      author,
      EthosReview.Score.Positive,
      _subject,
      _emptyAttestation(),
      _DEFAULT_VOUCH_USERKEY,
      _COMPOSITE_VOUCH_AMOUNT,
      "",
      address(_whuffie),
      permit
    );
  }

  function test_reviewAndVouchWithPermit_atomicRevert_whenVouchLegReverts() public {
    (MockVouchV2 vouchV2, address author, uint256 authorKey) =
      _setupComposite(_COMPOSITE_REVIEW_PRICE, _COMPOSITE_VOUCH_FEE_BPS);
    vouchV2.setRevertOnVouchFor(true);
    uint256 vouchFee = (_COMPOSITE_VOUCH_AMOUNT * _COMPOSITE_VOUCH_FEE_BPS + 9999) / 10_000;
    uint256 total = _COMPOSITE_REVIEW_PRICE + _COMPOSITE_VOUCH_AMOUNT + vouchFee;

    _whuffie.mint(author, total);
    uint256 nonceBefore = _whuffie.nonces(author);
    uint256 supplyBefore = _whuffie.totalSupply();
    uint256 authorBalBefore = _whuffie.balanceOf(author);
    uint256 reviewCountBefore = _review.reviewCount();

    EthosReview.PermitArgs memory permit = _compositePermit(author, authorKey, total, block.timestamp + 1 hours);

    vm.expectRevert(bytes("MockVouchV2: configured revert"));
    _callComposite(
      author,
      EthosReview.Score.Positive,
      _subject,
      _emptyAttestation(),
      _DEFAULT_VOUCH_USERKEY,
      _COMPOSITE_VOUCH_AMOUNT,
      "",
      address(_whuffie),
      permit
    );

    // Atomic: no review row written, no nonce consumed, no balance moved, no supply burned.
    assertEq(_review.reviewCount(), reviewCountBefore);
    assertEq(_whuffie.nonces(author), nonceBefore);
    assertEq(_whuffie.balanceOf(author), authorBalBefore);
    assertEq(_whuffie.totalSupply(), supplyBefore);
  }

  function test_reviewAndVouchWithPermit_zeroReviewFee_skipsBurn_butStillVouches() public {
    // Review price = 0 (default); vouchEntryFeeBps = 100.
    (MockVouchV2 vouchV2, address author, uint256 authorKey) = _setupComposite(0, _COMPOSITE_VOUCH_FEE_BPS);
    uint256 vouchFee = (_COMPOSITE_VOUCH_AMOUNT * _COMPOSITE_VOUCH_FEE_BPS + 9999) / 10_000;
    uint256 total = _COMPOSITE_VOUCH_AMOUNT + vouchFee;
    _whuffie.mint(author, total);

    EthosReview.PermitArgs memory permit = _compositePermit(author, authorKey, total, block.timestamp + 1 hours);

    _callComposite(
      author,
      EthosReview.Score.Positive,
      _subject,
      _emptyAttestation(),
      _DEFAULT_VOUCH_USERKEY,
      _COMPOSITE_VOUCH_AMOUNT,
      "",
      address(_whuffie),
      permit
    );

    assertEq(_review.reviewCount(), 1);
    assertEq(vouchV2.callCount(), 1);
    assertEq(_whuffie.balanceOf(author), 0);
  }

  function test_reinitV2ReentrancyGuard_revertsForNonOwner() public {
    vm.expectRevert();
    vm.prank(_author);
    _review.reinitV2ReentrancyGuard();
  }
}
