// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {EthosRewards} from "../src/EthosRewards.sol";
import {EthosVouchV2} from "../src/EthosVouchV2.sol";
import {EthosWhuffie} from "../src/EthosWhuffie.sol";
import {WhuffieLockList} from "../src/WhuffieLockList.sol";
import {AccessControlV2} from "../src/utils/AccessControlV2.sol";
import {ContractAddressManager} from "../src/utils/ContractAddressManager.sol";
import {
  ETHOS_ATTESTATION,
  ETHOS_PROFILE,
  ETHOS_REVIEW,
  ETHOS_REWARDS,
  ETHOS_VOUCH_V2,
  ETHOS_WHUFFIE
} from "../src/utils/Constants.sol";

struct WorkflowAttestationDetails {
  string account;
  string service;
}

interface ILegacyReviewWorkflow {
  struct PermitArgs {
    uint256 value;
    uint256 deadline;
    uint8 v;
    bytes32 r;
    bytes32 s;
  }

  function initialize(
    address owner,
    address admin,
    address expectedSigner,
    address signatureVerifier,
    address contractAddressManagerAddr
  ) external;

  function setReviewPrice(bool allowed, address paymentToken, uint256 price) external;

  function reviewAndVouchWithPermit(
    uint8 score,
    address subject,
    WorkflowAttestationDetails calldata attestationDetails,
    string calldata vouchUserkey,
    uint256 vouchAmount,
    string calldata vouchMetadata,
    address paymentToken,
    string calldata comment,
    string calldata metadata,
    PermitArgs calldata permit
  ) external;

  function reviewCount() external view returns (uint256);
}

contract WorkflowProfileMock {
  mapping(address user => uint256 profileId) public profileIdByAddress;
  mapping(bytes32 attestationHash => uint256 profileId) public profileIdByAttestation;

  uint256 private _nextProfileId = 1;

  function mintProfile(address user) external returns (uint256 profileId) {
    profileId = profileIdByAddress[user];
    if (profileId != 0) return profileId;

    profileId = _nextProfileId++;
    profileIdByAddress[user] = profileId;
  }

  function verifiedProfileIdForAddress(address user) external view returns (uint256 profileId) {
    profileId = profileIdByAddress[user];
    if (profileId == 0) revert("WorkflowProfileMock: missing profile");
  }

  function incrementProfileCount(bool isAttestation, address subject, bytes32 attestationHash)
    external
    returns (uint256 profileId)
  {
    profileId = _nextProfileId++;
    if (isAttestation) {
      profileIdByAttestation[attestationHash] = profileId;
    } else {
      profileIdByAddress[subject] = profileId;
    }
  }
}

contract WorkflowAttestationMock {
  function getServiceAndAccountHash(string calldata service, string calldata account) external pure returns (bytes32) {
    return keccak256(abi.encode(service, account));
  }
}

contract EthosReviewWhuffieLockWorkflowTest is Test {
  bytes32 internal constant PERMIT_TYPEHASH =
    keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
  uint8 internal constant SCORE_POSITIVE = 2;
  uint256 internal constant AUTHOR_PRIVATE_KEY = 0xBEEFCAFE;
  uint256 internal constant VOUCH_AMOUNT = 10e18;
  uint256 internal constant VOUCH_ENTRY_FEE_BPS = 100;
  string internal constant VOUCH_USERKEY = "address:0x000000000000000000000000000000000050b1ec7";

  address internal owner = address(this);
  address internal admin = address(0xA11CE);
  address internal signer = address(0x51E);
  address internal subject = address(0x50B1EC7);

  ContractAddressManager internal cam;
  EthosWhuffie internal whuffie;
  EthosVouchV2 internal vouch;
  EthosRewards internal rewards;
  ILegacyReviewWorkflow internal review;
  WorkflowProfileMock internal profile;
  WorkflowAttestationMock internal attestation;

  function setUp() public {
    cam = new ContractAddressManager();
    profile = new WorkflowProfileMock();
    attestation = new WorkflowAttestationMock();

    address signatureVerifier = vm.deployCode("SignatureVerifier.sol:SignatureVerifier");

    WhuffieLockList lockList = new WhuffieLockList(owner);
    address[] memory locked = new address[](1);
    locked[0] = vm.addr(AUTHOR_PRIVATE_KEY);
    lockList.lock(locked);
    whuffie = EthosWhuffie(_deployProxy(address(new EthosWhuffie(lockList))));
    whuffie.initialize(owner, address(cam), type(uint128).max);

    review = ILegacyReviewWorkflow(_deployProxy(vm.deployCode("EthosReview.sol:EthosReview")));
    review.initialize(owner, admin, signer, signatureVerifier, address(cam));

    AccessControlV2.AccessControlInitParams memory initParams = AccessControlV2.AccessControlInitParams({
      owner: owner,
      admin: admin,
      expectedSigner: signer,
      signatureVerifier: signatureVerifier,
      contractAddressManager: address(cam)
    });

    vouch = EthosVouchV2(_deployProxy(address(new EthosVouchV2())));
    vouch.initialize(initParams, address(whuffie), VOUCH_ENTRY_FEE_BPS, 50, 1e18, 50_000e18, 256, 0);

    rewards = EthosRewards(_deployProxy(address(new EthosRewards())));
    rewards.initialize(initParams, address(whuffie), 1000);

    _registerContracts();

    vm.prank(admin);
    review.setReviewPrice(true, address(whuffie), 0);
  }

  function test_reviewAndVouchWithPermit_succeedsDuringWhuffieLockWithZeroReviewFee() public {
    address author = vm.addr(AUTHOR_PRIVATE_KEY);
    profile.mintProfile(author);

    (, uint256 vouchGross) = vouch.previewVouchFee(VOUCH_AMOUNT);
    whuffie.mint(author, vouchGross);
    uint256 supplyBefore = whuffie.totalSupply();

    ILegacyReviewWorkflow.PermitArgs memory permit =
      _permit(author, AUTHOR_PRIVATE_KEY, vouchGross, block.timestamp + 1 hours);

    assertFalse(whuffie.transfersUnlocked());

    vm.prank(author);
    review.reviewAndVouchWithPermit(
      SCORE_POSITIVE,
      subject,
      WorkflowAttestationDetails({account: "", service: ""}),
      VOUCH_USERKEY,
      VOUCH_AMOUNT,
      "",
      address(whuffie),
      "review-comment",
      "{}",
      permit
    );

    assertEq(review.reviewCount(), 1);
    assertEq(whuffie.balanceOf(author), 0);
    assertEq(whuffie.balanceOf(address(review)), 0);
    assertEq(whuffie.balanceOf(address(vouch)), VOUCH_AMOUNT);
    assertEq(supplyBefore - whuffie.totalSupply(), vouchGross - VOUCH_AMOUNT);

    (address vouchAuthor, bool archived,, bytes32 targetHash, uint256 balance) = vouch.vouches(1);
    assertEq(vouchAuthor, author);
    assertFalse(archived);
    assertEq(targetHash, keccak256(bytes(VOUCH_USERKEY)));
    assertEq(balance, VOUCH_AMOUNT);
  }

  function _registerContracts() private {
    address[] memory addrs = new address[](6);
    string[] memory names = new string[](6);
    addrs[0] = address(profile);
    names[0] = ETHOS_PROFILE;
    addrs[1] = address(attestation);
    names[1] = ETHOS_ATTESTATION;
    addrs[2] = address(review);
    names[2] = ETHOS_REVIEW;
    addrs[3] = address(whuffie);
    names[3] = ETHOS_WHUFFIE;
    addrs[4] = address(vouch);
    names[4] = ETHOS_VOUCH_V2;
    addrs[5] = address(rewards);
    names[5] = ETHOS_REWARDS;
    cam.updateContractAddressesForNames(addrs, names);
  }

  function _permit(address author, uint256 authorKey, uint256 value, uint256 deadline)
    private
    view
    returns (ILegacyReviewWorkflow.PermitArgs memory permit)
  {
    bytes32 structHash =
      keccak256(abi.encode(PERMIT_TYPEHASH, author, address(review), value, whuffie.nonces(author), deadline));
    bytes32 digest = MessageHashUtils.toTypedDataHash(whuffie.DOMAIN_SEPARATOR(), structHash);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(authorKey, digest);
    permit = ILegacyReviewWorkflow.PermitArgs({value: value, deadline: deadline, v: v, r: r, s: s});
  }

  function _deployProxy(address impl) private returns (address) {
    return address(new ERC1967Proxy(impl, ""));
  }
}
