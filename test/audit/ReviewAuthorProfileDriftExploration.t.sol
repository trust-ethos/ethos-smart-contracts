// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ContractAddressManager} from "../../src/utils/ContractAddressManager.sol";
import {InteractionControl} from "../../src/utils/InteractionControl.sol";
import {SignatureVerifier} from "../../src/legacy/SignatureVerifier.sol";
import {EthosProfile} from "../../src/legacy/EthosProfile.sol";
import {EthosReview} from "../../src/legacy/EthosReview.sol";
import {AttestationDetails} from "../../src/utils/Structs.sol";
import {ETHOS_ATTESTATION, ETHOS_INTERACTION_CONTROL, ETHOS_PROFILE, ETHOS_REVIEW} from "../../src/utils/Constants.sol";

contract AuditReviewAttestation {
  function getServiceAndAccountHash(string calldata service, string calldata account) external pure returns (bytes32) {
    return keccak256(abi.encode(service, account));
  }
}

contract ReviewAuthorProfileDriftExplorationTest is Test {
  uint256 private constant OWNER_PROFILE_ID = 1;
  uint256 private constant SIGNER_PRIVATE_KEY = 0xA11CE;

  address private constant OWNER = address(0x1);
  address private constant ADMIN = address(0x2);
  address private constant AUTHOR_PRIMARY = address(0xA11CE);
  address private constant AUTHOR_SECONDARY = address(0xA11CE2);
  address private constant NEW_PROFILE_PRIMARY = address(0xB0B);
  address private constant SUBJECT = address(0x50B1EC7);

  ContractAddressManager private _cam;
  EthosProfile private _profile;
  EthosReview private _review;

  function setUp() public {
    address signer = vm.addr(SIGNER_PRIVATE_KEY);

    _cam = new ContractAddressManager();
    SignatureVerifier sigVerifier = new SignatureVerifier();
    AuditReviewAttestation attestation = new AuditReviewAttestation();
    InteractionControl ic = new InteractionControl(address(this), address(_cam));

    _profile = EthosProfile(_deployProxy(address(new EthosProfile())));
    _profile.initialize(OWNER, ADMIN, signer, address(sigVerifier), address(_cam));

    _review = EthosReview(_deployProxy(address(new EthosReview())));
    _review.initialize(OWNER, ADMIN, signer, address(sigVerifier), address(_cam));

    address[] memory addrs = new address[](4);
    string[] memory names = new string[](4);
    addrs[0] = address(_profile);
    names[0] = ETHOS_PROFILE;
    addrs[1] = address(attestation);
    names[1] = ETHOS_ATTESTATION;
    addrs[2] = address(ic);
    names[2] = ETHOS_INTERACTION_CONTROL;
    addrs[3] = address(_review);
    names[3] = ETHOS_REVIEW;
    _cam.updateContractAddressesForNames(addrs, names);
  }

  function test_audit_reviewEditAuthorityMovesWithAuthorAddressCurrentProfile() public {
    uint256 authorProfile = _mintProfile(AUTHOR_PRIMARY);
    _registerAddress(AUTHOR_PRIMARY, AUTHOR_SECONDARY, authorProfile, 11);

    vm.prank(AUTHOR_SECONDARY);
    _review.addReview(
      EthosReview.Score.Positive, SUBJECT, address(0), "original", "original-metadata", _emptyAttestation()
    );

    uint256 newProfile = _mintProfile(NEW_PROFILE_PRIMARY);

    vm.prank(AUTHOR_PRIMARY);
    _profile.deleteAddress(AUTHOR_SECONDARY, false);
    _registerAddress(NEW_PROFILE_PRIMARY, AUTHOR_SECONDARY, newProfile, 22);

    vm.prank(NEW_PROFILE_PRIMARY);
    _review.editReview(0, "edited-by-new-profile", "new-profile-metadata");

    (,,,,,, string memory comment, string memory metadata,) = _review.reviews(0);
    assertEq(comment, "edited-by-new-profile");
    assertEq(metadata, "new-profile-metadata");
  }

  function _deployProxy(address impl) private returns (address) {
    return address(new ERC1967Proxy(impl, ""));
  }

  function _mintProfile(address user) private returns (uint256) {
    vm.prank(OWNER);
    _profile.inviteAddress(user);
    vm.prank(user);
    _profile.createProfile(OWNER_PROFILE_ID);
    return _profile.verifiedProfileIdForAddress(user);
  }

  function _registerAddress(address profileOwner, address newAddr, uint256 profileId, uint256 randValue) private {
    bytes memory sig = _signHash(keccak256(abi.encodePacked(newAddr, profileId, randValue)));
    vm.prank(profileOwner);
    _profile.registerAddress(newAddr, profileId, randValue, sig);
  }

  function _signHash(bytes32 messageHash) private pure returns (bytes memory) {
    bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(messageHash);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PRIVATE_KEY, ethSignedHash);
    return abi.encodePacked(r, s, v);
  }

  function _emptyAttestation() private pure returns (AttestationDetails memory) {
    return AttestationDetails({account: "", service: ""});
  }
}
