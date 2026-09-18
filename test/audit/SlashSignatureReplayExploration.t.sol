// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

import {EthosSlash} from "../../src/legacy/EthosSlash.sol";
import {AttestationDetails} from "../../src/utils/Structs.sol";
import {SlashFixture} from "../helpers/SlashFixture.sol";

contract AlwaysValid1271Signer is IERC1271 {
  function isValidSignature(bytes32, bytes memory) external pure returns (bytes4) {
    return IERC1271.isValidSignature.selector;
  }
}

contract SlashSignatureReplayExplorationTest is SlashFixture {
  address private constant AUTHOR = address(0xA11CE01);
  address private constant SUBJECT = address(0xB0B01);

  function setUp() public {
    _deploySlashStack();
    _mintProfile(AUTHOR);
    _mintProfile(SUBJECT);
  }

  function test_audit_createSlashSignatureReplaysAcrossSlashContracts() public {
    uint256 authorProfileId = _profile.verifiedProfileIdForAddress(AUTHOR);
    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory signature = _signCreateSlash(
      authorProfileId, 777, NO_EXPIRY, SUBJECT, 1, "replay", "meta", attestation, EthosSlash.SlashType.SCORE
    );

    vm.prank(AUTHOR);
    _slash.createSlash(
      SUBJECT, 1, "replay", "meta", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 777, 0, signature
    );

    EthosSlash secondSlash = EthosSlash(_deployProxy(address(new EthosSlash())));
    secondSlash.initialize(_owner, _admin, _signer, address(_sigVerifier), address(_cam));

    vm.prank(AUTHOR);
    secondSlash.createSlash(
      SUBJECT, 1, "replay", "meta", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 777, 0, signature
    );

    assertEq(secondSlash.slashCount(), 2);
  }

  function test_audit_createSlashSignatureIgnoresChainId() public {
    uint256 originalChainId = block.chainid;
    uint256 authorProfileId = _profile.verifiedProfileIdForAddress(AUTHOR);
    AttestationDetails memory attestation = _emptyAttestation();
    bytes memory signature = _signCreateSlash(
      authorProfileId, 888, NO_EXPIRY, SUBJECT, 1, "chain", "meta", attestation, EthosSlash.SlashType.SCORE
    );

    vm.chainId(originalChainId + 1);

    vm.prank(AUTHOR);
    _slash.createSlash(
      SUBJECT, 1, "chain", "meta", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 888, 0, signature
    );

    assertEq(_slash.slashCount(), 2);
  }

  function test_audit_resolveSlashSignatureIgnoresChainId() public {
    uint256 slashId = _createFinancialSlash(AUTHOR, SUBJECT, 999);
    _warpPastDuration();

    uint256 originalChainId = block.chainid;
    bytes memory signature = _signResolveSlash(slashId, EthosSlash.SlashResolution.SLASHED, 100, 123);

    vm.chainId(originalChainId + 1);

    _slash.resolveSlash(slashId, EthosSlash.SlashResolution.SLASHED, 100, 123, signature);

    assertEq(uint256(_slash.financialSlash(slashId).resolution), uint256(EthosSlash.SlashResolution.SLASHED));
  }

  function test_audit_signatureReplayGuardKeysRawSignatureNotPayload() public {
    AlwaysValid1271Signer signer = new AlwaysValid1271Signer();
    vm.prank(_admin);
    _slash.updateExpectedSigner(address(signer));

    AttestationDetails memory attestation = _emptyAttestation();

    vm.prank(AUTHOR);
    _slash.createSlash(SUBJECT, 1, "same", "meta", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 444, 0, hex"01");

    vm.prank(AUTHOR);
    _slash.cancelSlash(1);

    vm.prank(AUTHOR);
    _slash.createSlash(SUBJECT, 1, "same", "meta", attestation, EthosSlash.SlashType.SCORE, NO_EXPIRY, 444, 0, hex"02");

    assertEq(_slash.slashCount(), 3);
  }
}
