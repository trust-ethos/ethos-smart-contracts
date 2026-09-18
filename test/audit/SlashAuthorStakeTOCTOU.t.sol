// SPDX-License-Identifier: MIT
pragma solidity 0.8.26 || 0.8.33;

import {SlashFixture} from "../helpers/SlashFixture.sol";
import {EthosSlash} from "../../src/legacy/EthosSlash.sol";
import {AttestationDetails} from "../../src/utils/Structs.sol";

/// @title SlashAuthorStakeTOCTOU
/// @notice Covers the sign->create time-of-check/time-of-use hole in FINANCIAL slashes and the
///         fix: an `authorMinBalance` floor bound into the createSlash signature and
///         re-checked on-chain over the frozen author snapshot. An author who held a balance when
///         Echo signed can no longer shed it (unvouch or deleteAddress) before submitting.
contract SlashAuthorStakeTOCTOU is SlashFixture {
  address internal _author = address(0xA17);
  address internal _subject = address(0x5B1);

  uint256 internal _authorProfileId;

  function setUp() public {
    _deploySlashStack();
    _authorProfileId = _mintProfile(_author);
  }

  // --- helpers ---

  /// @dev Signs a FINANCIAL createSlash for `_author` against `_subject`, binding `floor`.
  function _floorSig(uint256 randValue, uint256 floor) internal view returns (bytes memory) {
    return _signCreateSlash(
      _authorProfileId,
      randValue,
      NO_EXPIRY,
      _subject,
      0,
      "financial",
      "m",
      _emptyAttestation(),
      EthosSlash.SlashType.FINANCIAL,
      floor
    );
  }

  /// @dev Submits the FINANCIAL createSlash with the bound `floor`.
  function _createFinancial(uint256 randValue, uint256 floor, bytes memory sig) internal returns (uint256 id) {
    id = _slash.slashCount();
    vm.prank(_author);
    _slash.createSlash(
      _subject,
      0,
      "financial",
      "m",
      _emptyAttestation(),
      EthosSlash.SlashType.FINANCIAL,
      NO_EXPIRY,
      randValue,
      floor,
      sig
    );
  }

  // --- the attack: unvouch variant ---

  function test_unvouchVariant_revertsWhenStakeDrainedAfterSigning() public {
    // Author holds enough balance when Echo signs a floor of 100.
    _vouchV2.setActiveBalance(_author, 100);
    bytes memory sig = _floorSig(1, 100);

    // Author drains it (models unvouch/decreaseVouch) before submitting. Not frozen yet.
    _vouchV2.setActiveBalance(_author, 0);

    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSelector(EthosSlash.AuthorBalanceBelowFloor.selector, 0, 100));
    _slash.createSlash(
      _subject, 0, "financial", "m", _emptyAttestation(), EthosSlash.SlashType.FINANCIAL, NO_EXPIRY, 1, 100, sig
    );
  }

  function test_unvouchVariant_revertsOnPartialDrainBelowFloor() public {
    _vouchV2.setActiveBalance(_author, 100);
    bytes memory sig = _floorSig(1, 100);
    _vouchV2.setActiveBalance(_author, 99); // one wei short

    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSelector(EthosSlash.AuthorBalanceBelowFloor.selector, 99, 100));
    _slash.createSlash(
      _subject, 0, "financial", "m", _emptyAttestation(), EthosSlash.SlashType.FINANCIAL, NO_EXPIRY, 1, 100, sig
    );
  }

  // --- the attack: deleteAddress variant ---

  function test_deleteAddressVariant_revertsWhenStakeWalletRemovedFromProfile() public {
    address wallet = address(0xBEEF);
    _registerAddress(_author, wallet, _authorProfileId);
    // All the balance lives on the secondary wallet; the calling primary holds nothing.
    _vouchV2.setActiveBalance(wallet, 100);
    _vouchV2.setActiveBalance(_author, 0);

    bytes memory sig = _floorSig(1, 100);

    // Detach the balance-holding wallet from the profile so it is never snapshotted. Touches
    // EthosProfile only; the mock's per-address balance on `wallet` is untouched.
    vm.prank(_author);
    _profile.deleteAddress(wallet, false);

    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSelector(EthosSlash.AuthorBalanceBelowFloor.selector, 0, 100));
    _slash.createSlash(
      _subject, 0, "financial", "m", _emptyAttestation(), EthosSlash.SlashType.FINANCIAL, NO_EXPIRY, 1, 100, sig
    );
  }

  function test_deleteAddressVariant_controlSucceedsWhenWalletKept() public {
    address wallet = address(0xBEEF);
    _registerAddress(_author, wallet, _authorProfileId);
    _vouchV2.setActiveBalance(wallet, 100);
    _vouchV2.setActiveBalance(_author, 0);

    bytes memory sig = _floorSig(1, 100);
    // No deleteAddress: the snapshot sums author(0) + wallet(100) = 100 >= floor.
    _createFinancial(1, 100, sig);

    assertTrue(_vouchV2.frozen(_author));
    assertTrue(_vouchV2.frozen(wallet));
  }

  // --- the fix: happy path and exact boundary (no slack) ---

  function test_floorMet_succeeds() public {
    _vouchV2.setActiveBalance(_author, 100);
    bytes memory sig = _floorSig(1, 100);
    _createFinancial(1, 100, sig); // exactly at the floor passes (>=, no slack)
    assertTrue(_vouchV2.frozen(_author));
  }

  function test_floorExceeded_succeeds() public {
    _vouchV2.setActiveBalance(_author, 1000);
    bytes memory sig = _floorSig(1, 100);
    _createFinancial(1, 100, sig);
    assertTrue(_vouchV2.frozen(_author));
  }

  // --- multi-address summation (cross-address early exit) ---

  function test_stakeSummedAcrossProfileAddresses() public {
    address wallet = address(0xBEEF);
    _registerAddress(_author, wallet, _authorProfileId);
    _vouchV2.setActiveBalance(_author, 60);
    _vouchV2.setActiveBalance(wallet, 60); // 120 total clears a 100 floor

    bytes memory sig = _floorSig(1, 100);
    _createFinancial(1, 100, sig);
    assertTrue(_vouchV2.frozen(_author));
    assertTrue(_vouchV2.frozen(wallet));
  }

  function test_stakeSummedAcrossProfileAddresses_revertsWhenCombinedShort() public {
    address wallet = address(0xBEEF);
    _registerAddress(_author, wallet, _authorProfileId);
    _vouchV2.setActiveBalance(_author, 60);
    _vouchV2.setActiveBalance(wallet, 30); // 90 total < 100 floor

    bytes memory sig = _floorSig(1, 100);
    vm.prank(_author);
    vm.expectRevert(abi.encodeWithSelector(EthosSlash.AuthorBalanceBelowFloor.selector, 90, 100));
    _slash.createSlash(
      _subject, 0, "financial", "m", _emptyAttestation(), EthosSlash.SlashType.FINANCIAL, NO_EXPIRY, 1, 100, sig
    );
  }

  // --- semantics: floor of 0 means no floor; signature binds the floor ---

  function test_zeroFloor_skipsCheck_documentsEchoNoFloorChoice() public {
    _vouchV2.setActiveBalance(_author, 0); // no balance at all
    bytes memory sig = _floorSig(1, 0); // Echo bound no floor
    _createFinancial(1, 0, sig); // succeeds: authorMinBalance == 0 is "no floor"
    assertTrue(_vouchV2.frozen(_author));
  }

  function test_signatureBindsFloor_cannotSubmitLowerFloorThanSigned() public {
    _vouchV2.setActiveBalance(_author, 100);
    bytes memory signedAt100 = _floorSig(1, 100);

    // Submitting with a lower floor (50) than was signed (100) changes the payload hash, so
    // signature verification fails before the balance check is ever reached.
    _vouchV2.setActiveBalance(_author, 50);
    vm.prank(_author);
    vm.expectRevert();
    _slash.createSlash(
      _subject, 0, "financial", "m", _emptyAttestation(), EthosSlash.SlashType.FINANCIAL, NO_EXPIRY, 1, 50, signedAt100
    );
  }
}
