// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {EthosWhuffie} from "../../src/EthosWhuffie.sol";
import {WhuffieLockList} from "../../src/WhuffieLockList.sol";
import {AccessControlV2} from "../../src/utils/AccessControlV2.sol";
import {SignatureVerifier} from "../../src/legacy/SignatureVerifier.sol";
import {ContractAddressManager} from "../../src/utils/ContractAddressManager.sol";

/// @title V2TestFixture
/// @notice Shared addresses and infrastructure for v2 contract tests.
/// @dev Inherit this and call `_deployInfra()` in setUp(). Then use
///      `_defaultInitParams()` to build AccessControlInitParams.
abstract contract V2TestFixture is Test {
  SignatureVerifier internal _sigVerifier;
  ContractAddressManager internal _cam;

  address internal _owner = address(0x1);
  address internal _admin = address(0x2);
  uint256 internal _signerPrivateKey = 0xA11CE;
  address internal _signer;
  address internal _user = address(0xBEEF);
  address internal _user2 = address(0xCAFE);

  uint256 internal constant _WHUFFIE_TOKEN_CAP = type(uint128).max;
  string internal constant _WHUFFIE_TOKEN_NAME = "Whuffie";
  string internal constant _WHUFFIE_TOKEN_SYMBOL = "WHUF";
  string internal constant _MMB_TOKEN_NAME = "MeowMeowBeenz";
  string internal constant _MMB_TOKEN_SYMBOL = "MMB";

  /// @dev Deploys SignatureVerifier, ContractAddressManager, and derives signer address.
  function _deployInfra() internal {
    _signer = vm.addr(_signerPrivateKey);
    _sigVerifier = new SignatureVerifier();
    _cam = new ContractAddressManager();
  }

  /// @dev Returns default AccessControlInitParams using fixture addresses.
  function _defaultInitParams() internal view returns (AccessControlV2.AccessControlInitParams memory) {
    return AccessControlV2.AccessControlInitParams({
      owner: _owner,
      admin: _admin,
      expectedSigner: _signer,
      signatureVerifier: address(_sigVerifier),
      contractAddressManager: address(_cam)
    });
  }

  /// @dev Deploys a UUPS proxy for the given implementation and returns the proxy address.
  function _deployProxy(address impl) internal returns (address) {
    return address(new ERC1967Proxy(impl, ""));
  }

  /// @dev Deploys an EthosWhuffie implementation bound to an empty lock list.
  function _deployWhuffieImpl() internal returns (EthosWhuffie) {
    return _deployWhuffieImpl(new address[](0));
  }

  /// @dev Deploys an EthosWhuffie implementation bound to a lock list of `locked`, owned by this contract.
  function _deployWhuffieImpl(address[] memory locked) internal returns (EthosWhuffie) {
    WhuffieLockList list = new WhuffieLockList(address(this));
    list.lock(locked);
    return new EthosWhuffie(list);
  }

  /// @dev Signs a message hash with the fixture's signer key. Reusable by any
  ///      contract test that needs ECDSA-signed claims.
  function _signHash(bytes32 messageHash) internal view returns (bytes memory) {
    bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(messageHash);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(_signerPrivateKey, ethSignedHash);
    return abi.encodePacked(r, s, v);
  }
}
