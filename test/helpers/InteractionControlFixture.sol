// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {ContractAddressManager} from "../../src/utils/ContractAddressManager.sol";
import {InteractionControl} from "../../src/utils/InteractionControl.sol";
import {ETHOS_INTERACTION_CONTROL} from "../../src/utils/Constants.sol";

/// @title InteractionControlFixture
/// @notice Reusable test helper that wires up InteractionControl for pause/unpause tests.
/// @dev Inherit this and call `_setupInteractionControl(cam)` in setUp().
abstract contract InteractionControlFixture {
  InteractionControl internal _ic;
  ContractAddressManager private _icCam;

  function _setupInteractionControl(ContractAddressManager cam) internal {
    _icCam = cam;
    _ic = new InteractionControl(address(this), address(cam));

    address[] memory addrs = new address[](1);
    string[] memory names = new string[](1);
    addrs[0] = address(_ic);
    names[0] = ETHOS_INTERACTION_CONTROL;
    cam.updateContractAddressesForNames(addrs, names);
  }

  function _registerControlledContract(string memory name, address addr) internal {
    address[] memory addrs = new address[](1);
    string[] memory names = new string[](1);
    addrs[0] = addr;
    names[0] = name;
    _icCam.updateContractAddressesForNames(addrs, names);

    string[] memory controlledNames = new string[](1);
    controlledNames[0] = name;
    _ic.addControlledContractNames(controlledNames);
  }

  function _pauseContract(string memory name) internal {
    _ic.pauseContract(name);
  }

  function _unpauseContract(string memory name) internal {
    _ic.unpauseContract(name);
  }
}
