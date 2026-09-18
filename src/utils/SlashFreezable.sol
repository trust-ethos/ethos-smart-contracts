// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

import {IFreezable} from "../interfaces/IFreezable.sol";
import {NotSlasher} from "../errors/SlashFreezableErrors.sol";

/**
 * @title SlashFreezable
 * @author Ethos Network
 * @notice Abstract upgradeable base for contracts whose accounts can be frozen by the
 *         registered slasher. Frozen state is held in this contract's storage and
 *         exposed via isFrozen; implementing contracts decide which user actions to
 *         gate behind the frozen flag (typically actions that would defeat an
 *         in-flight slash, e.g. withdrawing stake).
 *
 * @dev Concrete contracts implement `_slasher()` to return the current slasher
 *      address (commonly resolved from a ContractAddressManager). The `onlySlasher`
 *      modifier enforces that only that address can flip freeze state.
 *
 *      Storage layout: one slot for `_frozenAccounts`, plus a 50-slot gap following
 *      the OpenZeppelin convention (each upgradeable base reserves 50 slots regardless
 *      of its current state).
 * @custom:security-contact security@ethos.network
 */
abstract contract SlashFreezable is Initializable, IFreezable {
  /// @notice Tracks which accounts are currently frozen.
  mapping(address => bool) internal _frozenAccounts;

  /// @dev Storage gap for future upgrades to this module.
  uint256[50] private __gap;

  /// @dev Initializer hook. No state to set today — present so inheriting
  ///      contracts can call a named initializer if future storage is added.
  // solhint-disable-next-line func-name-mixedcase
  function __SlashFreezable_init() internal onlyInitializing {}

  /// @dev Resolves the current slasher address. Implementers typically read this
  ///      from a ContractAddressManager so the slasher can be rotated without an
  ///      upgrade.
  function _slasher() internal view virtual returns (address);

  /// @dev Reverts if msg.sender is not the address returned by `_slasher()`.
  modifier onlySlasher() {
    address s = _slasher();
    if (msg.sender != s) {
      revert NotSlasher(msg.sender, s);
    }
    _;
  }

  /// @inheritdoc IFreezable
  function isFrozen(address account) public view virtual returns (bool) {
    return _frozenAccounts[account];
  }

  /// @inheritdoc IFreezable
  function freeze(address account) public virtual onlySlasher {
    _frozenAccounts[account] = true;
    emit Frozen(account, true);
  }

  /// @inheritdoc IFreezable
  function unfreeze(address account) public virtual onlySlasher {
    _frozenAccounts[account] = false;
    emit Frozen(account, false);
  }
}
