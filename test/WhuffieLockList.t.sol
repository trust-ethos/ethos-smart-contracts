// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Test} from "forge-std/Test.sol";

import {WhuffieLockList} from "../src/WhuffieLockList.sol";

contract WhuffieLockListTest is Test {
  WhuffieLockList internal list;

  address internal owner = makeAddr("owner");
  address internal stranger = makeAddr("stranger");
  address internal alice = makeAddr("alice");
  address internal bob = makeAddr("bob");
  address internal carol = makeAddr("carol");

  function setUp() public {
    list = new WhuffieLockList(owner);
  }

  function _accounts(address a) internal pure returns (address[] memory accounts) {
    accounts = new address[](1);
    accounts[0] = a;
  }

  function _accounts(address a, address b) internal pure returns (address[] memory accounts) {
    accounts = new address[](2);
    accounts[0] = a;
    accounts[1] = b;
  }

  // --- lock ---

  function test_lock_sets_only_listed_accounts() public {
    vm.prank(owner);
    list.lock(_accounts(alice, bob));

    assertTrue(list.isLocked(alice));
    assertTrue(list.isLocked(bob));
    assertFalse(list.isLocked(carol));
  }

  function test_lock_accumulates_across_batches() public {
    vm.prank(owner);
    list.lock(_accounts(alice));
    vm.prank(owner);
    list.lock(_accounts(bob));

    assertTrue(list.isLocked(alice));
    assertTrue(list.isLocked(bob));
  }

  function test_lock_emits_AccountLocked_per_account() public {
    vm.expectEmit(true, true, true, true, address(list));
    emit WhuffieLockList.AccountLocked(alice);
    vm.expectEmit(true, true, true, true, address(list));
    emit WhuffieLockList.AccountLocked(bob);
    vm.prank(owner);
    list.lock(_accounts(alice, bob));
  }

  function test_lock_reverts_for_non_owner() public {
    vm.prank(stranger);
    vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
    list.lock(_accounts(alice));
  }

  // --- lock is permanent ---

  function test_lock_is_permanent_no_unlock_selector() public {
    vm.prank(owner);
    list.lock(_accounts(alice));

    address[] memory accounts = _accounts(alice);
    vm.prank(owner);
    (bool success,) = address(list).call(abi.encodeWithSignature("unlock(address[])", accounts));

    assertFalse(success);
    assertTrue(list.isLocked(alice));
  }

  // --- constructor ---

  function test_constructor_reverts_on_zero_owner() public {
    vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableInvalidOwner.selector, address(0)));
    new WhuffieLockList(address(0));
  }
}
