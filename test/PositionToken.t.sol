// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {Test} from "forge-std/Test.sol";
import {PositionToken} from "../src/PositionToken.sol";
import {OnlyMarket, TransferToZeroAddress, TransferToMarket} from "../src/errors/PositionTokenErrors.sol";

contract PositionTokenTest is Test {
  PositionToken public token;
  address public marketAddr;
  address public alice = address(0xA11CE);
  address public bob = address(0xB0B);

  function setUp() public {
    // Deploy from this contract — so `market` immutable = address(this)
    token = new PositionToken("Trust #1", "TRUST-1", 1, true);
    marketAddr = address(this);
  }

  // --- Construction ---

  function test_constructor_setsMarket() public view {
    assertEq(token.market(), marketAddr);
  }

  function test_constructor_setsMarketId() public view {
    assertEq(token.marketId(), 1);
  }

  function test_constructor_setsIsPositive() public view {
    assertTrue(token.isPositive());
  }

  function test_constructor_setsNameAndSymbol() public view {
    assertEq(token.name(), "Trust #1");
    assertEq(token.symbol(), "TRUST-1");
  }

  function test_constructor_zeroInitialSupply() public view {
    assertEq(token.totalSupply(), 0);
  }

  // --- Mint ---

  function test_mint_succeeds() public {
    token.mint(alice, 100e18);
    assertEq(token.balanceOf(alice), 100e18);
    assertEq(token.totalSupply(), 100e18);
  }

  function test_mint_revertsForNonMarket() public {
    vm.expectRevert(OnlyMarket.selector);
    vm.prank(alice);
    token.mint(alice, 100e18);
  }

  // --- Burn ---

  function test_burn_succeeds() public {
    token.mint(alice, 100e18);
    token.burn(alice, 40e18);
    assertEq(token.balanceOf(alice), 60e18);
    assertEq(token.totalSupply(), 60e18);
  }

  function test_burn_revertsForNonMarket() public {
    token.mint(alice, 100e18);
    vm.expectRevert(OnlyMarket.selector);
    vm.prank(alice);
    token.burn(alice, 50e18);
  }

  // --- Transfer restrictions ---

  function test_transfer_revertsToZeroAddress() public {
    token.mint(alice, 100e18);
    vm.expectRevert(TransferToZeroAddress.selector);
    vm.prank(alice);
    token.transfer(address(0), 50e18);
  }

  function test_transfer_revertsToMarket() public {
    token.mint(alice, 100e18);
    vm.expectRevert(TransferToMarket.selector);
    vm.prank(alice);
    token.transfer(marketAddr, 50e18);
  }

  function test_transfer_succeedsBetweenUsers() public {
    token.mint(alice, 100e18);
    vm.prank(alice);
    token.transfer(bob, 40e18);
    assertEq(token.balanceOf(alice), 60e18);
    assertEq(token.balanceOf(bob), 40e18);
  }

  // --- TransferFrom restrictions ---

  function test_transferFrom_revertsToZeroAddress() public {
    token.mint(alice, 100e18);
    vm.prank(alice);
    token.approve(bob, 100e18);
    vm.expectRevert(TransferToZeroAddress.selector);
    vm.prank(bob);
    token.transferFrom(alice, address(0), 50e18);
  }

  function test_transferFrom_revertsToMarket() public {
    token.mint(alice, 100e18);
    vm.prank(alice);
    token.approve(bob, 100e18);
    vm.expectRevert(TransferToMarket.selector);
    vm.prank(bob);
    token.transferFrom(alice, marketAddr, 50e18);
  }

  function test_transferFrom_succeedsWithApproval() public {
    token.mint(alice, 100e18);
    vm.prank(alice);
    token.approve(bob, 60e18);
    vm.prank(bob);
    token.transferFrom(alice, bob, 60e18);
    assertEq(token.balanceOf(alice), 40e18);
    assertEq(token.balanceOf(bob), 60e18);
  }

  function test_transferFrom_revertsWithoutApproval() public {
    token.mint(alice, 100e18);
    vm.expectRevert();
    vm.prank(bob);
    token.transferFrom(alice, bob, 50e18);
  }

  // --- Fuzz ---

  function testFuzz_mintBurn_roundTrip(uint256 amount) public {
    amount = bound(amount, 1, type(uint128).max);
    token.mint(alice, amount);
    assertEq(token.balanceOf(alice), amount);
    assertEq(token.totalSupply(), amount);

    token.burn(alice, amount);
    assertEq(token.balanceOf(alice), 0);
    assertEq(token.totalSupply(), 0);
  }

  function testFuzz_transfer_preservesTotalSupply(uint256 mintAmount, uint256 sendAmount) public {
    mintAmount = bound(mintAmount, 1, type(uint128).max);
    sendAmount = bound(sendAmount, 1, mintAmount);

    token.mint(alice, mintAmount);
    vm.prank(alice);
    token.transfer(bob, sendAmount);

    assertEq(token.balanceOf(alice) + token.balanceOf(bob), mintAmount);
    assertEq(token.totalSupply(), mintAmount);
  }
}
