// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Burnable} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {EthosVouchV2} from "../src/EthosVouchV2.sol";
import {EthosRewards} from "../src/EthosRewards.sol";
import {ETHOS_REWARDS, ETHOS_VOUCH_V2, SLASHER} from "../src/utils/Constants.sol";
import {V2TestFixture} from "./helpers/V2TestFixture.sol";
import {InteractionControlFixture} from "./helpers/InteractionControlFixture.sol";

contract MockWhuffieToken is ERC20, ERC20Burnable, ERC20Permit {
  constructor() ERC20("Whuffie", "WHUF") ERC20Permit("Whuffie") {}

  function mint(address to, uint256 amount) external {
    _mint(to, amount);
  }
}

/// @title EthosVouchV2 activeBalanceOf
/// @notice Unit coverage for activeBalanceOf: sums an author's active vouch balances and tracks
///         vouch / increase / decrease / unvouch / slash.
contract EthosVouchV2ActiveBalanceTest is V2TestFixture, InteractionControlFixture {
  EthosVouchV2 internal vouch;
  EthosRewards internal rewards;
  MockWhuffieToken internal token;

  address internal alice = address(0xA11CE);

  function setUp() public {
    _deployInfra();
    token = new MockWhuffieToken();

    vouch = EthosVouchV2(_deployProxy(address(new EthosVouchV2())));
    vouch.initialize(_defaultInitParams(), address(token), 100, 50, 1e18, 50000e18, 256, 0);

    _setupInteractionControl(_cam);
    _registerControlledContract(ETHOS_VOUCH_V2, address(vouch));

    rewards = EthosRewards(_deployProxy(address(new EthosRewards())));
    rewards.initialize(_defaultInitParams(), address(token), 1000);
    address[] memory a = new address[](1);
    string[] memory n = new string[](1);
    a[0] = address(rewards);
    n[0] = ETHOS_REWARDS;
    _cam.updateContractAddressesForNames(a, n);

    // Register this test contract as SLASHER so it can call vouch.slash directly.
    address[] memory s = new address[](1);
    string[] memory sn = new string[](1);
    s[0] = address(this);
    sn[0] = SLASHER;
    _cam.updateContractAddressesForNames(s, sn);

    token.mint(alice, 1_000_000e18);
    vm.prank(alice);
    token.approve(address(vouch), type(uint256).max);
  }

  function _vouch(string memory target, uint256 amount) internal returns (uint256) {
    vm.prank(alice);
    vouch.vouch(target, amount);
    return vouch.vouchCount();
  }

  function test_zeroForAuthorWithNoVouches() public view {
    assertEq(vouch.activeBalanceOf(alice), 0);
  }

  function test_sumsAcrossActiveVouches() public {
    _vouch("a", 10e18);
    _vouch("b", 25e18);
    _vouch("c", 5e18);
    assertEq(vouch.activeBalanceOf(alice), 40e18);
  }

  function test_tracksIncreaseVouch() public {
    uint256 id = _vouch("a", 10e18);
    vm.prank(alice);
    vouch.increaseVouch(id, 15e18);
    assertEq(vouch.activeBalanceOf(alice), 25e18);
  }

  function test_dropsByDecreaseVouch() public {
    uint256 id = _vouch("a", 10e18);
    _vouch("b", 5e18);
    vm.prank(alice);
    vouch.decreaseVouch(id, 6e18); // remaining 4e18 stays >= 1e18 minimum
    assertEq(vouch.activeBalanceOf(alice), 9e18); // 4e18 + 5e18
  }

  function test_dropsFullBalanceOnUnvouch() public {
    uint256 id = _vouch("a", 10e18);
    _vouch("b", 5e18);
    vm.prank(alice);
    vouch.unvouch(id);
    assertEq(vouch.activeBalanceOf(alice), 5e18);
  }

  function test_zeroAfterUnvouchingEverything() public {
    uint256 id1 = _vouch("a", 10e18);
    uint256 id2 = _vouch("b", 5e18);
    vm.startPrank(alice);
    vouch.unvouch(id1);
    vouch.unvouch(id2);
    vm.stopPrank();
    assertEq(vouch.activeBalanceOf(alice), 0);
  }

  function test_dropsByAmountAppliedOnPartialSlash() public {
    _vouch("a", 10e18);
    _vouch("b", 30e18); // 40e18 total
    // 10% slash burns 10% of each active vouch: 1e18 + 3e18 = 4e18.
    uint256 burned = vouch.slash(alice, 1000);
    assertEq(burned, 4e18);
    assertEq(vouch.activeBalanceOf(alice), 36e18);
  }

  function test_zeroAfterFullSlash() public {
    _vouch("a", 10e18);
    _vouch("b", 5e18);
    vouch.slash(alice, 10_000); // 100%
    assertEq(vouch.activeBalanceOf(alice), 0);
  }

  function test_tracksSlashThenUnvouchRemainder() public {
    uint256 id = _vouch("a", 10e18);
    vouch.slash(alice, 2000); // 20% -> burns 2e18, remaining 8e18
    assertEq(vouch.activeBalanceOf(alice), 8e18);
    vm.prank(alice);
    vouch.unvouch(id); // drops the remaining 8e18
    assertEq(vouch.activeBalanceOf(alice), 0);
  }
}
