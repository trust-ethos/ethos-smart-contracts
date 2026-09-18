// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Burnable} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import {EthosRewards} from "../src/EthosRewards.sol";
import {EthosVouchV2} from "../src/EthosVouchV2.sol";
import {ISlashable} from "../src/interfaces/ISlashable.sol";
import {ETHOS_REWARDS, ETHOS_VOUCH_V2} from "../src/utils/Constants.sol";
import {V2TestFixture} from "./helpers/V2TestFixture.sol";
import {InteractionControlFixture} from "./helpers/InteractionControlFixture.sol";

/// @dev Standard burnable ERC-20 used by the invariant suite.
contract InvToken is ERC20, ERC20Burnable {
  constructor() ERC20("InvToken", "INV") {}

  function mint(address to, uint256 amount) external {
    _mint(to, amount);
  }
}

/// @dev Slasher proxy for the invariant suite — same shape as the unit-test mock.
contract InvSlasher {
  ISlashable private immutable _vault;

  constructor(address vault_) {
    _vault = ISlashable(vault_);
  }

  function freeze(address account) external {
    _vault.freeze(account);
  }

  function unfreeze(address account) external {
    _vault.unfreeze(account);
  }

  function slash(address account, uint256 bps) external returns (uint256) {
    return _vault.slash(account, bps);
  }
}

/// @dev Handler routes random fuzzer inputs into bounded contract calls. Each
///      action wraps the call in try/catch so legitimate revert paths (already
///      vouched, frozen, etc.) do NOT abort the run — only an actual invariant
///      violation should fail the test. Successes are recorded so subsequent
///      handler calls can target real vouches.
contract VouchHandler is Test {
  EthosVouchV2 public immutable vault;
  InvToken public immutable token;
  InvSlasher public immutable slasher;

  address[] public actors;
  uint256[] public liveVouchIds;
  // Counter so handler-generated target strings are unique within an actor.
  uint256 public targetCounter;

  // Public ghost counters — useful when running with -vvv to see which paths fired.
  uint256 public vouchCalls;
  uint256 public unvouchCalls;
  uint256 public increaseCalls;
  uint256 public decreaseCalls;
  uint256 public slashCalls;
  uint256 public freezeCalls;

  constructor(EthosVouchV2 vault_, InvToken token_, InvSlasher slasher_, address[] memory actors_) {
    vault = vault_;
    token = token_;
    slasher = slasher_;
    actors = actors_;
  }

  function _pickActor(uint256 seed) internal view returns (address) {
    return actors[seed % actors.length];
  }

  function vouchAction(uint256 actorSeed, uint256 amount, uint256 targetSeed) external {
    address actor = _pickActor(actorSeed);
    amount = bound(amount, 1e18, 100e18);
    string memory target = string(
      abi.encodePacked("h-", vm.toString(actor), "-", vm.toString(targetSeed), "-", vm.toString(targetCounter++))
    );
    vm.prank(actor);
    try vault.vouch(target, amount) {
      liveVouchIds.push(vault.vouchCount());
      vouchCalls++;
    } catch {}
  }

  function increaseAction(uint256 vidSeed, uint256 amount) external {
    if (liveVouchIds.length == 0) return;
    uint256 vid = liveVouchIds[vidSeed % liveVouchIds.length];
    amount = bound(amount, 1, 100e18);
    (address author,,,,) = vault.vouches(vid);
    vm.prank(author);
    try vault.increaseVouch(vid, amount) {
      increaseCalls++;
    } catch {}
  }

  function decreaseAction(uint256 vidSeed, uint256 amount) external {
    if (liveVouchIds.length == 0) return;
    uint256 vid = liveVouchIds[vidSeed % liveVouchIds.length];
    // Bound generously — most calls will revert (amount exceeds balance, would breach
    // minimum, frozen, etc.); the try/catch keeps those from aborting the run while
    // still letting the legal slice exercise the partial-withdrawal path.
    amount = bound(amount, 1, 100e18);
    (address author,,,,) = vault.vouches(vid);
    vm.prank(author);
    try vault.decreaseVouch(vid, amount) {
      decreaseCalls++;
    } catch {}
  }

  function unvouchAction(uint256 vidSeed) external {
    if (liveVouchIds.length == 0) return;
    uint256 idx = vidSeed % liveVouchIds.length;
    uint256 vid = liveVouchIds[idx];
    (address author,,,,) = vault.vouches(vid);
    vm.prank(author);
    try vault.unvouch(vid) {
      // swap-pop the handler's view of live ids to keep it bounded.
      liveVouchIds[idx] = liveVouchIds[liveVouchIds.length - 1];
      liveVouchIds.pop();
      unvouchCalls++;
    } catch {}
  }

  function unvouchUnhealthyAction(uint256 vidSeed) external {
    if (liveVouchIds.length == 0) return;
    uint256 idx = vidSeed % liveVouchIds.length;
    uint256 vid = liveVouchIds[idx];
    (address author,,,,) = vault.vouches(vid);
    vm.prank(author);
    try vault.unvouchUnhealthy(vid) {
      liveVouchIds[idx] = liveVouchIds[liveVouchIds.length - 1];
      liveVouchIds.pop();
      unvouchCalls++;
    } catch {}
  }

  function slashAction(uint256 actorSeed, uint256 bps) external {
    address actor = _pickActor(actorSeed);
    bps = bound(bps, 0, 12_000); // include over-cap values to exercise revert path
    try slasher.slash(actor, bps) {
      slashCalls++;
    } catch {}
  }

  function freezeAction(uint256 actorSeed) external {
    address actor = _pickActor(actorSeed);
    try slasher.freeze(actor) {
      freezeCalls++;
    } catch {}
  }

  function unfreezeAction(uint256 actorSeed) external {
    address actor = _pickActor(actorSeed);
    try slasher.unfreeze(actor) {} catch {}
  }
}

/// @notice Solvency invariant: at every point in time, the vault's token balance
///         equals the sum of every active vouch's balance. If this ever breaks,
///         either we've under-funded the vault (users can't be paid) or
///         over-funded it (tokens stranded). Either is a critical accounting bug.
contract EthosVouchV2InvariantTest is StdInvariant, V2TestFixture, InteractionControlFixture {
  EthosVouchV2 internal vault;
  InvToken internal token;
  InvSlasher internal slasher;
  VouchHandler internal handler;

  string internal constant CONTRACT_NAME = ETHOS_VOUCH_V2;

  function setUp() public {
    _deployInfra();

    token = new InvToken();

    EthosVouchV2 impl = new EthosVouchV2();
    vault = EthosVouchV2(_deployProxy(address(impl)));
    vault.initialize(
      _defaultInitParams(),
      address(token),
      100, // 1% entry
      50, // 0.5% exit
      1e18,
      50000e18,
      256,
      0
    );

    _setupInteractionControl(_cam);
    _registerControlledContract(CONTRACT_NAME, address(vault));

    EthosRewards rewardsImpl = new EthosRewards();
    EthosRewards rewards = EthosRewards(_deployProxy(address(rewardsImpl)));
    rewards.initialize(_defaultInitParams(), address(token), 1000);
    address[] memory rewardsAddrs = new address[](1);
    string[] memory rewardsNames = new string[](1);
    rewardsAddrs[0] = address(rewards);
    rewardsNames[0] = ETHOS_REWARDS;
    _cam.updateContractAddressesForNames(rewardsAddrs, rewardsNames);
    // vault is already registered in CAM under ETHOS_VOUCH_V2 via
    // _registerControlledContract above, which is what EthosRewards reads to
    // authorize credit/debit callers.

    slasher = new InvSlasher(address(vault));
    address[] memory addrs = new address[](1);
    string[] memory names = new string[](1);
    addrs[0] = address(slasher);
    names[0] = "SLASHER";
    _cam.updateContractAddressesForNames(addrs, names);

    // Three actors keep the state space tractable while still exercising
    // multi-author paths (burns, isolation, simultaneous vouches).
    address[] memory actors = new address[](3);
    actors[0] = address(0xA1);
    actors[1] = address(0xA2);
    actors[2] = address(0xA3);
    for (uint256 i = 0; i < actors.length; i++) {
      token.mint(actors[i], 1_000_000e18);
      vm.prank(actors[i]);
      token.approve(address(vault), type(uint256).max);
    }

    handler = new VouchHandler(vault, token, slasher, actors);

    // Restrict the fuzzer to the handler's external surface.
    targetContract(address(handler));
    bytes4[] memory selectors = new bytes4[](8);
    selectors[0] = handler.vouchAction.selector;
    selectors[1] = handler.increaseAction.selector;
    selectors[2] = handler.unvouchAction.selector;
    selectors[3] = handler.decreaseAction.selector;
    selectors[4] = handler.slashAction.selector;
    selectors[5] = handler.freezeAction.selector;
    selectors[6] = handler.unfreezeAction.selector;
    selectors[7] = handler.unvouchUnhealthyAction.selector;
    targetSelector(StdInvariant.FuzzSelector({addr: address(handler), selectors: selectors}));
  }

  /// @dev THE invariant. Iterates every minted vouch (ids start at 1) and sums
  ///      the active balances. Must equal the vault's token balance after every
  ///      sequence of handler calls.
  function invariant_solvency_vaultBalanceEqualsActiveSum() public view {
    uint256 totalActive;
    uint256 maxId = vault.vouchCount();
    for (uint256 vid = 1; vid <= maxId; vid++) {
      (, bool archived,,, uint256 bal) = vault.vouches(vid);
      if (!archived) {
        totalActive += bal;
      }
    }
    assertEq(token.balanceOf(address(vault)), totalActive, "vault solvency violated");
  }

  /// @dev Unhealthy lifecycle invariant: a vouch can only be unhealthy if it is
  ///      archived — unhealthy is set exclusively by unvouchUnhealthy, which
  ///      archives in the same call. Protects that coupling across refactors.
  function invariant_unhealthyImpliesArchived() public view {
    uint256 maxId = vault.vouchCount();
    for (uint256 vid = 1; vid <= maxId; vid++) {
      (, bool archived, bool unhealthy,,) = vault.vouches(vid);
      if (unhealthy) {
        assertTrue(archived, "unhealthy vouch must be archived");
      }
    }
  }

  /// @dev Fee accounting invariant: totalSupply is monotonically non-increasing.
  ///      Fees and slashed balances are burned — never minted back.
  uint256 internal _lastSeenTotalSupply = type(uint256).max;

  function invariant_totalSupplyMonotonicallyDecreasing() public {
    uint256 current = token.totalSupply();
    assertLe(current, _lastSeenTotalSupply, "totalSupply must never increase after burn");
    _lastSeenTotalSupply = current;
  }

  /// @dev Vouch IDs are append-only: once minted, the count never decreases.
  uint256 internal _lastSeenVouchCount;

  function invariant_vouchCountMonotonic() public {
    uint256 current = vault.vouchCount();
    assertGe(current, _lastSeenVouchCount, "vouchCount must be monotonically increasing");
    _lastSeenVouchCount = current;
  }
}
