// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {Test} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {EthosRewards} from "../src/EthosRewards.sol";
import {AccessControlV2} from "../src/utils/AccessControlV2.sol";
import {ETHOS_REWARDS, ETHOS_VOUCH_V2} from "../src/utils/Constants.sol";
import {V2TestFixture} from "./helpers/V2TestFixture.sol";
import {InteractionControlFixture} from "./helpers/InteractionControlFixture.sol";

/// @dev Plain ERC-20 used as the reward token by the invariant suite.
contract InvRewardToken is ERC20 {
  constructor() ERC20("InvReward", "INV") {}

  function mint(address to, uint256 amount) external {
    _mint(to, amount);
  }
}

/// @dev Empty accruing-contract stand-in; registered in CAM under
///      ETHOS_VOUCH_V2 so EthosRewards recognises it as the authorized caller.
contract InvAccruingContract {}

/// @dev Routes random fuzzer inputs into bounded contract calls and tracks
///      ghost state needed to express the invariants. Each action wraps the
///      contract call in try/catch — legitimate revert paths (insufficient
///      committed balance, no rewards to claim, etc.) must NOT abort the run.
contract RewardsHandler is Test {
  EthosRewards public immutable vault;
  InvRewardToken public immutable token;
  address public immutable accruingContract;

  address[] public actors;

  // Ghost state.
  uint256 public ghostTotalCommitted;
  uint256 public ghostTotalClaimed;

  // Visibility counters for `forge test -vvv`.
  uint256 public creditCalls;
  uint256 public debitCalls;
  uint256 public claimCalls;
  uint256 public timeWarps;
  uint256 public rateChanges;

  constructor(EthosRewards vault_, InvRewardToken token_, address accruingContract_, address[] memory actors_) {
    vault = vault_;
    token = token_;
    accruingContract = accruingContract_;
    actors = actors_;
  }

  function _pickActor(uint256 seed) internal view returns (address) {
    return actors[seed % actors.length];
  }

  function creditAction(uint256 actorSeed, uint256 amount) external {
    address actor = _pickActor(actorSeed);
    amount = bound(amount, 1, 1_000e18);
    vm.prank(accruingContract);
    try vault.credit(actor, amount) {
      ghostTotalCommitted += amount;
      creditCalls++;
    } catch {}
  }

  function debitAction(uint256 actorSeed, uint256 amount) external {
    address actor = _pickActor(actorSeed);
    uint256 balance = vault.committedBalance(actor);
    if (balance == 0) return;
    amount = bound(amount, 1, balance);
    vm.prank(accruingContract);
    try vault.debit(actor, amount) {
      ghostTotalCommitted -= amount;
      debitCalls++;
    } catch {}
  }

  function claimAction(uint256 actorSeed) external {
    address actor = _pickActor(actorSeed);
    uint256 before = token.balanceOf(actor);
    vm.prank(actor);
    try vault.claim() {
      ghostTotalClaimed += token.balanceOf(actor) - before;
      claimCalls++;
    } catch {}
  }

  function warpAction(uint256 seconds_) external {
    seconds_ = bound(seconds_, 1, 30 days);
    skip(seconds_);
    timeWarps++;
  }

  function rateAction(uint256 newRate) external {
    newRate = bound(newRate, 0, vault.MAX_EMISSION_RATE_BPS());
    try vault.setEmissionRate(newRate) {
      rateChanges++;
    } catch {}
  }

  function actorsLength() external view returns (uint256) {
    return actors.length;
  }

  function actorAt(uint256 i) external view returns (address) {
    return actors[i];
  }
}

contract EthosRewardsInvariantTest is V2TestFixture, InteractionControlFixture {
  EthosRewards internal vault;
  InvRewardToken internal token;
  RewardsHandler internal handler;

  address internal accruingContract;

  uint256 internal constant INITIAL_RATE_BPS = 2000;
  uint256 internal constant INITIAL_POOL = 1_000_000e18;

  function setUp() public {
    _deployInfra();
    token = new InvRewardToken();

    EthosRewards impl = new EthosRewards();
    vault = EthosRewards(_deployProxy(address(impl)));

    AccessControlV2.AccessControlInitParams memory p = _defaultInitParams();
    vault.initialize(p, address(token), INITIAL_RATE_BPS);

    _setupInteractionControl(_cam);
    _registerControlledContract(ETHOS_REWARDS, address(vault));

    accruingContract = address(new InvAccruingContract());
    address[] memory accruingAddrs = new address[](1);
    string[] memory accruingNames = new string[](1);
    accruingAddrs[0] = accruingContract;
    accruingNames[0] = ETHOS_VOUCH_V2;
    _cam.updateContractAddressesForNames(accruingAddrs, accruingNames);

    token.mint(address(vault), INITIAL_POOL);
    vm.prank(p.admin);
    vault.syncRewardBalance();

    address[] memory actors = new address[](3);
    actors[0] = address(0xA1);
    actors[1] = address(0xA2);
    actors[2] = address(0xA3);

    handler = new RewardsHandler(vault, token, accruingContract, actors);

    // Hand the handler ADMIN_ROLE so its rateAction can call setEmissionRate
    // without relying on vm.prank, which doesn't survive try/catch wrapping
    // inside an invariant run.
    vm.prank(p.owner);
    vault.addAdmin(address(handler));

    targetContract(address(handler));

    bytes4[] memory selectors = new bytes4[](5);
    selectors[0] = RewardsHandler.creditAction.selector;
    selectors[1] = RewardsHandler.debitAction.selector;
    selectors[2] = RewardsHandler.claimAction.selector;
    selectors[3] = RewardsHandler.warpAction.selector;
    selectors[4] = RewardsHandler.rateAction.selector;
    targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
  }

  /// @notice Per-user balances sum to `totalCommitted`, and that matches the
  ///         handler's independently-tracked ghost total.
  function invariant_totalCommittedReconciles() public view {
    uint256 sum;
    uint256 len = handler.actorsLength();
    for (uint256 i = 0; i < len; i++) {
      sum += vault.committedBalance(handler.actorAt(i));
    }
    assertEq(sum, vault.totalCommitted(), "sum(committedBalance) != totalCommitted");
    assertEq(vault.totalCommitted(), handler.ghostTotalCommitted(), "totalCommitted != ghostTotalCommitted");
  }

  /// @notice The contract is solvent: total claimed plus total still-claimable
  ///         across all actors never exceeds the genesis pool, and the
  ///         reward-token balance held by the contract reconciles with the
  ///         claimed total.
  function invariant_solvency() public view {
    uint256 outstanding;
    uint256 len = handler.actorsLength();
    for (uint256 i = 0; i < len; i++) {
      outstanding += vault.earned(handler.actorAt(i));
    }
    assertLe(handler.ghostTotalClaimed() + outstanding, INITIAL_POOL, "claimed + outstanding > genesis pool");
    assertEq(token.balanceOf(address(vault)), INITIAL_POOL - handler.ghostTotalClaimed(), "pool balance mismatch");
    assertEq(vault.accountedRewardBalance(), token.balanceOf(address(vault)), "accountedRewardBalance != pool balance");
    // Direct check on the contract's own solvency ledger — catches bookkeeping
    // drift that the rounded per-account `earned()` summation could miss.
    assertLe(
      vault.totalAccruedNotPaid(), vault.accountedRewardBalance(), "totalAccruedNotPaid > accountedRewardBalance"
    );
  }

  /// @notice For every user, `rewards[u]` (settled) does not exceed `earned(u)`
  ///         (settled + still-accruing).
  function invariant_settledNeverExceedsEarned() public view {
    uint256 len = handler.actorsLength();
    for (uint256 i = 0; i < len; i++) {
      address a = handler.actorAt(i);
      assertLe(vault.rewards(a), vault.earned(a), "rewards[a] > earned(a)");
    }
  }

  /// @notice `totalAccruedNotPaid` is always >= the sum of all settled
  ///         (storage) reward balances across actors.
  ///
  ///         `rewards[u]` and `totalAccruedNotPaid` are updated together by
  ///         the same `updateReward` snapshot, so this invariant is checkable
  ///         at any point in time — unlike the live `earned()` view, which
  ///         reads the current block timestamp and can exceed
  ///         `totalAccruedNotPaid` between snapshots. `claim()` subtracts
  ///         `rewards[msg.sender]`, not `earned()`, so this is the exact
  ///         subtraction that must never underflow.
  function invariant_totalAccruedNotPaidCoversSettledRewards() public view {
    uint256 sumSettled;
    uint256 len = handler.actorsLength();
    for (uint256 i = 0; i < len; i++) {
      sumSettled += vault.rewards(handler.actorAt(i));
    }
    assertGe(vault.totalAccruedNotPaid(), sumSettled, "totalAccruedNotPaid < sum(rewards[u]): claim() would underflow");
  }
}
