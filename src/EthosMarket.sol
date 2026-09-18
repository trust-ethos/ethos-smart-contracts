// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {
  ERC20BurnableUpgradeable
} from "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20BurnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {SignatureExpired} from "./errors/SignatureErrors.sol";
import {
  AmountBelowMinimum,
  FeeBpsTooHigh,
  InsufficientPermitAllowance,
  InsufficientPositionTokens,
  MarketAlreadyExists,
  MarketDoesNotExist,
  MarketPaused,
  MarketSellOnly,
  PricingNotAllowed,
  SlippageExceeded,
  TokenNotBurnable,
  ZeroInitialSupply,
  ZeroPayout,
  ZeroSellAmount,
  ZeroTokensMinted
} from "./errors/MarketErrors.sol";
import {IReputationPricing} from "./interfaces/IReputationPricing.sol";
import {PositionToken} from "./PositionToken.sol";
import {AccessControlV2} from "./utils/AccessControlV2.sol";
import {BPS_DENOMINATOR, WAD} from "./utils/MathConstants.sol";

/**
 * @title EthosMarket
 * @author Ethos Network
 * @notice UUPS-upgradeable contract that creates and manages reputation markets.
 *         Each market is associated with a subject (identified by a `userkeyHash`),
 *         has two sides (trust/distrust), and is denominated in a burnable ERC-20 backing token.
 *
 * @dev Pause states per market:
 *      - ACTIVE:    openPosition and closePosition both allowed.
 *      - SELL_ONLY: closePosition allowed; openPosition blocked.
 *      - PAUSED:    both operations blocked.
 *
 *      Fee rounding rules favour the contract: protocol fees use Math.mulDiv
 *      with Rounding.Ceil (round UP).
 *
 *      CEI pattern is enforced in trading functions. Market creation writes
 *      state after interactions (needs deployed token addresses); nonReentrant
 *      guards this path.
 *
 *      Token assumption: the backing token is a burnable ERC-20
 *      with no fee-on-transfer, no rebasing, and no callback hooks. SafeERC20
 *      is used as defense-in-depth.
 * @custom:security-contact security@ethos.network
 */
contract EthosMarket is AccessControlV2, UUPSUpgradeable, ReentrancyGuardUpgradeable {
  using SafeERC20 for ERC20BurnableUpgradeable;

  // --- Constants ---

  /// @notice Contract version for reinitializer tracking.
  uint256 public constant VERSION = 1;

  /// @notice Minimum buy amount to prevent dust attacks where fees round to zero.
  uint256 public constant MIN_BUY = 1e15; // 0.001 of the backing token (18 decimals)

  /// @notice Maximum protocol fee: 5 %.
  uint256 public constant MAX_PROTOCOL_FEE_BPS = 500;

  // --- Types ---

  enum PauseState {
    ACTIVE,
    SELL_ONLY,
    PAUSED
  }

  /// @dev Fields ordered for storage packing: each address (20 bytes) shares a
  ///      slot with adjacent small types (bool = 1 byte, PauseState/uint8 = 1 byte).
  struct MarketState {
    bytes32 userkeyHash;
    // --- slot: trustToken (20) + exists (1) + pauseState (1) = 22 bytes ---
    address trustToken;
    bool exists;
    PauseState pauseState;
    // --- slot: distrustToken (20) ---
    address distrustToken;
    // --- slot: pricingContract (20) ---
    address pricingContract;
    uint256 trustSupply;
    uint256 distrustSupply;
    uint256 poolBacking;
    /// @dev Monotonically increasing cumulative spend (buys + initial backing).
    ///      Includes protocol fees that are burned. Never decremented on sells.
    uint256 totalVolume;
  }

  // --- Storage ---

  /// @notice The burnable ERC-20 backing token used as the trading currency.
  /// @dev Packed slot: token (20 B) + entryFeeBps (2) + exitFeeBps (2) = 24 B.
  ERC20BurnableUpgradeable public token;

  /// @notice Protocol fee on buys, in basis points (0–500).
  uint16 public entryFeeBps;

  /// @notice Protocol fee on sells, in basis points (0–500).
  uint16 public exitFeeBps;

  /// @notice Tokens minted per side to the contract itself at market creation.
  /// @dev These tokens are permanently locked — they set a non-zero starting point on the
  ///      bonding curve so the first real buyer doesn't purchase at near-zero prices.
  ///      Deliberately immutable post-initialization: all markets share the same supply floor.
  uint256 public initialSupplyPerSide;

  /// @notice Markets indexed by auto-incrementing ID.
  mapping(uint256 marketId => MarketState) public markets;

  /// @notice Number of markets created (IDs go from 1 to marketCount).
  uint256 public marketCount;

  /// @notice Prevents a `userkeyHash` from being used in more than one market.
  mapping(bytes32 userkeyHash => bool) public userkeyHashUsed;

  /// @notice Allowlisted pricing strategy contracts.
  mapping(address pricingContract => bool) public pricingAllowed;

  /// @dev Storage gap for future upgrades. Reduce by 1 for each new storage variable added above.
  uint256[50] private __gap;

  // --- Events ---

  /// @notice Emitted when a new reputation market is created.
  /// @param marketId Unique identifier for the new market.
  /// @param userkeyHash Keccak-256 hash of the subject's userkey.
  /// @param creator Address that created the market.
  /// @param pricingContract Address of the bonding curve pricing contract.
  /// @param trustToken Address of the trust-side position token.
  /// @param distrustToken Address of the distrust-side position token.
  /// @param userkey Canonical userkey string for the subject, emitted for off-chain indexers.
  event MarketCreated(
    uint256 indexed marketId,
    bytes32 indexed userkeyHash,
    address indexed creator,
    address pricingContract,
    address trustToken,
    address distrustToken,
    string userkey
  );

  /// @notice Emitted when a buyer opens a new position.
  /// @param marketId Market the position was opened in.
  /// @param buyer Address that opened the position.
  /// @param isPositive True for trust side, false for distrust side.
  /// @param paymentAmount Credits spent (including fees).
  /// @param tokensMinted Position tokens minted to the buyer.
  event PositionOpened(
    uint256 indexed marketId, address indexed buyer, bool isPositive, uint256 paymentAmount, uint256 tokensMinted
  );

  /// @notice Emitted when a seller closes a position.
  /// @param marketId Market the position was closed in.
  /// @param seller Address that closed the position.
  /// @param isPositive True for trust side, false for distrust side.
  /// @param positionTokenAmount Position tokens burned.
  /// @param netCreditsOut Credits returned to the seller after fees.
  event PositionClosed(
    uint256 indexed marketId,
    address indexed seller,
    bool isPositive,
    uint256 positionTokenAmount,
    uint256 netCreditsOut
  );

  /// @notice Emitted after every trade to snapshot the market state.
  /// @param marketId Market that was updated.
  /// @param trustSupply Current trust token total supply.
  /// @param distrustSupply Current distrust token total supply.
  /// @param trustPrice WAD-scaled price of one trust token.
  /// @param distrustPrice WAD-scaled price of one distrust token.
  /// @param poolBacking Total credits backing the market.
  event MarketUpdated(
    uint256 indexed marketId,
    uint256 trustSupply,
    uint256 distrustSupply,
    uint256 trustPrice,
    uint256 distrustPrice,
    uint256 poolBacking
  );

  /// @notice Emitted when a `getPrice` call on the pricing contract reverts during
  ///         `_emitMarketUpdated`. The corresponding `trustPrice` / `distrustPrice` field
  ///         in the paired `MarketUpdated` event is 0 — indexers should treat that 0 as
  ///         "price unavailable", not a confirmed price reading.
  /// @param marketId The market whose price read failed.
  /// @param pricingContract Address of the pricing contract that reverted.
  /// @param isPositive Side whose price read reverted (true = trust, false = distrust).
  /// @param reason Raw revert data (custom error selector + args).
  event MarketUpdateFailed(uint256 indexed marketId, address indexed pricingContract, bool isPositive, bytes reason);

  /// @notice Emitted when a pricing contract is added or removed from the allowlist.
  /// @param pricingContract Address of the pricing contract.
  /// @param allowed Whether the contract is now allowed.
  event PricingAllowlistUpdated(address indexed pricingContract, bool allowed);
  /// @notice Emitted when the entry fee is changed.
  /// @param newBps New entry fee in basis points.
  event EntryFeeUpdated(uint256 newBps);
  /// @notice Emitted when the exit fee is changed.
  /// @param newBps New exit fee in basis points.
  event ExitFeeUpdated(uint256 newBps);
  /// @notice Emitted when a market's pause state is updated.
  /// @param marketId Market whose pause state changed.
  /// @param newState New pause state.
  event MarketPauseStateUpdated(uint256 indexed marketId, PauseState newState);

  // --- Initialization ---

  /**
   * @notice Initializes the contract.
   * @param p                    Access control initialization parameters.
   * @param token_               Backing token address (burnable ERC-20).
   * @param initialSupplyPerSide_ Initial tokens minted per side when a market is created.
   */
  function initialize(AccessControlInitParams calldata p, address token_, uint256 initialSupplyPerSide_)
    external
    initializer
  {
    if (token_ == address(0)) revert ZeroAddress();
    if (initialSupplyPerSide_ == 0) revert ZeroInitialSupply();
    try ERC20BurnableUpgradeable(token_).burn(0) {}
    catch {
      revert TokenNotBurnable(token_);
    }

    __accessControl_init(p);
    __UUPSUpgradeable_init();
    __ReentrancyGuard_init();

    token = ERC20BurnableUpgradeable(token_);
    initialSupplyPerSide = initialSupplyPerSide_;
    // marketCount defaults to 0; IDs start at 1 so ID 0 is always "no market"
  }

  // --- Market creation ---

  /**
   * @notice Creates a new reputation market, gated by an Ethos backend signature.
   * @dev The backend controls which subjects get markets and the economic parameters.
   *      The caller provides the backing token for initial backing.
   * @param userkey_         Canonical userkey string (e.g. "address:0x..."). Hash is computed on-chain.
   * @param subjectName      Human-readable subject name (e.g. "vitalik.eth") for position token metadata.
   * @param initialBacking   Credits transferred from caller to seed the pool.
   * @param pricingContract_ Allowlisted IReputationPricing implementation.
   * @param deadline         Timestamp after which the signature is no longer valid.
   * @param randValue        One-time nonce to prevent signature replay.
   * @param signature        Backend-signed authorization.
   */
  function createMarket(
    string calldata userkey_,
    string calldata subjectName,
    uint256 initialBacking,
    address pricingContract_,
    uint256 deadline,
    uint256 randValue,
    bytes calldata signature
  ) external whenNotPaused nonReentrant {
    if (block.timestamp > deadline) {
      revert SignatureExpired(deadline, block.timestamp);
    }

    validateAndSaveSignature(
      keccak256(
        abi.encode(
          address(this),
          block.chainid,
          msg.sender,
          userkey_,
          subjectName,
          initialBacking,
          pricingContract_,
          deadline,
          randValue
        )
      ),
      signature
    );

    bytes32 userkeyHash = keccak256(bytes(userkey_));
    _createMarket(userkeyHash, userkey_, subjectName, initialBacking, pricingContract_);
  }

  /**
   * @notice Creates a new reputation market. Admin bypass for bootstrapping.
   * @param userkey_         Canonical userkey string (e.g. "address:0x..."). Hash is computed on-chain.
   * @param subjectName      Human-readable subject name for position token metadata.
   * @param initialBacking   Credits transferred from caller to seed the pool.
   * @param pricingContract_ Allowlisted IReputationPricing implementation.
   */
  function createMarketAdmin(
    string calldata userkey_,
    string calldata subjectName,
    uint256 initialBacking,
    address pricingContract_
  ) external onlyAdmin whenNotPaused nonReentrant {
    bytes32 userkeyHash = keccak256(bytes(userkey_));
    _createMarket(userkeyHash, userkey_, subjectName, initialBacking, pricingContract_);
  }

  // --- Trading ---

  /**
   * @notice Buy position tokens for a market side. Caller must have approved
   *         this contract to spend `paymentAmount` of the backing token beforehand.
   * @param marketId       Target market.
   * @param isPositive     `true` = trust side, `false` = distrust side.
   * @param paymentAmount  Total credits the buyer is willing to spend (including protocol fee).
   * @param minTokensOut   Slippage guard: revert if fewer tokens would be minted.
   */
  function openPosition(uint256 marketId, bool isPositive, uint256 paymentAmount, uint256 minTokensOut)
    external
    whenNotPaused
    nonReentrant
  {
    _openPosition(marketId, isPositive, paymentAmount, minTokensOut);
  }

  /**
   * @notice Buy position tokens with an EIP-2612 permit, combining approval and
   *         trade into a single transaction.
   * @dev The permit call is wrapped in try/catch per OpenZeppelin's recommendation
   *      to tolerate frontrunning: if an attacker observes the permit in mempool
   *      and consumes the nonce first, the trade still proceeds against the
   *      already-applied allowance. To avoid masking real permit failures
   *      (expired signature, malformed payload) behind an opaque
   *      ERC20InsufficientAllowance from the downstream transferFrom, we assert
   *      the post-catch allowance covers the trade and revert with
   *      InsufficientPermitAllowance otherwise.
   * @param marketId       Target market.
   * @param isPositive     `true` = trust side, `false` = distrust side.
   * @param paymentAmount  Total credits the buyer is willing to spend (including protocol fee).
   * @param minTokensOut   Slippage guard: revert if fewer tokens would be minted.
   * @param deadline       Permit signature expiry timestamp.
   * @param v              Recovery byte of the permit signature.
   * @param r              First 32 bytes of the permit signature.
   * @param s              Second 32 bytes of the permit signature.
   */
  function openPositionWithPermit(
    uint256 marketId,
    bool isPositive,
    uint256 paymentAmount,
    uint256 minTokensOut,
    uint256 deadline,
    uint8 v,
    bytes32 r,
    bytes32 s
  ) external whenNotPaused nonReentrant {
    try IERC20Permit(address(token)).permit(msg.sender, address(this), paymentAmount, deadline, v, r, s) {}
    catch {
      if (token.allowance(msg.sender, address(this)) < paymentAmount) {
        revert InsufficientPermitAllowance(msg.sender, paymentAmount);
      }
    }
    _openPosition(marketId, isPositive, paymentAmount, minTokensOut);
  }

  /**
   * @notice Sell position tokens back for credits.
   * @param marketId              Target market.
   * @param isPositive            `true` = trust side, `false` = distrust side.
   * @param positionTokenAmount   Number of position tokens to burn.
   * @param minCreditsOut         Slippage guard: revert if payout would be less.
   */
  function closePosition(uint256 marketId, bool isPositive, uint256 positionTokenAmount, uint256 minCreditsOut)
    external
    whenNotPaused
    nonReentrant
  {
    if (positionTokenAmount == 0) revert ZeroSellAmount();
    MarketState storage m = _requireMarketForSell(marketId);

    address tokenAddr = _sideToken(m, isPositive);
    uint256 holderBalance = PositionToken(tokenAddr).balanceOf(msg.sender);
    if (holderBalance < positionTokenAmount) {
      revert InsufficientPositionTokens(holderBalance, positionTokenAmount);
    }

    uint256 curveRevenue = _curveRevenue(m, isPositive, positionTokenAmount);
    (uint256 exitFeeAmount, uint256 netCreditsOut) = _computePayoutBreakdown(curveRevenue);

    if (netCreditsOut == 0) revert ZeroPayout();
    if (netCreditsOut < minCreditsOut) revert SlippageExceeded(netCreditsOut, minCreditsOut);

    _applySellEffects(m, isPositive, positionTokenAmount, curveRevenue);
    _executeSellTransfers(tokenAddr, positionTokenAmount, netCreditsOut, exitFeeAmount);

    emit PositionClosed(marketId, msg.sender, isPositive, positionTokenAmount, netCreditsOut);
    _emitMarketUpdated(marketId, m);
  }

  // --- Admin: Fee configuration ---

  /// @notice Sets the protocol fee on buys.
  /// @param bps Fee in basis points (0–500).
  function setEntryFeeBasisPoints(uint256 bps) external onlyOwner {
    if (bps > MAX_PROTOCOL_FEE_BPS) revert FeeBpsTooHigh(bps, MAX_PROTOCOL_FEE_BPS);
    entryFeeBps = SafeCast.toUint16(bps);
    emit EntryFeeUpdated(bps);
  }

  /// @notice Sets the protocol fee on sells.
  /// @param bps Fee in basis points (0–500).
  function setExitFeeBasisPoints(uint256 bps) external onlyOwner {
    if (bps > MAX_PROTOCOL_FEE_BPS) revert FeeBpsTooHigh(bps, MAX_PROTOCOL_FEE_BPS);
    exitFeeBps = SafeCast.toUint16(bps);
    emit ExitFeeUpdated(bps);
  }

  // --- Admin: Pricing allowlist ---

  /// @notice Adds or removes a pricing strategy from the allowlist.
  /// @param pricingContract Address of the IReputationPricing implementation.
  /// @param allowed True to allow, false to revoke.
  function setPricingAllowed(address pricingContract, bool allowed)
    external
    onlyOwner
    onlyNonZeroAddress(pricingContract)
  {
    pricingAllowed[pricingContract] = allowed;
    emit PricingAllowlistUpdated(pricingContract, allowed);
  }

  // --- Admin: Per-market pause ---

  /// @notice Sets the per-market pause state (ACTIVE, SELL_ONLY, or PAUSED).
  /// @param marketId Target market.
  /// @param state New pause state.
  function setMarketPauseState(uint256 marketId, PauseState state) external onlyAdmin {
    MarketState storage m = markets[marketId];
    if (!m.exists) revert MarketDoesNotExist(marketId);
    if (m.pauseState == state) return;
    m.pauseState = state;
    emit MarketPauseStateUpdated(marketId, state);
  }

  // --- Read-only quote functions ---

  /**
   * @notice Preview the outcome of a buy without executing it.
   * @param marketId          Market to quote against.
   * @param isPositive        True for trust side, false for distrust side.
   * @param paymentAmount     Credits the buyer would spend (including fees).
   * @return tokensMinted     How many position tokens would be minted; zero for amounts below `MIN_BUY`.
   * @return effectivePrice   WAD-scaled all-in credits per token (paymentAmount * WAD / tokensMinted).
   * @return protocolFee      Credits burned as the protocol fee.
   */
  function quoteBuy(uint256 marketId, bool isPositive, uint256 paymentAmount)
    external
    view
    returns (uint256 tokensMinted, uint256 effectivePrice, uint256 protocolFee)
  {
    MarketState storage m = _requireExistingMarket(marketId);
    if (paymentAmount < MIN_BUY) return (0, 0, 0);

    protocolFee = _computeEntryFee(paymentAmount);
    uint256 curveAmount = paymentAmount - protocolFee;

    tokensMinted = _tokensForBudget(m, isPositive, curveAmount);
    effectivePrice = tokensMinted > 0 ? Math.mulDiv(paymentAmount, WAD, tokensMinted) : 0;
  }

  /**
   * @notice Preview the outcome of a sell without executing it.
   * @param marketId              Target market.
   * @param isPositive            Side to sell.
   * @param positionTokenAmount   Tokens to sell.
   * @param seller                Address of the seller.
   * @return curveRevenue         Credits from the bonding curve.
   * @return exitFee              Credits burned as the protocol fee.
   * @return netCreditsOut        Net credits the seller would receive.
   * @return effectivePrice       Credits per token.
   */
  function quoteSell(uint256 marketId, bool isPositive, uint256 positionTokenAmount, address seller)
    external
    view
    returns (uint256 curveRevenue, uint256 exitFee, uint256 netCreditsOut, uint256 effectivePrice)
  {
    MarketState storage m = _requireExistingMarket(marketId);
    if (positionTokenAmount == 0) return (0, 0, 0, 0);

    address tokenAddr = _sideToken(m, isPositive);
    uint256 sellerBalance = PositionToken(tokenAddr).balanceOf(seller);

    // Return zeros when positionTokenAmount exceeds balance so off-chain callers can
    // preview hypothetical sells without pre-fetching balances. The executing function
    // (closePosition) still enforces the balance check via PositionToken.burn.
    if (sellerBalance < positionTokenAmount) return (0, 0, 0, 0);

    curveRevenue = _curveRevenue(m, isPositive, positionTokenAmount);

    (exitFee, netCreditsOut) = _computePayoutBreakdown(curveRevenue);

    effectivePrice = Math.mulDiv(netCreditsOut, WAD, positionTokenAmount);
  }

  // --- Internal: trading core ---

  /// @dev Shared buy logic for openPosition and openPositionWithPermit.
  function _openPosition(uint256 marketId, bool isPositive, uint256 paymentAmount, uint256 minTokensOut) internal {
    MarketState storage m = _requireActiveMarket(marketId);
    if (paymentAmount < MIN_BUY) revert AmountBelowMinimum(paymentAmount, MIN_BUY);

    uint256 protocolAmount = _computeEntryFee(paymentAmount);
    uint256 curveAmount = paymentAmount - protocolAmount;

    uint256 tokensMinted = _tokensForBudget(m, isPositive, curveAmount);
    if (tokensMinted == 0) revert ZeroTokensMinted(curveAmount);
    if (tokensMinted < minTokensOut) revert SlippageExceeded(tokensMinted, minTokensOut);

    address tokenAddr = _sideToken(m, isPositive);

    _applyBuyEffects(m, isPositive, tokensMinted, curveAmount, paymentAmount);
    _executeBuyTransfers(tokenAddr, msg.sender, curveAmount, protocolAmount, tokensMinted);

    emit PositionOpened(marketId, msg.sender, isPositive, paymentAmount, tokensMinted);
    _emitMarketUpdated(marketId, m);
  }

  // --- UUPS ---

  function _authorizeUpgrade(address newImplementation)
    internal
    override
    onlyOwner
    onlyNonZeroAddress(newImplementation)
  {}

  // --- Internal helpers: market accessors ---

  /// @dev Returns the position token address for the given side.
  function _sideToken(MarketState storage m, bool isPositive) internal view returns (address) {
    return isPositive ? m.trustToken : m.distrustToken;
  }

  // --- Internal helpers: pricing wrappers ---

  /// @dev Tokens minted for a given budget on the bonding curve.
  function _tokensForBudget(MarketState storage m, bool isPositive, uint256 budget) internal view returns (uint256) {
    return IReputationPricing(m.pricingContract).getTokensForBudget(m.trustSupply, m.distrustSupply, isPositive, budget);
  }

  /// @dev Credits returned by the bonding curve for selling `amount` tokens.
  function _curveRevenue(MarketState storage m, bool isPositive, uint256 amount) internal view returns (uint256) {
    return IReputationPricing(m.pricingContract).getCost(m.trustSupply, m.distrustSupply, isPositive, false, amount);
  }

  // --- Internal helpers: fee computation ---

  /// @dev Computes the entry protocol fee from a buy payment.
  function _computeEntryFee(uint256 paymentAmount) internal view returns (uint256) {
    return Math.mulDiv(paymentAmount, entryFeeBps, BPS_DENOMINATOR, Math.Rounding.Ceil);
  }

  /// @dev Computes the exit protocol fee from curve revenue.
  function _computeExitFee(uint256 curveRevenue) internal view returns (uint256) {
    return Math.mulDiv(curveRevenue, exitFeeBps, BPS_DENOMINATOR, Math.Rounding.Ceil);
  }

  /// @dev Computes exit fee and net payout from curve revenue.
  ///      Shared by closePosition and quoteSell to guarantee quotes match execution.
  function _computePayoutBreakdown(uint256 curveRevenue) internal view returns (uint256 exitFee, uint256 netPayout) {
    exitFee = _computeExitFee(curveRevenue);
    netPayout = curveRevenue - exitFee;
  }

  // --- Internal helpers: effects ---

  /// @dev Applies state changes for a buy: increment supply, add to pool backing and volume totals.
  function _applyBuyEffects(
    MarketState storage m,
    bool isPositive,
    uint256 tokensMinted,
    uint256 curveAmount,
    uint256 paymentAmount
  ) internal {
    if (isPositive) {
      m.trustSupply += tokensMinted;
    } else {
      m.distrustSupply += tokensMinted;
    }
    m.poolBacking += curveAmount;
    m.totalVolume += paymentAmount;
  }

  /// @dev Applies state changes for a sell: decrement supply and reduce pool backing.
  function _applySellEffects(MarketState storage m, bool isPositive, uint256 positionTokenAmount, uint256 curveRevenue)
    internal
  {
    if (isPositive) {
      m.trustSupply -= positionTokenAmount;
    } else {
      m.distrustSupply -= positionTokenAmount;
    }
    m.poolBacking -= curveRevenue;
  }

  // --- Internal helpers: interactions ---

  /// @dev Executes external transfers for a buy: pull the backing token from buyer, burn fee, mint position tokens.
  function _executeBuyTransfers(
    address tokenAddr,
    address buyer,
    uint256 curveAmount,
    uint256 protocolAmount,
    uint256 tokensMinted
  ) internal {
    token.safeTransferFrom(buyer, address(this), curveAmount + protocolAmount);
    if (protocolAmount > 0) {
      token.burn(protocolAmount);
    }
    PositionToken(tokenAddr).mint(buyer, tokensMinted);
  }

  /// @dev Executes external transfers for a sell: burn position tokens, pay seller, burn fee.
  function _executeSellTransfers(
    address tokenAddr,
    uint256 positionTokenAmount,
    uint256 netPayout,
    uint256 exitFeeAmount
  ) internal {
    PositionToken(tokenAddr).burn(msg.sender, positionTokenAmount);
    token.safeTransfer(msg.sender, netPayout);
    if (exitFeeAmount > 0) {
      token.burn(exitFeeAmount);
    }
  }

  /// @notice Shared market creation logic used by both createMarket and createMarketAdmin.
  /// @param userkeyHash_     keccak256 of the canonical userkey string.
  /// @param userkey_         Canonical userkey string, emitted in MarketCreated for indexers.
  /// @param subjectName      Human-readable subject name for position token metadata.
  /// @param initialBacking   Credits transferred from caller to seed the pool.
  /// @param pricingContract_ Allowlisted IReputationPricing implementation.
  function _createMarket(
    bytes32 userkeyHash_,
    string calldata userkey_,
    string calldata subjectName,
    uint256 initialBacking,
    address pricingContract_
  ) internal {
    if (userkeyHashUsed[userkeyHash_]) {
      revert MarketAlreadyExists(userkeyHash_);
    }
    if (!pricingAllowed[pricingContract_]) revert PricingNotAllowed(pricingContract_);
    // MIN_BUY is the floor; deployers should provide meaningful liquidity relative to
    // initialSupplyPerSide so the bonding curve doesn't start at a near-zero price.
    if (initialBacking < MIN_BUY) revert AmountBelowMinimum(initialBacking, MIN_BUY);

    uint256 marketId;
    unchecked {
      marketId = ++marketCount; // overflow impossible: uint256 counter; IDs start at 1
    }

    (PositionToken trustToken, PositionToken distrustToken) = _deployPositionTokens(marketId, subjectName);

    _seedMarket(trustToken, distrustToken, initialBacking);

    userkeyHashUsed[userkeyHash_] = true;

    markets[marketId] = MarketState({
      userkeyHash: userkeyHash_,
      trustToken: address(trustToken),
      exists: true,
      pauseState: PauseState.ACTIVE,
      distrustToken: address(distrustToken),
      pricingContract: pricingContract_,
      trustSupply: initialSupplyPerSide,
      distrustSupply: initialSupplyPerSide,
      poolBacking: initialBacking,
      totalVolume: initialBacking
    });

    emit MarketCreated(
      marketId, userkeyHash_, msg.sender, pricingContract_, address(trustToken), address(distrustToken), userkey_
    );
    _emitMarketUpdated(marketId, markets[marketId]);
  }

  /// @dev Deploys trust and distrust position tokens for a new market.
  ///      External calls before state writes (CEI relaxation); nonReentrant guards this path.
  function _deployPositionTokens(uint256 marketId, string calldata subjectName)
    internal
    returns (PositionToken trustToken, PositionToken distrustToken)
  {
    trustToken = new PositionToken(
      string.concat("Trust: ", subjectName), string.concat("TRUST-", subjectName), marketId, true
    );
    distrustToken = new PositionToken(
      string.concat("Distrust: ", subjectName), string.concat("DISTRUST-", subjectName), marketId, false
    );
  }

  /// @dev Pulls initial backing from the caller and mints locked supply-floor tokens.
  function _seedMarket(PositionToken trustToken, PositionToken distrustToken, uint256 initialBacking) internal {
    token.safeTransferFrom(msg.sender, address(this), initialBacking);
    trustToken.mint(address(this), initialSupplyPerSide);
    distrustToken.mint(address(this), initialSupplyPerSide);
  }

  /// @dev Reverts if the market does not exist.
  function _requireExistingMarket(uint256 marketId) internal view returns (MarketState storage m) {
    m = markets[marketId];
    if (!m.exists) revert MarketDoesNotExist(marketId);
  }

  /// @dev Reverts if the market is paused or sell-only. Used by openPosition.
  function _requireActiveMarket(uint256 marketId) internal view returns (MarketState storage m) {
    m = _requireExistingMarket(marketId);
    if (m.pauseState == PauseState.PAUSED) revert MarketPaused(marketId);
    if (m.pauseState == PauseState.SELL_ONLY) revert MarketSellOnly(marketId);
  }

  /// @dev Reverts if the market is fully paused. Allows sell-only. Used by closePosition.
  function _requireMarketForSell(uint256 marketId) internal view returns (MarketState storage m) {
    m = _requireExistingMarket(marketId);
    if (m.pauseState == PauseState.PAUSED) revert MarketPaused(marketId);
  }

  function _emitMarketUpdated(uint256 marketId, MarketState storage m) internal {
    uint256 trustPrice;
    uint256 distrustPrice;
    // try/catch: a misbehaving pricing contract must not DoS sells. Price defaults to 0;
    // MarketUpdateFailed carries the revert reason (see event NatSpec for indexer guidance).
    try IReputationPricing(m.pricingContract).getPrice(m.trustSupply, m.distrustSupply, true) returns (uint256 p) {
      trustPrice = p;
    } catch (bytes memory reason) {
      emit MarketUpdateFailed(marketId, m.pricingContract, true, reason);
    }
    try IReputationPricing(m.pricingContract).getPrice(m.trustSupply, m.distrustSupply, false) returns (uint256 p) {
      distrustPrice = p;
    } catch (bytes memory reason) {
      emit MarketUpdateFailed(marketId, m.pricingContract, false, reason);
    }
    emit MarketUpdated(marketId, m.trustSupply, m.distrustSupply, trustPrice, distrustPrice, m.poolBacking);
  }
}
