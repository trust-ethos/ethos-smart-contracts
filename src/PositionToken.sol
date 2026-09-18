// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {OnlyMarket, TransferToZeroAddress, TransferToMarket} from "./errors/PositionTokenErrors.sol";

/**
 * @title PositionToken
 * @author Ethos Network
 * @notice Minimal ERC-20 representing one side of a reputation market position.
 * @dev Deployed once per market per side (trust or distrust). Only the market
 *      contract that deployed this token can call `mint` or `burn`. Transfers
 *      directly to `address(0)` and to the market address are blocked — the
 *      only valid burn path is through the market's `closePosition`, which
 *      maintains market accounting.
 * @custom:security-contact security@ethos.network
 */
contract PositionToken is ERC20 {
  /// @notice The market contract that owns (and can mint/burn) this token.
  address public immutable market;

  /// @notice The market ID this token belongs to.
  uint256 public immutable marketId;

  /// @notice Whether this is the trust (true) or distrust (false) side.
  bool public immutable isPositive;

  modifier onlyMarket() {
    if (msg.sender != market) revert OnlyMarket();
    _;
  }

  /**
   * @notice Deploys a new position token bound to the calling market.
   * @param name_       Human-readable token name (e.g. "Trust: vitalik.eth").
   * @param symbol_     Token symbol (e.g. "TRUST-vitalik.eth").
   * @param marketId_   The market ID this token belongs to.
   * @param isPositive_ True for trust side, false for distrust side.
   */
  constructor(string memory name_, string memory symbol_, uint256 marketId_, bool isPositive_) ERC20(name_, symbol_) {
    market = msg.sender;
    marketId = marketId_;
    isPositive = isPositive_;
  }

  /// @notice Mints `amount` tokens to `to`. Only callable by the market contract.
  /// @param to Recipient of the minted tokens.
  /// @param amount Number of tokens to mint.
  function mint(address to, uint256 amount) external onlyMarket {
    _mint(to, amount);
  }

  /**
   * @notice Burns `amount` tokens from `from`. Only callable by the market contract.
   * @dev No approval from `from` is required — the market initiates burns only
   *      inside `closePosition` which the holder themselves initiates.
   * @param from Account whose tokens are burned.
   * @param amount Number of tokens to burn.
   */
  function burn(address from, uint256 amount) external onlyMarket {
    _burn(from, amount);
  }

  /**
   * @notice Transfers tokens after validating the recipient.
   * @dev Blocks transfers to address(0) and the market contract. Holders must
   *      sell through `closePosition` — direct burns and dumps to the market
   *      address would bypass market accounting.
   * @param to Recipient address.
   * @param value Number of tokens to transfer.
   */
  function transfer(address to, uint256 value) public override returns (bool) {
    _validateRecipient(to);
    return super.transfer(to, value);
  }

  /// @notice Transfers tokens on behalf of `from` after validating the recipient.
  /// @dev Same restrictions as `transfer`.
  /// @param from Token owner.
  /// @param to Recipient address.
  /// @param value Number of tokens to transfer.
  function transferFrom(address from, address to, uint256 value) public override returns (bool) {
    _validateRecipient(to);
    return super.transferFrom(from, to, value);
  }

  function _validateRecipient(address to) private view {
    if (to == address(0)) revert TransferToZeroAddress();
    if (to == market) revert TransferToMarket();
  }
}
