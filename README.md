# Ethos Protocol Contracts

This repository is the canonical source for the Ethos V2 protocol smart contracts: a
standalone Foundry package containing Solidity sources, Solidity tests, Foundry config,
and Soldeer lock data.

## Audits

| Guardian security review | July 2026                                                                                                                                                                            |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Report                   | [Guardian Audits repository](https://github.com/GuardianAudits/Audits/blob/main/Ethos/Ethos-Network-Guardian-Report.pdf) · [local copy](audits/2026-07-guardian-security-review.pdf) |
| Review window            | June 9–25, 2026 · final report July 9, 2026                                                                                                                                          |
| Findings                 | 0 Critical · 0 High · 5 Medium · 17 Low · 34 Informational                                                                                                                           |
| Audited commit           | `2e16c17110929849d15dd1357a68d904c18ada23`                                                                                                                                           |

Previous Ethos Sherlock contests:

- https://github.com/sherlock-audit/2024-10-ethos-network
- https://github.com/sherlock-audit/2024-11-ethos-network-ii
- https://github.com/sherlock-audit/2024-12-ethos-update

## Setup

Install dependencies and run the full Solidity suite:

```shell
forge soldeer install
forge build
forge test
```

Optional formatting check:

```shell
forge fmt --check src test
```

No Node install is required for the test suite.

## Tests Included

Solidity test suites:

- `test/EthosVouchV2.t.sol`
- `test/EthosVouchV2.invariant.t.sol`
- `test/EthosWhuffie.t.sol`
- `test/EthosMarket.t.sol`
- `test/EthosMarket.invariant.t.sol`
- `test/EthosMarketAdaptiveLMSR.t.sol`
- `test/EthosMarketAdaptiveLMSR.invariant.t.sol`
- `test/EthosRewards.t.sol`
- `test/EthosRewards.invariant.t.sol`
- `test/AdaptiveLMSRPricing.t.sol`
- `test/PositionToken.t.sol`
- `test/AccessControlV2.t.sol`
- `test/EthosReview.t.sol`
- `test/EthosSlash.t.sol`

## Trust Assumptions

- Owner and admin roles are trusted governance or operations actors.
- The expected signer is trusted to authorize only valid signed actions.
- `ContractAddressManager` ownership and registered addresses are trusted.
- The registered slasher address is trusted only for the intended slash/freeze flow.
- UUPS upgrades are performed by the authorized owner through the intended proxy flow.
- WHUF (`EthosWhuffie`) is the registered burnable token for V2 fee burns and claims.
- Market and vouch flows assume configured ERC20 tokens behave as standard non-rebasing,
  non-fee-on-transfer tokens unless explicitly handled by the contract.
